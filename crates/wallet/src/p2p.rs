//! Block download from random onion peers over Tor (what Wasabi's P2P block provider does),
//! for blocks that are neither cached nor obtainable from the user's node.

use bitcoin::consensus::encode::{deserialize_partial, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::{Block, BlockHash, Network};
use rand::seq::SliceRandom;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAINNET_ONION_PEERS: &str = include_str!("../../../vendor/onion_peers_main.txt");
const MAINNET_IPV4_PEERS: &str = include_str!("../../../vendor/ipv4_peers_main.txt");

pub struct P2pBlockFetcher {
    socks: String,
    peers: Vec<String>,
    magic: Magic,
    /// Peers that served a block before; many seed onions are stale, so these go first.
    good: std::sync::Mutex<Vec<String>>,
}

impl P2pBlockFetcher {
    pub fn new(socks: &str, network: Network) -> Self {
        // Onion peers first (no exit needed), clearnet peers reached through Tor exits as a fallback.
        let peers = match network {
            Network::Bitcoin => MAINNET_ONION_PEERS
                .lines()
                .chain(MAINNET_IPV4_PEERS.lines())
                .map(|l| l.split('#').next().unwrap_or("").trim())
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        Self { socks: socks.to_string(), peers, magic: Magic::from(network), good: std::sync::Mutex::new(Vec::new()) }
    }

    pub fn has_peers(&self) -> bool {
        !self.peers.is_empty()
    }

    /// Tries known-good peers first, then random ones, three at a time (first block wins).
    pub async fn get_block(&self, hash: &BlockHash, attempts: usize) -> anyhow::Result<Block> {
        let mut candidates: Vec<String> = self.good.lock().unwrap().clone();
        let mut onions: Vec<String> = self.peers.iter().filter(|p| !candidates.contains(p) && p.contains(".onion")).cloned().collect();
        let mut clearnet: Vec<String> = self.peers.iter().filter(|p| !candidates.contains(p) && !p.contains(".onion")).cloned().collect();
        onions.shuffle(&mut rand::thread_rng());
        clearnet.shuffle(&mut rand::thread_rng());
        onions.truncate(attempts.max(3) / 2);
        candidates.extend(onions);
        candidates.extend(clearnet);
        candidates.truncate(attempts.max(3));
        let mut last = anyhow::anyhow!("no peers");
        for chunk in candidates.chunks(3) {
            let mut set = tokio::task::JoinSet::new();
            for peer in chunk {
                let (socks, peer, magic, hash) = (self.socks.clone(), peer.clone(), self.magic, *hash);
                set.spawn(async move {
                    let r = tokio::time::timeout(Duration::from_secs(120), fetch_from_peer(&socks, &peer, magic, &hash)).await;
                    (peer, r)
                });
            }
            while let Some(joined) = set.join_next().await {
                match joined {
                    Ok((peer, Ok(Ok(b)))) => {
                        let mut good = self.good.lock().unwrap();
                        if !good.contains(&peer) {
                            good.push(peer);
                        }
                        set.abort_all();
                        return Ok(b);
                    }
                    Ok((peer, Ok(Err(e)))) => {
                        tracing::debug!("p2p {peer}: {e}");
                        self.good.lock().unwrap().retain(|p| p != &peer);
                        last = e;
                    }
                    Ok((peer, Err(_))) => {
                        tracing::debug!("p2p {peer}: timeout");
                        self.good.lock().unwrap().retain(|p| p != &peer);
                        last = anyhow::anyhow!("timeout");
                    }
                    Err(e) => last = anyhow::anyhow!("{e}"),
                }
            }
        }
        Err(anyhow::anyhow!("block {hash} not obtained from {} peers: {last}", candidates.len()))
    }
}

async fn write_msg(stream: &mut TcpStream, magic: Magic, msg: NetworkMessage) -> anyhow::Result<()> {
    let raw = RawNetworkMessage::new(magic, msg);
    stream.write_all(&serialize(&raw)).await?;
    Ok(())
}

async fn read_msg(stream: &mut TcpStream) -> anyhow::Result<NetworkMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header).await?;
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if len > 8_000_000 {
        anyhow::bail!("message too large: {len}");
    }
    let mut buf = Vec::with_capacity(24 + len);
    buf.extend_from_slice(&header);
    buf.resize(24 + len, 0);
    stream.read_exact(&mut buf[24..]).await?;
    // Some peers pad messages (version with extra fields, addrv2 variants): take what decodes.
    let (raw, _consumed): (RawNetworkMessage, usize) = deserialize_partial(&buf)?;
    Ok(raw.into_payload())
}

async fn fetch_from_peer(socks: &str, peer: &str, magic: Magic, hash: &BlockHash) -> anyhow::Result<Block> {
    // Seed lines may carry a comment ("host:port # AS1234"); only the address counts.
    let peer = peer.split('#').next().unwrap_or(peer).trim();
    let (host, port) = peer.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("bad peer {peer}"))?;
    let port: u16 = port.parse()?;
    let circuit = format!("p2p-{:08x}", rand::thread_rng().next_u32());
    let proxied = tokio_socks::tcp::Socks5Stream::connect_with_password(socks, (host, port), &circuit, "x").await?;
    let mut stream = proxied.into_inner();
    let dummy = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let version = VersionMessage::new(
        ServiceFlags::NONE,
        now,
        Address::new(&dummy, ServiceFlags::NONE),
        Address::new(&dummy, ServiceFlags::NONE),
        rand::thread_rng().next_u64(),
        "/sabid:0.1.0/".to_string(),
        0,
    );
    write_msg(&mut stream, magic, NetworkMessage::Version(version)).await?;
    let mut got_version = false;
    let mut got_verack = false;
    while !(got_version && got_verack) {
        match read_msg(&mut stream).await? {
            NetworkMessage::Version(_) => {
                got_version = true;
                write_msg(&mut stream, magic, NetworkMessage::Verack).await?;
            }
            NetworkMessage::Verack => got_verack = true,
            _ => {}
        }
    }
    write_msg(&mut stream, magic, NetworkMessage::GetData(vec![Inventory::WitnessBlock(*hash)])).await?;
    loop {
        match read_msg(&mut stream).await? {
            NetworkMessage::Block(b) => {
                if b.block_hash() != *hash {
                    anyhow::bail!("peer sent the wrong block");
                }
                if !b.check_merkle_root() || !b.check_witness_commitment() {
                    anyhow::bail!("peer sent an invalid block");
                }
                return Ok(b);
            }
            NetworkMessage::NotFound(_) => anyhow::bail!("peer does not have the block"),
            NetworkMessage::Ping(n) => write_msg(&mut stream, magic, NetworkMessage::Pong(n)).await?,
            _ => {}
        }
    }
}
