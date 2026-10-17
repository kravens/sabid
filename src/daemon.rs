//! Daemon state: config, Tor, filter store, bitcoind, loaded wallets and the sync loop.

use crate::config::{wasabi_data_dir, WasabiConfig};
use bitcoin::Network;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use wallet::bitcoind::Bitcoind;
use wallet::filters::{FilterRow, FilterStore};
use wallet::sync::BlockSource;
use wallet::{KeyManager, WalletState, WalletStore};

pub struct LoadedWallet {
    pub km: KeyManager,
    pub store: WalletStore,
    pub state: WalletState,
    /// Synced to the filter tip at least once.
    pub loaded: bool,
    pub sync_progress: Option<(u32, u32)>,
    pub coinjoin_status: &'static str,
    pub last_error: Option<String>,
}

impl LoadedWallet {
    pub fn rebuild_state(&mut self) -> anyhow::Result<()> {
        let txs = self.store.all_txs()?;
        let (state, changed) = WalletState::build(&txs, &mut self.km);
        self.state = state;
        if changed || self.km.ensure_gap() {
            self.km.save()?;
        }
        Ok(())
    }
}

pub struct Daemon {
    pub cfg: WasabiConfig,
    pub network: Network,
    pub datadir: PathBuf,
    pub wallet_dir: PathBuf,
    pub socks: Option<String>,
    pub tor_enabled: bool,
    pub filters: Mutex<FilterStore>,
    pub bitcoind: Option<Bitcoind>,
    pub blocks: BlockSource,
    pub wallets: RwLock<BTreeMap<String, Arc<Mutex<LoadedWallet>>>>,
    pub node_height: RwLock<Option<u32>>,
    pub fee_rates: RwLock<BTreeMap<u32, u32>>,
    pub shutdown: tokio::sync::Notify,
}

fn network_dir_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "Main",
        Network::Testnet => "TestNet",
        Network::Regtest => "RegTest",
        Network::Signet => "Signet",
        _ => "Main",
    }
}

impl Daemon {
    pub fn new(cfg: WasabiConfig, network: Network, datadir: PathBuf, socks: Option<String>, wallet_dir: Option<PathBuf>) -> anyhow::Result<Arc<Self>> {
        let net_name = network_dir_name(network);
        let wasabi_dir = wasabi_data_dir();
        let wasabi_store = wasabi_dir.join("BitcoinStore").join(net_name);
        let own_net_dir = datadir.join(net_name);
        std::fs::create_dir_all(&own_net_dir)?;
        let filters = FilterStore::open(Some(&wasabi_store.join("IndexStore/IndexStore.sqlite")), &own_net_dir.join("filters.sqlite"))?;
        let bitcoind = if cfg.bitcoin_rpc_end_point.is_empty() {
            None
        } else {
            match Bitcoind::new(&cfg.bitcoin_rpc_end_point, &cfg.bitcoin_rpc_credential_string, socks.as_deref()) {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::warn!("bitcoind config unusable: {e}");
                    None
                }
            }
        };
        let blocks = BlockSource {
            wasabi_blocks_dir: Some(wasabi_store.join("Blocks")).filter(|p| p.exists()),
            own_blocks_dir: own_net_dir.join("Blocks"),
            bitcoind: bitcoind.clone(),
            p2p: socks.as_deref().map(|s| wallet::p2p::P2pBlockFetcher::new(s, network)).filter(|p| p.has_peers()),
        };
        let tor_enabled = !cfg.use_tor.eq_ignore_ascii_case("Disabled");
        Ok(Arc::new(Self {
            cfg,
            network,
            datadir,
            wallet_dir: wallet_dir.unwrap_or_else(|| wasabi_dir.join("Wallets")),
            socks,
            tor_enabled,
            filters: Mutex::new(filters),
            bitcoind,
            blocks,
            wallets: RwLock::new(BTreeMap::new()),
            node_height: RwLock::new(None),
            fee_rates: RwLock::new(BTreeMap::new()),
            shutdown: tokio::sync::Notify::new(),
        }))
    }

    pub fn wallet_files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.wallet_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                    .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    pub async fn load_wallet(self: &Arc<Self>, name: &str) -> anyhow::Result<Arc<Mutex<LoadedWallet>>> {
        if let Some(w) = self.wallets.read().await.get(name) {
            return Ok(w.clone());
        }
        let path = self.wallet_dir.join(format!("{name}.json"));
        if !path.exists() {
            anyhow::bail!("wallet '{name}' not found");
        }
        let km = KeyManager::load(&path)?;
        if km.network() != self.network {
            anyhow::bail!("wallet '{name}' is for {:?}, daemon runs {:?}", km.network(), self.network);
        }
        let store = WalletStore::open(&self.datadir.join(network_dir_name(self.network)).join(format!("{name}.sqlite")))?;
        let mut lw = LoadedWallet { km, store, state: WalletState::default(), loaded: false, sync_progress: None, coinjoin_status: "Idle", last_error: None };
        lw.rebuild_state()?;
        let w = Arc::new(Mutex::new(lw));
        self.wallets.write().await.insert(name.to_string(), w.clone());
        let me = self.clone();
        let wname = name.to_string();
        tokio::spawn(async move {
            if let Err(e) = me.sync_wallet(&wname).await {
                tracing::warn!("sync {wname}: {e}");
            }
        });
        Ok(w)
    }

    pub async fn get_wallet(&self, name: &str) -> Option<Arc<Mutex<LoadedWallet>>> {
        self.wallets.read().await.get(name).cloned()
    }

    /// Scans one wallet to the current filter tip.
    pub async fn sync_wallet(self: &Arc<Self>, name: &str) -> anyhow::Result<()> {
        let Some(w) = self.get_wallet(name).await else { return Ok(()) };
        let mut lw = w.lock().await;
        let filters = self.filters.lock().await;
        let report = {
            let LoadedWallet { km, store, .. } = &mut *lw;
            let mut last_log = std::time::Instant::now();
            wallet::sync::scan(km, store, &filters, &self.blocks, |h, tip| {
                if last_log.elapsed().as_secs() >= 5 {
                    tracing::info!("{name}: scanned to {h} / {tip}");
                    last_log = std::time::Instant::now();
                }
            })
            .await
        };
        drop(filters);
        match report {
            Ok(r) => {
                if r.new_txs > 0 || !lw.loaded {
                    lw.rebuild_state()?;
                }
                if r.to > 0 {
                    lw.km.set_file_height(r.to);
                }
                lw.loaded = true;
                lw.last_error = None;
                if r.new_txs > 0 {
                    tracing::info!("{name}: {} new transactions in {} blocks ({}..{})", r.new_txs, r.matched_blocks, r.from, r.to);
                }
            }
            Err(e) => {
                lw.last_error = Some(e.to_string());
                return Err(e);
            }
        }
        Ok(())
    }

    /// Pulls new filters from bitcoind into our own store (handles a reorg at the tip).
    pub async fn update_filters(&self) -> anyhow::Result<u32> {
        let Some(node) = &self.bitcoind else { return Ok(0) };
        let node_height = node.get_block_count().await?;
        *self.node_height.write().await = Some(node_height);
        let mut added = 0;
        loop {
            let tip = { self.filters.lock().await.tip() };
            let (mut next, prev_hash) = match &tip {
                Some(t) => (t.height + 1, Some(t.block_hash)),
                None => (wallet::filters::SEGWIT_ACTIVATION_HEIGHT, None),
            };
            if let (Some(t), Some(ph)) = (&tip, prev_hash) {
                // Reorg check: our tip must still be the node's block at that height.
                let node_hash = node.get_block_hash(t.height).await?;
                if node_hash != ph {
                    tracing::warn!("reorg at {}: rolling back own filters", t.height);
                    let f = self.filters.lock().await;
                    f.rollback_own_above(t.height - 1)?;
                    for w in self.wallets.read().await.values() {
                        let lw = w.lock().await;
                        lw.store.rollback_above(t.height - 1)?;
                    }
                    continue;
                }
            }
            if next > node_height {
                break;
            }
            let end = (next + 50).min(node_height);
            let hash_calls: Vec<(&str, serde_json::Value)> = (next..=end).map(|h| ("getblockhash", serde_json::json!([h]))).collect();
            let hashes = node.batch(&hash_calls).await?;
            let mut filter_calls = Vec::new();
            let mut parsed: Vec<bitcoin::BlockHash> = Vec::new();
            for h in hashes {
                let s = h?;
                let bh: bitcoin::BlockHash = s.as_str().unwrap_or("").parse()?;
                filter_calls.push(("getblockfilter", serde_json::json!([bh.to_string(), "basic"])));
                filter_calls.push(("getblockheader", serde_json::json!([bh.to_string(), true])));
                parsed.push(bh);
            }
            let results = node.batch(&filter_calls).await?;
            let f = self.filters.lock().await;
            for (i, bh) in parsed.iter().enumerate() {
                let filter = results[2 * i].as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
                let header = results[2 * i + 1].as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
                let (data, fh) = Bitcoind::parse_filter(filter)?;
                let time = header.get("time").and_then(|v| v.as_i64()).unwrap_or(0);
                f.append(&FilterRow { height: next, block_hash: *bh, filter: data, filter_header: fh, time })?;
                next += 1;
                added += 1;
            }
        }
        Ok(added)
    }

    pub async fn update_fee_rates(&self) {
        let Some(node) = &self.bitcoind else { return };
        let mut rates = BTreeMap::new();
        for target in [2u32, 3, 6, 18, 36, 72, 144, 432, 1008] {
            if let Ok(Some(r)) = node.estimate_fee(target).await {
                rates.insert(target, r.ceil() as u32);
            }
        }
        if !rates.is_empty() {
            *self.fee_rates.write().await = rates;
        }
    }

    /// Background loop: new filters, fee rates, wallet scans.
    pub async fn run_sync_loop(self: Arc<Self>) {
        let mut first = true;
        loop {
            match self.update_filters().await {
                Ok(n) if n > 0 => tracing::info!("{n} new filters"),
                Ok(_) => {}
                Err(e) => tracing::warn!("filters: {e}"),
            }
            if first {
                self.update_fee_rates().await;
            }
            let names: Vec<String> = self.wallets.read().await.keys().cloned().collect();
            for n in names {
                if let Err(e) = self.sync_wallet(&n).await {
                    tracing::warn!("sync {n}: {e}");
                }
            }
            first = false;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                _ = self.shutdown.notified() => return,
            }
        }
    }
}
