//! Scan: match every filter against the wallet's scripts, fetch matching blocks, store the
//! wallet's transactions. Blocks come from Wasabi's on-disk block cache when present, else bitcoind.

use futures_util::{StreamExt, TryStreamExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::bitcoind::Bitcoind;
use crate::filters::{first_height, FilterRow};
use bitcoin::ScriptBuf;
use crate::keymanager::KeyManager;
use crate::store::WalletStore;
use bitcoin::bip158::BlockFilterReader;
use bitcoin::consensus::encode::deserialize;
use bitcoin::{Block, BlockHash, OutPoint};
use std::collections::HashSet;
use std::path::PathBuf;

pub struct BlockSource {
    /// Wasabi's `BitcoinStore/<net>/Blocks/` (files named by block hash)
    pub wasabi_blocks_dir: Option<PathBuf>,
    pub own_blocks_dir: PathBuf,
    pub bitcoind: Option<Bitcoind>,
    /// The node through separate Tor circuits, used round-robin by parallel fetches.
    pub node_pool: Vec<Bitcoind>,
    pub next_slot: AtomicUsize,
    pub p2p: Option<crate::p2p::P2pBlockFetcher>,
    /// Fetches in flight across every scan of the daemon.
    pub fetch_limit: Arc<Semaphore>,
}

/// Blocks in flight at once during a scan, each on its own Tor circuit to the node. Measured on
/// an onion node: more streams only share its upload bandwidth (16 streams were slower than 4).
pub const FETCH_SLOTS: usize = 4;
/// Threads matching filters; past this the memory churn of per-thread allocator arenas costs
/// more than the time it saves (eight cores already match 20000 filters a second).
pub const MATCH_THREADS: usize = 8;

impl BlockSource {
    pub fn with_node_pool(self) -> Self {
        self.with_node_pool_of(FETCH_SLOTS)
    }

    /// `n` node identities (Tor circuits) and `n` fetches in flight.
    pub fn with_node_pool_of(mut self, n: usize) -> Self {
        if let Some(node) = &self.bitcoind {
            self.node_pool = (0..n.max(1) as u32).filter_map(|i| node.with_identity(i).ok()).collect();
        }
        self.fetch_limit = Arc::new(Semaphore::new(n.max(1)));
        self
    }

    pub async fn get(&self, hash: &BlockHash) -> anyhow::Result<Block> {
        let slot = self.next_slot.fetch_add(1, Ordering::Relaxed);
        let name = hash.to_string();
        for dir in self.wasabi_blocks_dir.iter().chain(std::iter::once(&self.own_blocks_dir)) {
            let p = dir.join(&name);
            if let Ok(raw) = std::fs::read(&p) {
                if let Ok(b) = deserialize::<Block>(&raw) {
                    return Ok(b);
                }
            }
        }
        let mut last_err = anyhow::anyhow!("block {name}: no block source configured");
        let node = if self.node_pool.is_empty() { self.bitcoind.as_ref() } else { self.node_pool.get(slot % self.node_pool.len()) };
        if let Some(node) = node {
            match node.get_block(hash).await {
                Ok(b) => return Ok(self.cache(b)),
                Err(e) => {
                    tracing::warn!("bitcoind getblock {name}: {e}; trying P2P peers");
                    last_err = e.into();
                }
            }
        }
        if let Some(p2p) = &self.p2p {
            match p2p.get_block(hash, 12).await {
                Ok(b) => return Ok(self.cache(b)),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn cache(&self, block: Block) -> Block {
        std::fs::create_dir_all(&self.own_blocks_dir).ok();
        std::fs::write(self.own_blocks_dir.join(block.block_hash().to_string()), bitcoin::consensus::encode::serialize(&block)).ok();
        block
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScanReport {
    pub from: u32,
    pub to: u32,
    pub matched_blocks: u32,
    pub new_txs: u32,
    /// Keys were derived past the gap at this height: the rest of the batch and everything matched
    /// ahead did not see them, so the scan resumes right after this block with the new scripts.
    pub keys_changed_at: Option<u32>,
}

/// Where a wallet scan starts: the store's synced height + 1, or the wallet's birth height.
pub fn scan_start(km: &KeyManager, store: &WalletStore) -> u32 {
    match store.synced_height() {
        Some(h) => h + 1,
        None => km.birth_height().unwrap_or(first_height(km.network())).max(first_height(km.network())),
    }
}

/// Phase 1 (under the wallet lock, CPU only): which of `rows` match the wallet's scripts.
pub fn match_batch(km: &mut KeyManager, rows: &[FilterRow]) -> anyhow::Result<Vec<usize>> {
    km.ensure_gap();
    match_filters(&km.scripts(), rows)
}

/// Indexes of the rows whose filter matches any of the scripts, on up to `MATCH_THREADS` cores.
pub fn match_filters(scripts: &[ScriptBuf], rows: &[FilterRow]) -> anyhow::Result<Vec<usize>> {
    match_filters_with(scripts, rows, std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(MATCH_THREADS))
}

/// Each filter is keyed by its block hash, so every script is hashed again per filter: the work
/// is per filter and splits cleanly across threads.
pub fn match_filters_with(scripts: &[ScriptBuf], rows: &[FilterRow], threads: usize) -> anyhow::Result<Vec<usize>> {
    let threads = threads.max(1).min(rows.len().max(1));
    let chunk = rows.len().div_ceil(threads);
    let results: Vec<anyhow::Result<Vec<usize>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = rows
            .chunks(chunk.max(1))
            .enumerate()
            .map(|(c, part)| {
                scope.spawn(move || -> anyhow::Result<Vec<usize>> {
                    let mut matched = Vec::new();
                    for (j, row) in part.iter().enumerate() {
                        // Read the stored filter in place rather than copying it into a BlockFilter.
                        let reader = BlockFilterReader::new(&row.block_hash);
                        if reader.match_any(&mut &row.filter[..], &mut scripts.iter().map(|s| s.as_bytes()))? {
                            matched.push(c * chunk + j);
                        }
                    }
                    Ok(matched)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("matcher thread")).collect()
    });
    let mut matched = Vec::new();
    for r in results {
        matched.extend(r?);
    }
    matched.sort_unstable();
    Ok(matched)
}

/// Phase 2 (no locks, network): the matched blocks, within the source's shared fetch limit so
/// concurrent scans together keep the slots busy without flooding Tor.
pub async fn fetch_blocks(blocks: &BlockSource, rows: &[FilterRow], matched: &[usize]) -> anyhow::Result<Vec<(usize, Block)>> {
    let futs = matched.to_vec().into_iter().map(|i| {
        let limit = blocks.fetch_limit.clone();
        async move {
            let _permit = limit.acquire().await?;
            blocks.get(&rows[i].block_hash).await.map(|b| (i, b))
        }
    });
    let mut out: Vec<(usize, Block)> = futures_util::stream::iter(futs).buffer_unordered(FETCH_SLOTS).try_collect().await?;
    out.sort_by_key(|(i, _)| *i);
    Ok(out)
}

/// Block fetch throughput through the configured sources: `count` blocks, as many in flight as
/// the source allows (`with_node_pool_of`).
pub async fn bench_fetch(blocks: &BlockSource, hashes: &[BlockHash], concurrency: usize) -> anyhow::Result<(f64, f64)> {
    let t = std::time::Instant::now();
    let futs = hashes.to_vec().into_iter().map(|h| {
        let limit = blocks.fetch_limit.clone();
        async move {
            let _permit = limit.acquire().await?;
            blocks.get(&h).await.map(|b| bitcoin::consensus::encode::serialize(&b).len())
        }
    });
    let sizes: Vec<usize> = futures_util::stream::iter(futs).buffer_unordered(concurrency.max(1)).try_collect().await?;
    let secs = t.elapsed().as_secs_f64();
    Ok((hashes.len() as f64 / secs, sizes.iter().sum::<usize>() as f64 / 1e6 / secs))
}

/// `match_filters` for an async caller: chunks go to tokio's blocking pool (reused threads, no
/// per-batch thread and allocator-arena churn).
pub async fn match_filters_async(scripts: Arc<Vec<ScriptBuf>>, rows: Arc<Vec<FilterRow>>) -> anyhow::Result<Vec<usize>> {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(MATCH_THREADS).max(1);
    let chunk = rows.len().div_ceil(threads).max(1);
    let mut tasks = Vec::new();
    for c in 0..threads {
        let (start, end) = (c * chunk, ((c + 1) * chunk).min(rows.len()));
        if start >= end {
            break;
        }
        let (scripts, rows) = (scripts.clone(), rows.clone());
        tasks.push(tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<usize>> {
            let mut matched = Vec::new();
            for (j, row) in rows[start..end].iter().enumerate() {
                let reader = BlockFilterReader::new(&row.block_hash);
                if reader.match_any(&mut &row.filter[..], &mut scripts.iter().map(|s| s.as_bytes()))? {
                    matched.push(start + j);
                }
            }
            Ok(matched)
        }));
    }
    let mut matched = Vec::new();
    for t in tasks {
        matched.extend(t.await??);
    }
    matched.sort_unstable();
    Ok(matched)
}

/// The wallet's own unspent-or-not outpoints known so far, to recognise spends while scanning.
pub fn own_outpoints(km: &KeyManager, store: &WalletStore) -> anyhow::Result<HashSet<OutPoint>> {
    let mut ours = HashSet::new();
    for st in store.all_txs()? {
        for (i, o) in st.tx.output.iter().enumerate() {
            if km.key_for_script(&o.script_pubkey).is_some() {
                ours.insert(OutPoint { txid: st.txid, vout: i as u32 });
            }
        }
    }
    Ok(ours)
}

/// Phase 3 (under the wallet lock): store the wallet's transactions of the matched blocks and
/// advance the synced height through the whole batch. Returns the next height and the report.
pub fn process_batch(km: &mut KeyManager, store: &WalletStore, rows: &[FilterRow], blocks: &[(usize, Block)], our_outpoints: &mut HashSet<OutPoint>) -> anyhow::Result<(u32, ScanReport)> {
    let Some(first) = rows.first() else { anyhow::bail!("empty batch") };
    let mut report = ScanReport { from: first.height, to: first.height, ..Default::default() };
    let mut keys_changed = false;
    let mut next = first.height;
    let mut block_iter = blocks.iter().peekable();
    let mut synced_here = false;
    for (i, row) in rows.iter().enumerate() {
        if row.height != next {
            anyhow::bail!("filter store has a gap at height {next} (got {})", row.height);
        }
        if let Some((_, block)) = block_iter.next_if(|(bi, _)| *bi == i) {
            report.matched_blocks += 1;
            for (idx, tx) in block.txdata.iter().enumerate() {
                let spends_ours = tx.input.iter().any(|i| our_outpoints.contains(&i.previous_output));
                let pays_ours = tx.output.iter().any(|o| km.key_for_script(&o.script_pubkey).is_some());
                if !spends_ours && !pays_ours {
                    continue;
                }
                let txid = tx.compute_txid();
                store.insert_tx(tx, row.height, &row.block_hash, idx as u32, row.time)?;
                report.new_txs += 1;
                for (vout, o) in tx.output.iter().enumerate() {
                    if let Some(k) = km.key_for_script_mut(&o.script_pubkey) {
                        if k.state != crate::keymanager::KeyState::Used {
                            k.state = crate::keymanager::KeyState::Used;
                            keys_changed = true;
                        }
                        our_outpoints.insert(OutPoint { txid, vout: vout as u32 });
                    }
                }
            }
        }
        report.to = row.height;
        next = row.height + 1;
        if keys_changed {
            // New keys from here on: later rows of this batch were matched without them.
            store.set_synced(row.height, &row.block_hash)?;
            synced_here = true;
            km.ensure_gap();
            km.save().ok();
            report.keys_changed_at = Some(row.height);
            break;
        }
    }
    if !synced_here {
        if let Some(last) = rows.last() {
            store.set_synced(last.height, &last.block_hash)?;
        }
    }
    Ok((next, report))
}
