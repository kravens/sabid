//! Scan: match every filter against the wallet's scripts, fetch matching blocks, store the
//! wallet's transactions. Blocks come from Wasabi's on-disk block cache when present, else bitcoind.

use crate::bitcoind::Bitcoind;
use crate::filters::{FilterRow, SEGWIT_ACTIVATION_HEIGHT};
use crate::keymanager::KeyManager;
use crate::store::WalletStore;
use bitcoin::bip158::BlockFilter;
use bitcoin::consensus::encode::deserialize;
use bitcoin::{Block, BlockHash, OutPoint};
use std::collections::HashSet;
use std::path::PathBuf;

pub struct BlockSource {
    /// Wasabi's `BitcoinStore/<net>/Blocks/` (files named by block hash)
    pub wasabi_blocks_dir: Option<PathBuf>,
    pub own_blocks_dir: PathBuf,
    pub bitcoind: Option<Bitcoind>,
    pub p2p: Option<crate::p2p::P2pBlockFetcher>,
}

impl BlockSource {
    pub async fn get(&self, hash: &BlockHash) -> anyhow::Result<Block> {
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
        if let Some(node) = &self.bitcoind {
            match node.get_block(hash).await {
                Ok(b) => return Ok(self.cache(b)),
                Err(e) => {
                    tracing::debug!("bitcoind getblock {name}: {e}");
                    last_err = e.into();
                }
            }
        }
        if let Some(p2p) = &self.p2p {
            match p2p.get_block(hash, 6).await {
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
}

/// Where a wallet scan starts: the store's synced height + 1, or the wallet's birth height.
pub fn scan_start(km: &KeyManager, store: &WalletStore) -> u32 {
    match store.synced_height() {
        Some(h) => h + 1,
        None => km.birth_height().unwrap_or(SEGWIT_ACTIVATION_HEIGHT).max(SEGWIT_ACTIVATION_HEIGHT),
    }
}

/// Phase 1 (under the wallet lock, CPU only): which of `rows` match the wallet's scripts.
pub fn match_batch(km: &mut KeyManager, rows: &[FilterRow]) -> anyhow::Result<Vec<usize>> {
    km.ensure_gap();
    let scripts = km.scripts();
    let mut matched = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let filter = BlockFilter::new(&row.filter);
        if filter.match_any(&row.block_hash, &mut scripts.iter().map(|s| s.as_bytes()))? {
            matched.push(i);
        }
    }
    Ok(matched)
}

/// Phase 2 (no locks, network): the matched blocks.
pub async fn fetch_blocks(blocks: &BlockSource, rows: &[FilterRow], matched: &[usize]) -> anyhow::Result<Vec<(usize, Block)>> {
    let mut out = Vec::with_capacity(matched.len());
    for &i in matched {
        out.push((i, blocks.get(&rows[i].block_hash).await?));
    }
    Ok(out)
}

/// Phase 3 (under the wallet lock): store the wallet's transactions of the matched blocks and
/// advance the synced height through the whole batch. Returns the next height and the report.
pub fn process_batch(km: &mut KeyManager, store: &WalletStore, rows: &[FilterRow], blocks: &[(usize, Block)]) -> anyhow::Result<(u32, ScanReport)> {
    let Some(first) = rows.first() else { anyhow::bail!("empty batch") };
    let mut report = ScanReport { from: first.height, to: first.height, ..Default::default() };
    let mut our_outpoints: HashSet<OutPoint> = HashSet::new();
    for st in store.all_txs()? {
        for (i, o) in st.tx.output.iter().enumerate() {
            if km.key_for_script(&o.script_pubkey).is_some() {
                our_outpoints.insert(OutPoint { txid: st.txid, vout: i as u32 });
            }
        }
    }
    let mut keys_changed = false;
    let mut next = first.height;
    let mut block_iter = blocks.iter().peekable();
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
        store.set_synced(row.height, &row.block_hash)?;
        report.to = row.height;
        next = row.height + 1;
    }
    if keys_changed {
        km.ensure_gap();
        km.save().ok();
    }
    Ok((next, report))
}
