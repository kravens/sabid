//! Bootstrap a wallet's transaction store from Wasabi's own confirmed-transaction store
//! (`BitcoinStore/<net>/ConfirmedTransactions/2/Transactions.sqlite`), so a wallet Wasabi already
//! synced does not need a rescan from its birth height.

use crate::keymanager::KeyManager;
use crate::store::WalletStore;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Transaction};
use rusqlite::{Connection, OpenFlags};
use std::collections::HashSet;
use std::path::Path;

/// Returns the number of imported transactions and the highest height seen.
pub fn from_wasabi_store(wasabi_tx_store: &Path, km: &KeyManager, store: &WalletStore) -> anyhow::Result<(usize, u32)> {
    let uri = format!("file:{}?mode=ro&immutable=1", wasabi_tx_store.display());
    let conn = Connection::open_with_flags(uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)?;
    let mut st = conn.prepare("SELECT block_height, block_hash, block_index, first_seen, tx FROM \"transaction\" WHERE block_hash IS NOT NULL ORDER BY block_height, block_index")?;
    let rows = st.query_map([], |r| {
        let hash: Vec<u8> = r.get(1)?;
        Ok((r.get::<_, i64>(0)?, hash, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, Vec<u8>>(4)?))
    })?;
    let scripts: HashSet<_> = km.scripts().into_iter().collect();
    let mut ours: HashSet<OutPoint> = HashSet::new();
    let mut imported = 0;
    let mut max_height = 0u32;
    for row in rows {
        let (height, hash, index, first_seen, raw) = row?;
        if height <= 0 || height >= i32::MAX as i64 - 1 {
            continue;
        }
        let Ok(tx): Result<Transaction, _> = deserialize(&raw) else { continue };
        let txid = tx.compute_txid();
        let pays = tx.output.iter().any(|o| scripts.contains(&o.script_pubkey));
        let spends = tx.input.iter().any(|i| ours.contains(&i.previous_output));
        if !pays && !spends {
            continue;
        }
        for (vout, o) in tx.output.iter().enumerate() {
            if scripts.contains(&o.script_pubkey) {
                ours.insert(OutPoint { txid, vout: vout as u32 });
            }
        }
        let block_hash = BlockHash::from_slice(&hash).unwrap_or(BlockHash::all_zeros());
        store.insert_tx(&tx, height as u32, &block_hash, index as u32, first_seen)?;
        imported += 1;
        max_height = max_height.max(height as u32);
    }
    Ok((imported, max_height))
}
