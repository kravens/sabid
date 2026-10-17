//! Per-wallet transaction store (`~/.sabid/<net>/<wallet>.sqlite`) and the coin/history view
//! derived from it (Wasabi `TransactionProcessor` + `CoinsRegistry`, confirmed transactions only).

use crate::keymanager::{KeyManager, KeyState};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
use rusqlite::{params, Connection};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

/// Wasabi `Height.Mempool`: unconfirmed transactions sort after every block.
pub const MEMPOOL_HEIGHT: u32 = i32::MAX as u32 - 1;

pub struct WalletStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct StoredTx {
    pub txid: Txid,
    pub tx: Transaction,
    pub height: u32,
    pub block_hash: BlockHash,
    pub block_index: u32,
    pub time: i64,
}

impl WalletStore {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS txs (
                txid BLOB NOT NULL PRIMARY KEY,
                raw BLOB NOT NULL,
                height INTEGER NOT NULL,
                block_hash BLOB NOT NULL,
                block_index INTEGER NOT NULL,
                time INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_txs_height ON txs(height);
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn synced_height(&self) -> Option<u32> {
        self.conn.lock().unwrap().query_row("SELECT value FROM state WHERE key = 'height'", [], |r| r.get::<_, String>(0)).ok().and_then(|s| s.parse().ok())
    }

    pub fn synced_hash(&self) -> Option<BlockHash> {
        self.conn.lock().unwrap().query_row("SELECT value FROM state WHERE key = 'hash'", [], |r| r.get::<_, String>(0)).ok().and_then(|s| s.parse().ok())
    }

    pub fn set_synced(&self, height: u32, hash: &BlockHash) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute("INSERT OR REPLACE INTO state (key, value) VALUES ('height', ?1)", params![height.to_string()])?;
        self.conn.lock().unwrap().execute("INSERT OR REPLACE INTO state (key, value) VALUES ('hash', ?1)", params![hash.to_string()])?;
        Ok(())
    }

    pub fn insert_tx(&self, tx: &Transaction, height: u32, block_hash: &BlockHash, block_index: u32, time: i64) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO txs (txid, raw, height, block_hash, block_index, time) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![tx.compute_txid().as_byte_array().to_vec(), serialize(tx), height as i64, block_hash.as_byte_array().to_vec(), block_index as i64, time],
        )?;
        Ok(())
    }

    pub fn rollback_above(&self, height: u32) -> rusqlite::Result<usize> {
        self.conn.lock().unwrap().execute("DELETE FROM txs WHERE height > ?1", params![height as i64])
    }

    pub fn all_txs(&self) -> rusqlite::Result<Vec<StoredTx>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn.prepare("SELECT txid, raw, height, block_hash, block_index, time FROM txs ORDER BY height, block_index")?;
        let rows = st.query_map([], |r| {
            let txid: Vec<u8> = r.get(0)?;
            let raw: Vec<u8> = r.get(1)?;
            let hash: Vec<u8> = r.get(3)?;
            Ok((txid, raw, r.get::<_, i64>(2)? as u32, hash, r.get::<_, i64>(4)? as u32, r.get::<_, i64>(5)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (txid, raw, height, hash, idx, time) = row?;
            let tx: Transaction = match deserialize(&raw) {
                Ok(t) => t,
                Err(_) => continue,
            };
            out.push(StoredTx {
                txid: Txid::from_slice(&txid).unwrap_or(tx.compute_txid()),
                tx,
                height,
                block_hash: BlockHash::from_slice(&hash).unwrap_or(BlockHash::all_zeros()),
                block_index: idx,
                time,
            });
        }
        Ok(out)
    }

    pub fn get_tx(&self, txid: &Txid) -> Option<Transaction> {
        let raw: Vec<u8> = self.conn.lock().unwrap().query_row("SELECT raw FROM txs WHERE txid = ?1", params![txid.as_byte_array().to_vec()], |r| r.get(0)).ok()?;
        deserialize(&raw).ok()
    }
}

#[derive(Debug, Clone)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub amount: u64,
    pub script: ScriptBuf,
    pub key_path: String,
    pub label: String,
    pub height: u32,
    pub spender: Option<Txid>,
    /// ponytail: heuristic (1, or the equal-output count in an own coinjoin); the real
    /// BlockchainAnalyzer port replaces it in M2.
    pub anonymity_set: f64,
    pub excluded_from_coinjoin: bool,
    pub is_own_coinjoin_output: bool,
}

impl Coin {
    pub fn is_spent(&self) -> bool {
        self.spender.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct TxSummary {
    pub txid: Txid,
    pub height: u32,
    pub time: i64,
    pub amount: i64,
    pub labels: String,
    pub is_own_coinjoin: bool,
    pub wallet_inputs: usize,
    pub total_inputs: usize,
}

#[derive(Debug, Default, Clone)]
pub struct WalletState {
    pub coins: Vec<Coin>,
    pub history: Vec<TxSummary>,
}

impl WalletState {
    /// Replays the stored transactions in block order against the wallet's keys. Marks keys
    /// `Used` on the key manager (caller persists when it changed).
    pub fn build(txs: &[StoredTx], km: &mut KeyManager) -> (WalletState, bool) {
        let mut keys_changed = false;
        let mut by_script: HashMap<ScriptBuf, usize> = km.keys.iter().enumerate().map(|(i, k)| (k.script.clone(), i)).collect();
        let excluded: HashSet<OutPoint> = km.excluded_coins().into_iter().collect();
        let mut coins: BTreeMap<OutPoint, Coin> = BTreeMap::new();
        let mut history = Vec::new();
        for st in txs {
            let txid = st.txid;
            let mut amount: i64 = 0;
            let mut wallet_inputs = 0;
            let mut labels: Vec<String> = Vec::new();
            for input in &st.tx.input {
                if let Some(c) = coins.get_mut(&input.previous_output) {
                    c.spender = Some(txid);
                    amount -= c.amount as i64;
                    wallet_inputs += 1;
                    if !c.label.is_empty() && !labels.contains(&c.label) {
                        labels.push(c.label.clone());
                    }
                }
            }
            let is_own_coinjoin = wallet_inputs > 0 && wallet_inputs != st.tx.input.len();
            let mut value_counts: HashMap<u64, usize> = HashMap::new();
            for o in &st.tx.output {
                *value_counts.entry(o.value.to_sat()).or_default() += 1;
            }
            for (vout, out) in st.tx.output.iter().enumerate() {
                let Some(&ki) = by_script.get(&out.script_pubkey) else { continue };
                let key = &mut km.keys[ki];
                if key.state != KeyState::Used {
                    key.state = KeyState::Used;
                    keys_changed = true;
                }
                amount += out.value.to_sat() as i64;
                if !key.label.is_empty() && !labels.contains(&key.label) {
                    labels.push(key.label.clone());
                }
                let op = OutPoint { txid, vout: vout as u32 };
                let equal = value_counts.get(&out.value.to_sat()).copied().unwrap_or(1);
                coins.insert(
                    op,
                    Coin {
                        outpoint: op,
                        amount: out.value.to_sat(),
                        script: out.script_pubkey.clone(),
                        key_path: key.path.clone(),
                        label: key.label.clone(),
                        height: st.height,
                        spender: None,
                        anonymity_set: if is_own_coinjoin && equal > 1 { equal as f64 } else { 1.0 },
                        excluded_from_coinjoin: excluded.contains(&op),
                        is_own_coinjoin_output: is_own_coinjoin,
                    },
                );
            }
            if keys_changed && km.ensure_gap() {
                by_script = km.keys.iter().enumerate().map(|(i, k)| (k.script.clone(), i)).collect();
            }
            history.push(TxSummary {
                txid,
                height: st.height,
                time: st.time,
                amount,
                labels: labels.join(", "),
                is_own_coinjoin,
                wallet_inputs,
                total_inputs: st.tx.input.len(),
            });
        }
        (WalletState { coins: coins.into_values().collect(), history }, keys_changed)
    }

    pub fn unspent(&self) -> impl Iterator<Item = &Coin> {
        self.coins.iter().filter(|c| !c.is_spent())
    }

    pub fn balance(&self) -> u64 {
        self.unspent().map(|c| c.amount).sum()
    }
}
