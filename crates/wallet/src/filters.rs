//! BIP158 filter store. Wasabi keeps every filter since segwit activation in
//! `BitcoinStore/<net>/IndexStore/IndexStore.sqlite` (table `filter`); sabid reads that read-only
//! and appends newer filters to its own database with the same schema.

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;
use std::sync::Mutex;

pub const SEGWIT_ACTIVATION_HEIGHT: u32 = 481_824;

/// The first block worth a filter: segwit activation on mainnet, the genesis block elsewhere.
pub fn first_height(network: bitcoin::Network) -> u32 {
    if network == bitcoin::Network::Bitcoin {
        SEGWIT_ACTIVATION_HEIGHT
    } else {
        0
    }
}

#[derive(Debug, Clone)]
pub struct FilterRow {
    pub height: u32,
    pub block_hash: BlockHash,
    pub filter: Vec<u8>,
    /// Wasabi stores the BIP157 filter header in `previous_block_hash`.
    pub filter_header: [u8; 32],
    pub time: i64,
}

pub struct FilterStore {
    wasabi: Option<Mutex<Connection>>,
    own: Mutex<Connection>,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS filter (
    block_height INTEGER NOT NULL PRIMARY KEY,
    block_hash BLOB NOT NULL,
    filter_data BLOB NOT NULL,
    previous_block_hash BLOB NOT NULL,
    epoch_block_time INTEGER NOT NULL
);";

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<FilterRow> {
    let hash: Vec<u8> = r.get(1)?;
    let header: Vec<u8> = r.get(3)?;
    Ok(FilterRow {
        height: r.get::<_, i64>(0)? as u32,
        block_hash: BlockHash::from_slice(&hash).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        filter: r.get(2)?,
        filter_header: header.try_into().unwrap_or([0u8; 32]),
        time: r.get(4)?,
    })
}

impl FilterStore {
    pub fn open(wasabi_index: Option<&Path>, own_path: &Path) -> rusqlite::Result<Self> {
        let wasabi = match wasabi_index {
            Some(p) if p.exists() => {
                let uri = format!("file:{}?mode=ro&immutable=1", p.display());
                Some(Mutex::new(Connection::open_with_flags(uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX)?))
            }
            _ => None,
        };
        if let Some(parent) = own_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let own = Connection::open(own_path)?;
        own.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        own.execute_batch(SCHEMA)?;
        Ok(Self { wasabi, own: Mutex::new(own) })
    }

    fn wasabi_tip(&self) -> Option<u32> {
        self.wasabi.as_ref()?.lock().unwrap().query_row("SELECT MAX(block_height) FROM filter", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten().map(|h| h as u32)
    }

    fn own_tip(&self) -> Option<u32> {
        self.own.lock().unwrap().query_row("SELECT MAX(block_height) FROM filter", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten().map(|h| h as u32)
    }

    pub fn tip(&self) -> Option<FilterRow> {
        let h = self.wasabi_tip().into_iter().chain(self.own_tip()).max()?;
        self.get(h)
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.wasabi_tip().into_iter().chain(self.own_tip()).max()
    }

    pub fn count(&self) -> u64 {
        let w = self.wasabi.as_ref().and_then(|c| c.lock().unwrap().query_row("SELECT COUNT(*) FROM filter", [], |r| r.get::<_, i64>(0)).ok()).unwrap_or(0);
        let wt = self.wasabi_tip().unwrap_or(0);
        let o = self.own.lock().unwrap().query_row("SELECT COUNT(*) FROM filter WHERE block_height > ?1", params![wt as i64], |r| r.get::<_, i64>(0)).unwrap_or(0);
        (w + o) as u64
    }

    pub fn get(&self, height: u32) -> Option<FilterRow> {
        let q = "SELECT block_height, block_hash, filter_data, previous_block_hash, epoch_block_time FROM filter WHERE block_height = ?1";
        if let Some(w) = &self.wasabi {
            if let Ok(r) = w.lock().unwrap().query_row(q, params![height as i64], row_from) {
                return Some(r);
            }
        }
        self.own.lock().unwrap().query_row(q, params![height as i64], row_from).ok()
    }

    /// Filters from `from` upwards, at most `limit`, Wasabi's store first then our own.
    pub fn range(&self, from: u32, limit: usize) -> rusqlite::Result<Vec<FilterRow>> {
        let q = "SELECT block_height, block_hash, filter_data, previous_block_hash, epoch_block_time FROM filter WHERE block_height >= ?1 ORDER BY block_height LIMIT ?2";
        let mut out = Vec::new();
        if let Some(w) = &self.wasabi {
            let w = w.lock().unwrap();
            let mut st = w.prepare_cached(q)?;
            out = st.query_map(params![from as i64, limit as i64], row_from)?.collect::<Result<Vec<_>, _>>()?;
        }
        if out.len() < limit {
            let next = out.last().map(|r| r.height + 1).unwrap_or(from);
            let own = self.own.lock().unwrap();
            let mut st = own.prepare_cached(q)?;
            let more = st.query_map(params![next as i64, (limit - out.len()) as i64], row_from)?.collect::<Result<Vec<_>, _>>()?;
            out.extend(more);
        }
        Ok(out)
    }

    pub fn append(&self, row: &FilterRow) -> rusqlite::Result<()> {
        self.own.lock().unwrap().execute(
            "INSERT OR REPLACE INTO filter (block_height, block_hash, filter_data, previous_block_hash, epoch_block_time) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![row.height as i64, row.block_hash.as_byte_array().to_vec(), row.filter, row.filter_header.to_vec(), row.time],
        )?;
        Ok(())
    }

    /// Drops our own filters above `height` (a reorg); Wasabi's store is never written.
    pub fn rollback_own_above(&self, height: u32) -> rusqlite::Result<usize> {
        self.own.lock().unwrap().execute("DELETE FROM filter WHERE block_height > ?1", params![height as i64])
    }
}
