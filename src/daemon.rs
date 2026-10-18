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
    pub last_error: Option<String>,
    /// Decrypted master key of a soft wallet and its wall-clock expiry (`unlockwallet`).
    pub unlocked: Option<(bitcoin::bip32::Xpriv, std::time::SystemTime)>,
}

impl LoadedWallet {
    pub fn is_unlocked(&self) -> bool {
        matches!(&self.unlocked, Some((_, until)) if std::time::SystemTime::now() < *until)
    }

    /// The cached master key while it lasts; an expired one is erased here.
    pub fn unlocked_master(&mut self) -> Option<bitcoin::bip32::Xpriv> {
        if self.is_unlocked() {
            return self.unlocked.map(|(m, _)| m);
        }
        self.lock();
        None
    }

    pub fn lock(&mut self) {
        if let Some((mut m, _)) = self.unlocked.take() {
            m.private_key.non_secure_erase();
        }
    }

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
    /// Where wallet files are read and written: sabid's own directory unless `--wallet-dir` says otherwise.
    pub wallet_dir: PathBuf,
    /// Wasabi's wallet directory, copied from (never written) when a wallet is first loaded.
    pub bootstrap_wallet_dir: Option<PathBuf>,
    pub socks: Option<String>,
    pub tor_enabled: bool,
    pub filters: Mutex<FilterStore>,
    pub bitcoind: Option<Bitcoind>,
    pub blocks: BlockSource,
    pub wallets: RwLock<BTreeMap<String, Arc<Mutex<LoadedWallet>>>>,
    pub managers: RwLock<BTreeMap<String, Arc<crate::coinjoin_manager::CoinJoinManager>>>,
    pub node_height: RwLock<Option<u32>>,
    /// Wallets with a scan in progress (the load-time scan and the periodic loop must not overlap).
    pub syncing: std::sync::Mutex<std::collections::HashSet<String>>,
    pub fee_rates: RwLock<BTreeMap<u32, u32>>,
    pub shutdown: tokio::sync::Notify,
}

pub fn network_dir_name(n: Network) -> &'static str {
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
            bootstrap_wallet_dir: wallet_dir.is_none().then(|| wasabi_dir.join("Wallets")),
            wallet_dir: wallet_dir.unwrap_or_else(|| own_net_dir.join("Wallets")),
            socks,
            tor_enabled,
            filters: Mutex::new(filters),
            bitcoind,
            blocks,
            wallets: RwLock::new(BTreeMap::new()),
            managers: RwLock::new(BTreeMap::new()),
            node_height: RwLock::new(None),
            syncing: std::sync::Mutex::new(std::collections::HashSet::new()),
            fee_rates: RwLock::new(BTreeMap::new()),
            shutdown: tokio::sync::Notify::new(),
        }))
    }

    /// A new wallet file in sabid's wallet directory; the name must be free there and in Wasabi's.
    pub fn create_wallet(&self, name: &str, mnemonic: &bip39::Mnemonic, password: &str, birth_height: u32) -> anyhow::Result<()> {
        if name.is_empty() || name.contains(['/', '\\']) || name == ".." || name.ends_with(".json") {
            anyhow::bail!("Invalid wallet name.");
        }
        if self.wallet_files().iter().any(|n| n == name) {
            anyhow::bail!("Wallet '{name}' already exists.");
        }
        wallet::create::write_wallet(&self.wallet_dir.join(format!("{name}.json")), mnemonic, password, self.network, birth_height)?;
        Ok(())
    }

    pub fn wallet_files(&self) -> Vec<String> {
        let list = |dir: &PathBuf| -> Vec<String> {
            std::fs::read_dir(dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut names = list(&self.wallet_dir);
        if let Some(b) = &self.bootstrap_wallet_dir {
            names.extend(list(b));
        }
        names.sort();
        names.dedup();
        names
    }

    pub async fn load_wallet(self: &Arc<Self>, name: &str) -> anyhow::Result<Arc<Mutex<LoadedWallet>>> {
        if let Some(w) = self.wallets.read().await.get(name) {
            return Ok(w.clone());
        }
        let path = self.wallet_dir.join(format!("{name}.json"));
        if !path.exists() {
            // First load: take Wasabi's file as the starting point; sabid writes only its own copy from here on.
            match self.bootstrap_wallet_dir.as_ref().map(|b| b.join(format!("{name}.json"))).filter(|p| p.exists()) {
                Some(src) => {
                    std::fs::create_dir_all(&self.wallet_dir)?;
                    std::fs::copy(&src, &path)?;
                    tracing::info!("wallet {name}: copied {} to {}; Wasabi's file stays untouched", src.display(), path.display());
                }
                None => anyhow::bail!("wallet '{name}' not found"),
            }
        }
        let km = KeyManager::load(&path)?;
        if km.network() != self.network {
            anyhow::bail!("wallet '{name}' is for {:?}, daemon runs {:?}", km.network(), self.network);
        }
        let store = WalletStore::open(&self.datadir.join(network_dir_name(self.network)).join(format!("{name}.sqlite")))?;
        let mut lw = LoadedWallet { km, store, state: WalletState::default(), loaded: false, sync_progress: None, last_error: None, unlocked: None };
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

    pub async fn manager(self: &Arc<Self>, name: &str) -> anyhow::Result<Arc<crate::coinjoin_manager::CoinJoinManager>> {
        if let Some(m) = self.managers.read().await.get(name) {
            return Ok(m.clone());
        }
        let w = self.get_wallet(name).await.ok_or_else(|| anyhow::anyhow!("wallet '{name}' is not loaded"))?;
        let m = crate::coinjoin_manager::CoinJoinManager::new(self.clone(), name, w)?;
        self.managers.write().await.insert(name.to_string(), m.clone());
        Ok(m)
    }

    /// Scans one wallet to the current filter tip, releasing the wallet between batches so
    /// RPC calls keep answering during a long scan.
    pub async fn sync_wallet(self: &Arc<Self>, name: &str) -> anyhow::Result<()> {
        if !self.syncing.lock().unwrap().insert(name.to_string()) {
            return Ok(());
        }
        let r = self.sync_wallet_inner(name).await;
        self.syncing.lock().unwrap().remove(name);
        r
    }

    async fn sync_wallet_inner(self: &Arc<Self>, name: &str) -> anyhow::Result<()> {
        let Some(w) = self.get_wallet(name).await else { return Ok(()) };
        let tip = { self.filters.lock().await.tip_height().unwrap_or(0) };
        let mut height = {
            let lw = w.lock().await;
            wallet::sync::scan_start(&lw.km, &lw.store)
        };
        let mut total_new = 0u32;
        let mut last_log = std::time::Instant::now();
        while height <= tip {
            // Short locks: filters only while reading rows, the wallet only for matching and processing.
            let rows = { self.filters.lock().await.range(height, 2000)? };
            if rows.is_empty() {
                break;
            }
            let matched = {
                let mut lw = w.lock().await;
                wallet::sync::match_batch(&mut lw.km, &rows)?
            };
            let blocks = match wallet::sync::fetch_blocks(&self.blocks, &rows, &matched).await {
                Ok(b) => b,
                Err(e) => {
                    w.lock().await.last_error = Some(e.to_string());
                    return Err(e);
                }
            };
            let (next, report) = {
                let mut lw = w.lock().await;
                let LoadedWallet { km, store, .. } = &mut *lw;
                let r = wallet::sync::process_batch(km, store, &rows, &blocks)?;
                lw.sync_progress = Some((r.1.to, tip));
                if r.1.new_txs > 0 {
                    lw.rebuild_state()?;
                    tracing::info!("{name}: {} new transactions in {} blocks ({}..{})", r.1.new_txs, r.1.matched_blocks, r.1.from, r.1.to);
                }
                r
            };
            total_new += report.new_txs;
            if next == height {
                break;
            }
            height = next;
            if last_log.elapsed().as_secs() >= 10 {
                tracing::info!("{name}: scanned to {} / {tip}", height - 1);
                last_log = std::time::Instant::now();
            }
        }
        let mut lw = w.lock().await;
        if !lw.loaded || total_new > 0 {
            lw.rebuild_state()?;
        }
        if tip > 0 {
            lw.km.set_file_height(tip);
        }
        lw.loaded = true;
        lw.sync_progress = None;
        lw.last_error = None;
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
                    // Filters first, released before any wallet lock (RPC handlers lock wallet then filters).
                    let after = {
                        let f = self.filters.lock().await;
                        f.rollback_own_above(t.height - 1)?;
                        f.tip()
                    };
                    if after.as_ref().map(|a| a.block_hash) == Some(ph) {
                        anyhow::bail!("reorg at {} reaches into Wasabi's read-only filter store; let Wasabi repair it", t.height);
                    }
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
    /// Wasabi started while sabid runs: stop coinjoining, let critical phases finish, then exit.
    async fn wasabi_appeared(&self, what: String) {
        tracing::error!("Wasabi Wallet started: {what}. {}", crate::wasabi_guard::WARNING);
        let managers: Vec<_> = self.managers.read().await.values().cloned().collect();
        for m in &managers {
            m.stop();
        }
        for _ in 0..120 {
            if managers.iter().all(|m| !*m.in_critical.lock().unwrap()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        tracing::error!("shutting down because Wasabi Wallet is running");
        self.shutdown.notify_waiters();
    }

    pub async fn run_sync_loop(self: Arc<Self>) {
        let mut iteration: u32 = 0;
        loop {
            if let Some(w) = crate::wasabi_guard::wasabi_running() {
                self.wasabi_appeared(w).await;
                return;
            }
            match self.update_filters().await {
                Ok(n) if n > 0 => tracing::info!("{n} new filters"),
                Ok(_) => {}
                Err(e) => tracing::warn!("filters: {e}"),
            }
            if iteration % 20 == 0 {
                self.update_fee_rates().await; // about every ten minutes
            }
            let names: Vec<String> = self.wallets.read().await.keys().cloned().collect();
            for n in names {
                if let Err(e) = self.sync_wallet(&n).await {
                    tracing::warn!("sync {n}: {e}");
                }
            }
            iteration = iteration.wrapping_add(1);
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                _ = self.shutdown.notified() => return,
            }
        }
    }
}
