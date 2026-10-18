//! Per-wallet coinjoin manager (Wasabi `CoinJoinManager` + `CoinJoinTracker`): start/stop,
//! coin candidates, pleb stop, auto-restart until all coins are private, bans, result handling.

use crate::daemon::{Daemon, LoadedWallet};
use bitcoin::bip32::DerivationPath;
use bitcoin::{OutPoint, ScriptBuf};
use coinjoin::client::{CjError, CoinJoinClient, CoinJoinConfig, CoinJoinResult, CoinjoinError, Progress};
use coinjoin::destinations::DestinationProvider;
use coinjoin::keychain::{derivation_path, KeyChain, SoftKeyChain};
use coinjoin::round_state::RoundStateUpdater;
use coinjoin::selector::{CjCoin, CoinJoinCoinSelector};
use coinjoin::ScriptType;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::CancellationToken;
use wallet::{AccountKind, KeyState};
use wasabi_proto::{CoordinatorClient, ProxyConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinJoinClientState {
    Idle,
    InSchedule,
    InProgress,
    InCriticalPhase,
}

impl CoinJoinClientState {
    pub fn as_wasabi(&self) -> &'static str {
        match self {
            CoinJoinClientState::Idle => "Idle",
            CoinJoinClientState::InSchedule => "In schedule",
            CoinJoinClientState::InProgress => "In progress",
            CoinJoinClientState::InCriticalPhase => "In critical phase",
        }
    }
}

/// `PrisonedCoins.json` entry (Wasabi's format, kept in the same per-coordinator directory).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PrisonedCoinRecord {
    pub outpoint: String,
    pub banned_until: chrono::DateTime<chrono::FixedOffset>,
}

pub struct CoinPrison {
    path: PathBuf,
    records: std::sync::Mutex<HashMap<OutPoint, chrono::DateTime<chrono::FixedOffset>>>,
}

impl CoinPrison {
    pub fn load(path: PathBuf) -> Self {
        let mut records = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(list) = serde_json::from_str::<Vec<PrisonedCoinRecord>>(text.trim_start_matches('\u{feff}')) {
                for r in list {
                    if let Some(op) = wasabi_proto::script::outpoint_from_hex(&r.outpoint) {
                        records.insert(op, r.banned_until);
                    }
                }
            }
        }
        Self { path, records: std::sync::Mutex::new(records) }
    }

    pub fn is_banned(&self, op: &OutPoint) -> bool {
        self.records.lock().unwrap().get(op).map(|u| *u > chrono::Utc::now()).unwrap_or(false)
    }

    pub fn ban(&self, op: OutPoint, until: chrono::DateTime<chrono::FixedOffset>) {
        let mut r = self.records.lock().unwrap();
        if until < chrono::Utc::now() || r.contains_key(&op) {
            return;
        }
        r.insert(op, until);
        let list: Vec<PrisonedCoinRecord> = r.iter().map(|(o, u)| PrisonedCoinRecord { outpoint: wasabi_proto::script::outpoint_to_hex(o), banned_until: *u }).collect();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if let Ok(text) = serde_json::to_string_pretty(&list) {
            std::fs::write(&self.path, text).ok();
        }
    }
}

/// `InternalDestinationProvider` over the daemon's wallet (locked internal keys).
pub struct WalletDestinations {
    wallet: Arc<Mutex<LoadedWallet>>,
}

impl WalletDestinations {
    fn with_wallet<T>(&self, f: impl FnOnce(&mut LoadedWallet) -> T) -> T {
        tokio::task::block_in_place(|| {
            let mut w = tokio::runtime::Handle::current().block_on(self.wallet.lock());
            f(&mut w)
        })
    }
}

impl DestinationProvider for WalletDestinations {
    fn supported_script_types(&self) -> Vec<ScriptType> {
        self.with_wallet(|w| {
            if w.km.has_slip25_account() {
                vec![ScriptType::Taproot]
            } else if w.km.taproot_xpub().is_some() {
                vec![ScriptType::P2WPKH, ScriptType::Taproot]
            } else {
                vec![ScriptType::P2WPKH]
            }
        })
    }

    fn next_destinations(&self, count: usize, prefer_taproot: bool) -> Vec<ScriptBuf> {
        self.with_wallet(|w| {
            let taproot_only = w.km.has_slip25_account();
            w.km.ensure_gap();
            let want_taproot = taproot_only || prefer_taproot;
            let kind = if want_taproot { w.km.taproot_kind().unwrap_or(AccountKind::Segwit) } else { AccountKind::Segwit };
            // Wasabi hands out the wallet's locked internal keys (left over from earlier rounds) and
            // locks clean ones only when there are not enough (AssertLockedInternalKeysIndexedAndPersist).
            let mut scripts: Vec<ScriptBuf> = w.km.keys.iter().filter(|k| k.kind == kind && k.is_internal && k.state == KeyState::Locked).map(|k| k.script.clone()).collect();
            for k in w.km.keys.iter_mut().filter(|k| k.kind == kind && k.is_internal && k.state == KeyState::Clean) {
                if scripts.len() >= count {
                    break;
                }
                k.state = KeyState::Locked;
                scripts.push(k.script.clone());
            }
            scripts.truncate(count.max(scripts.len().min(count)));
            w.km.ensure_gap();
            w.km.save().ok();
            scripts
        })
    }

    fn set_used(&self, scripts: &[ScriptBuf]) {
        self.with_wallet(|w| {
            for s in scripts {
                if let Some(k) = w.km.key_for_script_mut(s) {
                    k.state = KeyState::Used;
                }
            }
            w.km.save().ok();
        })
    }
}

pub struct CoinJoinManager {
    pub daemon: Arc<Daemon>,
    pub wallet_name: String,
    pub wallet: Arc<Mutex<LoadedWallet>>,
    pub state: std::sync::Mutex<CoinJoinClientState>,
    pub stop_when_all_mixed: std::sync::Mutex<bool>,
    pub override_pleb_stop: std::sync::Mutex<bool>,
    pub cancel: std::sync::Mutex<Option<CancellationToken>>,
    pub in_critical: std::sync::Mutex<bool>,
    pub last_error: std::sync::Mutex<Option<String>>,
    pub updater: Arc<RoundStateUpdater>,
    pub updater_stop: Arc<Notify>,
    pub prison: Arc<CoinPrison>,
    pub liquidity_clue: Arc<Mutex<Option<i64>>>,
    pub trezor: Mutex<Option<Arc<hw::TrezorKeyChain>>>,
    pub coldcard: Mutex<Option<Arc<hw::ColdcardKeyChain>>>,
}

pub const PLEB_STOP_DEFAULT_SATS: i64 = 1_000_000;

fn candidate_coins(w: &LoadedWallet, prison: &CoinPrison) -> (Vec<CjCoin>, Vec<coinjoin::client::CoinjoinError>) {
    let hardware_taproot_only = w.km.has_slip25_account();
    let mut reasons = Vec::new();
    let mut out = Vec::new();
    for c in w.state.unspent() {
        let Some(st) = ScriptType::of_script(&c.script) else { continue };
        if hardware_taproot_only && st != ScriptType::Taproot {
            continue;
        }
        if c.height == wallet::store::MEMPOOL_HEIGHT {
            reasons.push(CoinjoinError::NoConfirmedCoinsEligibleToMix);
            continue;
        }
        if c.excluded_from_coinjoin {
            reasons.push(CoinjoinError::OnlyExcludedCoinsAvailable);
            continue;
        }
        if prison.is_banned(&c.outpoint) {
            reasons.push(CoinjoinError::CoinsRejected);
            continue;
        }
        out.push(CjCoin { outpoint: c.outpoint, amount: c.amount as i64, script: c.script.clone(), script_type: st, anonymity_set: c.anonymity_set });
    }
    (out, reasons)
}

impl CoinJoinManager {
    pub fn new(daemon: Arc<Daemon>, wallet_name: &str, wallet: Arc<Mutex<LoadedWallet>>) -> anyhow::Result<Arc<Self>> {
        let coordinator = daemon.cfg.coordinator_uri.clone();
        let proxy = daemon.socks.clone().map(|socks5| ProxyConfig { socks5 });
        let status_client = CoordinatorClient::new(&coordinator, proxy.as_ref(), "satoshi")?;
        let updater = RoundStateUpdater::new(status_client);
        let host = reqwest::Url::parse(&coordinator).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| "coordinator".into());
        let prison = Arc::new(CoinPrison::load(crate::config::wasabi_data_dir().join(host).join("PrisonedCoins.json")));
        let m = Arc::new(Self {
            daemon,
            wallet_name: wallet_name.to_string(),
            wallet,
            state: std::sync::Mutex::new(CoinJoinClientState::Idle),
            stop_when_all_mixed: std::sync::Mutex::new(true),
            override_pleb_stop: std::sync::Mutex::new(false),
            cancel: std::sync::Mutex::new(None),
            in_critical: std::sync::Mutex::new(false),
            last_error: std::sync::Mutex::new(None),
            updater: updater.clone(),
            updater_stop: Arc::new(Notify::new()),
            prison,
            liquidity_clue: Arc::new(Mutex::new(None)),
            trezor: Mutex::new(None),
            coldcard: Mutex::new(None),
        });
        tokio::spawn(updater.run(m.updater_stop.clone()));
        Ok(m)
    }

    pub fn status(&self) -> CoinJoinClientState {
        *self.state.lock().unwrap()
    }

    fn set_state(&self, s: CoinJoinClientState) {
        *self.state.lock().unwrap() = s;
    }

    pub fn stop(&self) {
        *self.stop_when_all_mixed.lock().unwrap() = true;
        let in_critical = *self.in_critical.lock().unwrap();
        if let Some(c) = self.cancel.lock().unwrap().as_ref() {
            if !in_critical {
                c.cancel();
            }
        }
        if !in_critical {
            self.set_state(CoinJoinClientState::Idle);
        }
    }

    /// `RequestCoinJoinStart`: builds the key chain now (so a bad password fails here) and
    /// runs rounds in the background until stopped or all coins are private.
    pub async fn start(self: &Arc<Self>, password: Option<String>, stop_when_all_mixed: bool, override_pleb_stop: bool) -> Result<(), String> {
        if self.status() != CoinJoinClientState::Idle {
            *self.stop_when_all_mixed.lock().unwrap() = stop_when_all_mixed;
            return Ok(());
        }
        let key_chain: Arc<dyn KeyChain> = {
            let w = self.wallet.lock().await;
            if w.km.is_hardware_wallet() {
                drop(w);
                self.device_key_chain().await?
            } else {
            let (Some(enc), Some(cc)) = (w.km.encrypted_secret(), w.km.chain_code()) else { return Err("This is a watch-only wallet.".into()) };
            let mut paths: HashMap<ScriptBuf, DerivationPath> = HashMap::new();
            for k in &w.km.keys {
                if let Some(p) = derivation_path(&k.path) {
                    paths.insert(k.script.clone(), p);
                }
            }
            Arc::new(SoftKeyChain::new(enc, cc, password.as_deref().unwrap_or(""), w.km.network(), paths).map_err(|e| e.to_string())?)
            }
        };
        *self.stop_when_all_mixed.lock().unwrap() = stop_when_all_mixed;
        *self.override_pleb_stop.lock().unwrap() = override_pleb_stop;
        let cancel = CancellationToken::new();
        *self.cancel.lock().unwrap() = Some(cancel.clone());
        self.set_state(CoinJoinClientState::InProgress);
        *self.last_error.lock().unwrap() = None;
        let me = self.clone();
        tokio::spawn(async move { me.run_loop(key_chain, cancel).await });
        Ok(())
    }

    /// Preview 8 flow: the device authorizes a batch of rounds (hold-to-confirm on the Trezor) and
    /// the key chain that signs them is kept until the authorization is spent or the session is gone.
    async fn device_key_chain(self: &Arc<Self>) -> Result<Arc<dyn KeyChain>, String> {
        let (vendor, fingerprint, network, account, max_rounds, max_fee, paths, has_slip25) = {
            let w = self.wallet.lock().await;
            let paths: HashMap<ScriptBuf, String> = w.km.keys.iter().map(|k| (k.script.clone(), k.path.clone())).collect();
            (
                w.km.i64_field("CoinJoinVendor", 0),
                w.km.master_fingerprint(),
                w.km.network(),
                w.km.taproot_account_path().unwrap_or("").to_string(),
                w.km.i64_field("CoinJoinDeviceMaxRounds", 50) as u64,
                w.km.f64_field("CoinJoinDeviceMaxMiningFeeRate", 5.0),
                paths,
                w.km.has_slip25_account(),
            )
        };
        if vendor == 2 {
            return self.coldcard_key_chain().await;
        }
        if vendor != 1 {
            return Err(format!("DeviceAuthorizationFailed: only Trezor and Coldcard are implemented for device-signed coinjoins (CoinJoinVendor={vendor})."));
        }
        if !has_slip25 {
            return Err("DeviceAuthorizationFailed: this wallet has no SLIP-25 coinjoin account; import it with coinjoin enabled in Wasabi first.".into());
        }
        let existing = self.trezor.lock().await.clone();
        let kc = match existing {
            Some(kc) if kc.device.is_session_alive().await => kc,
            _ => {
                tracing::info!("{}: looking for the Trezor ({fingerprint}) on the bridge", self.wallet_name);
                let device = hw::TrezorDevice::find(Some(&fingerprint)).await.map_err(|e| format!("DeviceNotFound: {e}"))?;
                Arc::new(hw::TrezorKeyChain::new(Arc::new(device), network, paths.clone()))
            }
        };
        kc.set_paths(paths);
        if kc.needs_authorization() {
            tracing::info!("{}: confirm the coinjoin authorization on the Trezor ({max_rounds} rounds, {max_fee} sat/vB)", self.wallet_name);
            let fee = coinjoin::FeeRate::from_sat_per_vb(max_fee);
            tokio::time::timeout(std::time::Duration::from_secs(300), kc.authorize(&self.daemon.cfg.coordinator_identifier, max_rounds, fee, &account))
                .await
                .map_err(|_| "DeviceAuthorizationFailed: the device did not confirm within 5 minutes.".to_string())?
                .map_err(|e| format!("DeviceAuthorizationFailed: {e}"))?;
        }
        *self.trezor.lock().await = Some(kc.clone());
        Ok(kc)
    }

    /// Coldcard (Preview 8 shape): the device runs an HSM policy composed from the wallet's limits; the
    /// user approves it on the device once per boot, then proofs and signatures come unattended.
    async fn coldcard_key_chain(self: &Arc<Self>) -> Result<Arc<dyn KeyChain>, String> {
        if let Some(kc) = self.coldcard.lock().await.clone() {
            if !kc.needs_authorization() {
                return Ok(kc);
            }
        }
        let (fingerprint, keys, policy, approved_hash, max_rounds, max_fee, min_inputs) = {
            let w = self.wallet.lock().await;
            let keys: HashMap<ScriptBuf, hw::ColdcardKeyInfo> = w.km.keys.iter().filter(|k| k.kind != AccountKind::Other).map(|k| (k.script.clone(), hw::ColdcardKeyInfo { path: k.path.clone(), pubkey: k.pubkey.inner })).collect();
            let mut accounts = vec![w.km.segwit_account_path().to_string()];
            if let (Some(_), Some(p)) = (w.km.taproot_xpub(), w.km.taproot_account_path()) {
                accounts.push(p.to_string());
            }
            let max_fee = w.km.f64_field("CoinJoinDeviceMaxMiningFeeRate", 5.0);
            let min_inputs = w.km.i64_field("ColdcardMinInputs", 21);
            let limits = hw::coldcard::policy::Limits {
                max_sats_leaving: w.km.i64_field("ColdcardMaxSatsLeaving", 100_000),
                max_transactions: w.km.i64_field("CoinJoinDeviceMaxRounds", 50),
                max_transactions_per_period: w.km.i64_field("ColdcardMaxTransactionsPerPeriod", 6),
                period_minutes: w.km.i64_field("ColdcardPeriodMinutes", 60),
                min_inputs: (min_inputs > 0).then_some(min_inputs),
                max_fee_per_kvbyte: hw::coldcard::policy::fee_rate_to_per_kvbyte(max_fee),
            };
            (
                w.km.master_fingerprint(),
                keys,
                hw::coldcard::policy::compose(&accounts, &limits),
                w.km.str_field("ColdcardActivePolicyHash").filter(|s| !s.is_empty()).map(str::to_string),
                w.km.i64_field("CoinJoinDeviceMaxRounds", 50) as usize,
                max_fee,
                min_inputs as i32,
            )
        };
        let name = self.wallet_name.clone();
        let policy_for_log = policy.clone();
        let policy_fingerprint = hw::coldcard::policy::fingerprint(&policy);
        let fp = fingerprint.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<(Arc<hw::ColdcardDevice>, Option<String>), String> {
            let device = hw::ColdcardDevice::open().map_err(|e| format!("DeviceNotFound: {e}"))?;
            if !device.master_fingerprint.eq_ignore_ascii_case(&fp) {
                return Err(format!("DeviceNotFound: the connected Coldcard ({}) is not this wallet's ({fp}).", device.master_fingerprint));
            }
            let version = device.version().map_err(|e| format!("DeviceNotFound: {e}"))?;
            tracing::info!("{name}: Coldcard firmware: {}", version.replace('\n', " "));
            hw::coldcard::policy::ensure_firmware_supports_policy(&version).map_err(|e| format!("DeviceAuthorizationFailed: {e}"))?;
            tracing::info!("{name}: installing the coinjoin HSM policy; approve it on the Coldcard if it asks. Policy: {policy_for_log}");
            let active = device.start_hsm(&policy, approved_hash.as_deref()).map_err(|e| {
                if e.0.contains("Unknown item") {
                    "DeviceAuthorizationFailed: This Coldcard's firmware does not understand the coinjoin policy. Install the coinjoin-fw-2 build.".to_string()
                } else {
                    format!("DeviceAuthorizationFailed: {e}")
                }
            })?;
            Ok((Arc::new(device), active))
        })
        .await
        .map_err(|e| e.to_string())??;
        let (device, active_hash) = result;
        if let Some(h) = &active_hash {
            let mut w = self.wallet.lock().await;
            if w.km.str_field("ColdcardActivePolicyHash") != Some(h.as_str()) {
                w.km.set_field("ColdcardActivePolicyHash", serde_json::json!(h));
                w.km.set_field("ColdcardApprovedPolicyFingerprint", serde_json::json!(policy_fingerprint));
                w.km.save().ok();
            }
        }
        let kc = Arc::new(hw::ColdcardKeyChain::new(device, &fingerprint, keys, max_rounds, coinjoin::FeeRate::from_sat_per_vb(max_fee), min_inputs).map_err(|e| e.to_string())?);
        *self.coldcard.lock().await = Some(kc.clone());
        Ok(kc)
    }

    async fn run_loop(self: Arc<Self>, key_chain: Arc<dyn KeyChain>, cancel: CancellationToken) {
        let mut first = true;
        while !cancel.is_cancelled() {
            if !first {
                self.set_state(CoinJoinClientState::InSchedule);
                let wait = std::time::Duration::from_secs(30 + rand::random::<u64>() % 60);
                tokio::select! { _ = tokio::time::sleep(wait) => {}, _ = cancel.cancelled() => break }
                self.set_state(CoinJoinClientState::InProgress);
            }
            first = false;
            let key_chain = if key_chain.needs_authorization() {
                match self.device_key_chain().await {
                    Ok(kc) => kc,
                    Err(e) => {
                        *self.last_error.lock().unwrap() = Some(e.clone());
                        tracing::warn!("{}: {e}", self.wallet_name);
                        break;
                    }
                }
            } else {
                key_chain.clone()
            };
            match self.run_once(key_chain, cancel.child_token()).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    *self.last_error.lock().unwrap() = Some(e.clone());
                    tracing::warn!("{}: coinjoin: {e}", self.wallet_name);
                    if cancel.is_cancelled() || !*self.stop_when_all_mixed.lock().unwrap() {
                        // keep trying (auto mode) unless cancelled
                    }
                    if cancel.is_cancelled() {
                        break;
                    }
                    if e.contains("CoordinatorLiedAboutInputs") || e.contains("Invalid passphrase") || e.contains("DeviceNotFound") || e.contains("DeviceAuthorizationFailed") || e.contains("device:") {
                        break;
                    }
                }
            }
        }
        *self.in_critical.lock().unwrap() = false;
        self.set_state(CoinJoinClientState::Idle);
        *self.cancel.lock().unwrap() = None;
    }

    /// One round attempt. `Ok(true)` = keep going, `Ok(false)` = done (all mixed, stop requested).
    async fn run_once(self: &Arc<Self>, key_chain: Arc<dyn KeyChain>, cancel: CancellationToken) -> Result<bool, String> {
        let d = &self.daemon;
        let (anon_target, non_private_isolation, only_private_payments, pleb_stop) = {
            let w = self.wallet.lock().await;
            (
                w.km.i64_field("AnonScoreTarget", 10) as i32,
                w.km.bool_field("RedCoinIsolation", false),
                w.km.bool_field("OnlyUsePrivateFundsForPayments", false),
                w.km.str_field("PlebStopThreshold").and_then(|s| s.parse::<f64>().ok()).map(|b| (b * 1e8) as i64).unwrap_or(PLEB_STOP_DEFAULT_SATS),
            )
        };
        let (candidates, reasons) = {
            let w = self.wallet.lock().await;
            candidate_coins(&w, &self.prison)
        };
        if candidates.is_empty() {
            let reason = reasons.first().copied().unwrap_or(CoinjoinError::NoCoinsEligibleToMix);
            return Err(format!("{reason:?}: No candidate coins available for coinjoin."));
        }
        let total: i64 = candidates.iter().map(|c| c.amount).sum();
        if total < pleb_stop && !*self.override_pleb_stop.lock().unwrap() {
            return Err(format!("NotEnoughUnprivateBalance: the balance {} sat is under the pleb stop threshold {} sat.", total, pleb_stop));
        }
        if candidates.iter().all(|c| c.is_private(anon_target)) {
            if *self.stop_when_all_mixed.lock().unwrap() {
                tracing::info!("{}: all coins are private, stopping.", self.wallet_name);
                return Ok(false);
            }
            return Err("AllCoinsPrivate".into());
        }
        let proxy = d.socks.clone().map(|socks5| ProxyConfig { socks5 });
        let coordinator = d.cfg.coordinator_uri.clone();
        let make_client: coinjoin::client::ClientFactory = Arc::new(move |identity: &str| CoordinatorClient::new(&coordinator, proxy.as_ref(), identity));
        let (tx, mut rx) = mpsc::unbounded_channel::<Progress>();
        let client = CoinJoinClient {
            make_client,
            key_chain: key_chain.clone(),
            destinations: Arc::new(WalletDestinations { wallet: self.wallet.clone() }),
            updater: self.updater.clone(),
            selector: CoinJoinCoinSelector::new(false, anon_target, non_private_isolation, false),
            config: CoinJoinConfig {
                coordinator_identifier: d.cfg.coordinator_identifier.clone(),
                max_mining_fee_rate_sat_vb: key_chain.max_mining_fee_rate().map(|f| f.sat_per_vb()).unwrap_or(d.cfg.max_coin_join_mining_fee_rate).min(d.cfg.max_coin_join_mining_fee_rate),
                absolute_min_input_count: d.cfg.absolute_min_input_count,
                allow_solo_coinjoining: false,
            },
            liquidity_clue: self.liquidity_clue.clone(),
            input_verifier: d.bitcoind.clone().map(|node| {
                let f: coinjoin::client::InputVerifier = Arc::new(move |coins: Vec<coinjoin::client::ForeignCoin>| {
                    let node = node.clone();
                    Box::pin(async move {
                        // Wasabi `InputVerifiers.CreateRpcVerifier`: check a random 10% sample (at least one).
                        if coins.is_empty() {
                            return Ok(());
                        }
                        let mut sample = coins.clone();
                        {
                            use rand::seq::SliceRandom;
                            sample.shuffle(&mut rand::thread_rng());
                        }
                        let n = ((coins.len() as f64) * 0.10).floor().max(1.0) as usize;
                        sample.truncate(n);
                        let outpoints: Vec<bitcoin::OutPoint> = sample.iter().map(|c| c.outpoint).collect();
                        let found = node.get_tx_outs(&outpoints).await.map_err(|e| format!("gettxout failed: {e}"))?;
                        for (c, spk) in sample.iter().zip(found) {
                            match spk {
                                None => return Err(format!("UTXO {} does not exist or is already spent. The coordinator may be malicious.", c.outpoint)),
                                Some(s) if s != c.script => return Err(format!("ScriptPubKey mismatch for {}. The coordinator may be malicious.", c.outpoint)),
                                _ => {}
                            }
                        }
                        Ok(())
                    })
                });
                f
            }),
            do_not_register_in_last_minute: std::time::Duration::from_secs(60),
            min_anon_score_for_payments: if only_private_payments { anon_target } else { 0 },
            progress: tx,
            coins_in_critical_phase: Mutex::new(Vec::new()),
            coins_banned: Mutex::new(HashSet::new()),
        };
        let me = self.clone();
        let progress_task = tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                match &p {
                    Progress::EnteringCriticalPhase => {
                        *me.in_critical.lock().unwrap() = true;
                        me.set_state(CoinJoinClientState::InCriticalPhase);
                    }
                    Progress::LeavingCriticalPhase => {
                        *me.in_critical.lock().unwrap() = false;
                        me.set_state(CoinJoinClientState::InProgress);
                    }
                    Progress::CoinBanned { outpoint, until } => me.prison.ban(*outpoint, *until),
                    _ => {}
                }
                tracing::info!("{}: {:?}", me.wallet_name, p);
            }
        });
        let candidates_fn = {
            let wallet = self.wallet.clone();
            let prison = self.prison.clone();
            move || {
                tokio::task::block_in_place(|| {
                    let w = tokio::runtime::Handle::current().block_on(wallet.lock());
                    candidate_coins(&w, &prison).0
                })
            }
        };
        let result = client.start_coin_join(candidates_fn, cancel.clone()).await;
        drop(client);
        progress_task.abort();
        match result {
            Ok(CoinJoinResult::Success { coins, output_scripts, unsigned_tx, costs }) => {
                tracing::info!("{}: coinjoin finished, transaction {} was broadcast (mining fee {} sat, dust {} sat)", self.wallet_name, unsigned_tx.compute_txid(), costs.mining_fee, costs.wasted_dust);
                let mut w = self.wallet.lock().await;
                for s in &output_scripts {
                    if let Some(k) = w.km.key_for_script_mut(s) {
                        k.state = KeyState::Used;
                    }
                }
                let _ = coins;
                let now = chrono::Utc::now().timestamp();
                if let Err(e) = w.store.insert_tx(&unsigned_tx, wallet::store::MEMPOOL_HEIGHT, &bitcoin::BlockHash::all_zeros(), 0, now) {
                    tracing::warn!("storing coinjoin tx: {e}");
                }
                w.rebuild_state().map_err(|e| e.to_string())?;
                Ok(true)
            }
            Ok(CoinJoinResult::Failed) => {
                tracing::info!("{}: coinjoin round failed, will retry.", self.wallet_name);
                Ok(true)
            }
            Err(CjError::Cancelled) => {
                // The user's stop cancels the parent token; a round timeout only cancels a child.
                Ok(!cancel.is_cancelled() && self.cancel.lock().unwrap().as_ref().map(|c| !c.is_cancelled()).unwrap_or(false))
            }
            Err(CjError::UnknownRoundEnding { coins, output_scripts, msg }) => {
                tracing::warn!("{}: round ending unknown: {msg}", self.wallet_name);
                let mut w = self.wallet.lock().await;
                for s in &output_scripts {
                    if let Some(k) = w.km.key_for_script_mut(s) {
                        k.state = KeyState::Used;
                    }
                }
                let _ = coins;
                w.km.save().ok();
                Ok(true)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

use bitcoin::hashes::Hash;
