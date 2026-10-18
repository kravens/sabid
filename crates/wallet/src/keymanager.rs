//! Wasabi `Wallets/<name>.json` (`KeyManager`). The file is kept as a JSON object so fields sabid
//! does not understand survive a rewrite; `HdPubKeys` is the only array rebuilt from typed state.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::key::{CompressedPublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::All;
use bitcoin::{Address, Network, OutPoint, PublicKey, ScriptBuf};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Clean = 0,
    Locked = 1,
    Used = 2,
}

impl KeyState {
    fn from_i64(n: i64) -> KeyState {
        match n {
            1 => KeyState::Locked,
            2 => KeyState::Used,
            _ => KeyState::Clean,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    /// m/84'
    Segwit,
    /// m/86'
    Taproot,
    /// m/10025' (coinjoin account of a hardware wallet, taproot)
    Slip25,
    /// e.g. silent payment keys (m/352'), kept in the file, never used by sabid
    Other,
}

impl AccountKind {
    pub fn is_taproot(self) -> bool {
        matches!(self, AccountKind::Taproot | AccountKind::Slip25)
    }
}

#[derive(Debug, Clone)]
pub struct HdKey {
    pub pubkey: PublicKey,
    /// Wasabi `FullKeyPath.ToString()`, e.g. `84'/0'/0'/1/7`
    pub path: String,
    pub label: String,
    pub state: KeyState,
    pub script: ScriptBuf,
    pub kind: AccountKind,
    pub is_internal: bool,
    pub index: u32,
    /// Extra JSON fields of the entry (`TweakData` for silent payment keys), written back as is.
    extra: Map<String, Value>,
}

impl HdKey {
    pub fn address(&self, network: Network) -> Option<Address> {
        Address::from_script(&self.script, network).ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletFileError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wallet file: {0}")]
    Invalid(String),
}

pub struct KeyManager {
    pub path: PathBuf,
    raw: Map<String, Value>,
    pub keys: Vec<HdKey>,
    secp: Secp256k1<All>,
    network: Network,
    segwit_xpub: Xpub,
    taproot_xpub: Option<Xpub>,
    segwit_account: String,
    taproot_account: Option<String>,
    /// script -> position in `keys`, extended wherever keys are appended (`load`, `ensure_gap`).
    index: HashMap<ScriptBuf, usize>,
}

fn kind_of_path(path: &str) -> AccountKind {
    match path.split('/').next() {
        Some("84'") => AccountKind::Segwit,
        Some("86'") => AccountKind::Taproot,
        Some("10025'") => AccountKind::Slip25,
        _ => AccountKind::Other,
    }
}

pub fn script_for(secp: &Secp256k1<All>, pubkey: &PublicKey, kind: AccountKind) -> ScriptBuf {
    if kind.is_taproot() {
        let xonly = XOnlyPublicKey::from(pubkey.inner);
        ScriptBuf::new_p2tr(secp, xonly, None)
    } else {
        let c = CompressedPublicKey(pubkey.inner);
        ScriptBuf::new_p2wpkh(&c.wpubkey_hash())
    }
}

impl KeyManager {
    pub fn load(path: &Path) -> Result<Self, WalletFileError> {
        let bytes = std::fs::read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        let text = text.trim_start_matches('\u{feff}');
        let raw: Map<String, Value> = serde_json::from_str(text)?;
        let network = match raw.get("BlockchainState").and_then(|b| b.get("Network")).and_then(Value::as_str).unwrap_or("Main") {
            "Main" => Network::Bitcoin,
            "TestNet" | "TestNet4" => Network::Testnet,
            "RegTest" => Network::Regtest,
            "Signet" => Network::Signet,
            other => return Err(WalletFileError::Invalid(format!("unknown network {other}"))),
        };
        let xpub = |k: &str| -> Result<Option<Xpub>, WalletFileError> {
            match raw.get(k).and_then(Value::as_str) {
                Some(s) => s.parse::<Xpub>().map(Some).map_err(|e| WalletFileError::Invalid(format!("{k}: {e}"))),
                None => Ok(None),
            }
        };
        let segwit_xpub = xpub("ExtPubKey")?.ok_or_else(|| WalletFileError::Invalid("ExtPubKey missing".into()))?;
        let taproot_xpub = xpub("TaprootExtPubKey")?;
        let segwit_account = raw.get("AccountKeyPath").and_then(Value::as_str).unwrap_or("84'/0'/0'").to_string();
        let taproot_account = raw.get("TaprootAccountKeyPath").and_then(Value::as_str).map(str::to_string);
        let secp = Secp256k1::new();
        let mut keys = Vec::new();
        for entry in raw.get("HdPubKeys").and_then(Value::as_array).cloned().unwrap_or_default() {
            let obj = entry.as_object().ok_or_else(|| WalletFileError::Invalid("HdPubKeys entry".into()))?;
            let pk_hex = obj.get("PubKey").and_then(Value::as_str).unwrap_or("");
            let pubkey = pk_hex.parse::<PublicKey>().map_err(|e| WalletFileError::Invalid(format!("PubKey {pk_hex}: {e}")))?;
            let path = obj.get("FullKeyPath").and_then(Value::as_str).unwrap_or("").to_string();
            let kind = kind_of_path(&path);
            let parts: Vec<&str> = path.split('/').collect();
            let (is_internal, index) = if parts.len() >= 2 {
                (parts[parts.len() - 2] == "1", parts[parts.len() - 1].parse().unwrap_or(0))
            } else {
                (false, 0)
            };
            let mut extra = obj.clone();
            for k in ["PubKey", "FullKeyPath", "Label", "KeyState"] {
                extra.remove(k);
            }
            keys.push(HdKey {
                script: script_for(&secp, &pubkey, kind),
                pubkey,
                path,
                label: obj.get("Label").and_then(Value::as_str).unwrap_or("").to_string(),
                state: KeyState::from_i64(obj.get("KeyState").and_then(Value::as_i64).unwrap_or(0)),
                kind,
                is_internal,
                index,
                extra,
            });
        }
        let index = keys.iter().enumerate().map(|(i, k)| (k.script.clone(), i)).collect();
        Ok(Self { path: path.to_path_buf(), raw, keys, secp, network, segwit_xpub, taproot_xpub, segwit_account, taproot_account, index })
    }

    pub fn wallet_name(&self) -> String {
        self.path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn raw(&self) -> &Map<String, Value> {
        &self.raw
    }

    pub fn str_field(&self, k: &str) -> Option<&str> {
        self.raw.get(k).and_then(Value::as_str)
    }

    pub fn i64_field(&self, k: &str, default: i64) -> i64 {
        self.raw.get(k).and_then(Value::as_i64).unwrap_or(default)
    }

    pub fn f64_field(&self, k: &str, default: f64) -> f64 {
        self.raw.get(k).and_then(Value::as_f64).unwrap_or(default)
    }

    pub fn bool_field(&self, k: &str, default: bool) -> bool {
        self.raw.get(k).and_then(Value::as_bool).unwrap_or(default)
    }

    pub fn set_field(&mut self, k: &str, v: Value) {
        self.raw.insert(k.to_string(), v);
    }

    pub fn master_fingerprint(&self) -> String {
        self.str_field("MasterFingerprint").unwrap_or("").to_string()
    }

    pub fn is_watch_only(&self) -> bool {
        self.raw.get("EncryptedSecret").map(Value::is_null).unwrap_or(true)
    }

    pub fn is_hardware_wallet(&self) -> bool {
        self.is_watch_only() && !self.master_fingerprint().is_empty()
    }

    pub fn encrypted_secret(&self) -> Option<&str> {
        self.str_field("EncryptedSecret")
    }

    pub fn chain_code(&self) -> Option<&str> {
        self.str_field("ChainCode")
    }

    pub fn min_gap_limit(&self) -> u32 {
        self.i64_field("MinGapLimit", 200) as u32
    }

    pub fn segwit_xpub(&self) -> &Xpub {
        &self.segwit_xpub
    }

    pub fn taproot_xpub(&self) -> Option<&Xpub> {
        self.taproot_xpub.as_ref()
    }

    pub fn segwit_account_path(&self) -> &str {
        &self.segwit_account
    }

    pub fn taproot_account_path(&self) -> Option<&str> {
        self.taproot_account.as_deref()
    }

    pub fn has_slip25_account(&self) -> bool {
        self.taproot_account.as_deref().map(|p| p.starts_with("10025'")).unwrap_or(false)
    }

    pub fn birth_height(&self) -> Option<u32> {
        self.raw.get("BlockchainState").and_then(|b| b.get("BirthHeight")).and_then(Value::as_u64).map(|h| h as u32)
    }

    pub fn file_height(&self) -> Option<u32> {
        self.raw.get("BlockchainState").and_then(|b| b.get("Height")).and_then(Value::as_str).and_then(|s| s.parse().ok())
    }

    pub fn set_file_height(&mut self, height: u32) {
        if let Some(Value::Object(bs)) = self.raw.get_mut("BlockchainState") {
            bs.insert("Height".into(), Value::String(height.to_string()));
        }
    }

    pub fn excluded_coins(&self) -> Vec<OutPoint> {
        self.raw
            .get("ExcludedCoinsFromCoinJoin")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str()).filter_map(wasabi_proto::script::outpoint_from_hex).collect())
            .unwrap_or_default()
    }

    pub fn set_excluded(&mut self, outpoint: OutPoint, exclude: bool) {
        let mut list = self.excluded_coins();
        list.retain(|o| *o != outpoint);
        if exclude {
            list.push(outpoint);
        }
        let arr: Vec<Value> = list.iter().map(|o| Value::String(wasabi_proto::script::outpoint_to_hex(o))).collect();
        self.raw.insert("ExcludedCoinsFromCoinJoin".into(), Value::Array(arr));
    }

    pub fn position_of(&self, script: &ScriptBuf) -> Option<usize> {
        if self.index.len() == self.keys.len() {
            self.index.get(script).copied()
        } else {
            // Keys appended without the index: still correct, just the old linear scan.
            self.keys.iter().position(|k| &k.script == script)
        }
    }

    pub fn key_for_script(&self, script: &ScriptBuf) -> Option<&HdKey> {
        self.position_of(script).map(|i| &self.keys[i])
    }

    pub fn key_for_script_mut(&mut self, script: &ScriptBuf) -> Option<&mut HdKey> {
        self.position_of(script).map(move |i| &mut self.keys[i])
    }

    /// Scripts sabid scans for: every loud key (segwit, taproot, SLIP-25).
    pub fn scripts(&self) -> Vec<ScriptBuf> {
        self.keys.iter().filter(|k| k.kind != AccountKind::Other).map(|k| k.script.clone()).collect()
    }

    fn account_of(&self, kind: AccountKind) -> Option<(&Xpub, &str)> {
        match kind {
            AccountKind::Segwit => Some((&self.segwit_xpub, &self.segwit_account)),
            AccountKind::Taproot | AccountKind::Slip25 => Some((self.taproot_xpub.as_ref()?, self.taproot_account.as_deref()?)),
            AccountKind::Other => None,
        }
    }

    pub fn taproot_kind(&self) -> Option<AccountKind> {
        self.taproot_account.as_deref().map(|p| if p.starts_with("10025'") { AccountKind::Slip25 } else { AccountKind::Taproot })
    }

    fn derive_key(&self, kind: AccountKind, internal: bool, index: u32) -> Option<HdKey> {
        let (xpub, account) = self.account_of(kind)?;
        let path = DerivationPath::from(vec![ChildNumber::from_normal_idx(internal as u32).ok()?, ChildNumber::from_normal_idx(index).ok()?]);
        let child = xpub.derive_pub(&self.secp, &path).ok()?;
        let pubkey = PublicKey::new(child.public_key);
        Some(HdKey {
            script: script_for(&self.secp, &pubkey, kind),
            pubkey,
            path: format!("{account}/{}/{index}", internal as u32),
            label: String::new(),
            state: KeyState::Clean,
            kind,
            is_internal: internal,
            index,
            extra: Map::new(),
        })
    }

    /// Keeps `MinGapLimit` clean keys after the last non-clean key of every branch
    /// (Wasabi `AssertCleanKeysIndexed`). Returns true when keys were added.
    pub fn ensure_gap(&mut self) -> bool {
        let gap = self.min_gap_limit();
        let mut branches = vec![(AccountKind::Segwit, false), (AccountKind::Segwit, true)];
        if let Some(k) = self.taproot_kind() {
            branches.push((k, false));
            branches.push((k, true));
        }
        let mut changed = false;
        for (kind, internal) in branches {
            loop {
                let branch: Vec<&HdKey> = self.keys.iter().filter(|k| k.kind == kind && k.is_internal == internal).collect();
                let last_nonclean = branch.iter().filter(|k| k.state != KeyState::Clean).map(|k| k.index as i64).max().unwrap_or(-1);
                let clean_after = branch.iter().filter(|k| k.state == KeyState::Clean && k.index as i64 > last_nonclean).count() as u32;
                if clean_after >= gap {
                    break;
                }
                let next = branch.iter().map(|k| k.index + 1).max().unwrap_or(0);
                let missing = gap - clean_after;
                let mut new_keys = Vec::with_capacity(missing as usize);
                for i in next..next + missing {
                    match self.derive_key(kind, internal, i) {
                        Some(k) => new_keys.push(k),
                        None => break,
                    }
                }
                if new_keys.is_empty() {
                    break;
                }
                for k in new_keys {
                    self.index.insert(k.script.clone(), self.keys.len());
                    self.keys.push(k);
                }
                changed = true;
            }
        }
        changed
    }

    /// Wasabi `GetNextReceiveKey`: first clean, unlabeled external key of the branch; labels it and locks it.
    pub fn next_receive_key(&mut self, label: &str, taproot: bool) -> Option<usize> {
        let kind = if taproot { self.taproot_kind()? } else { AccountKind::Segwit };
        self.ensure_gap();
        let idx = self
            .keys
            .iter()
            .position(|k| k.kind == kind && !k.is_internal && k.state == KeyState::Clean && k.label.is_empty())?;
        let k = &mut self.keys[idx];
        k.label = label.to_string();
        k.state = KeyState::Locked;
        self.ensure_gap();
        Some(idx)
    }

    /// Wasabi `GetNextChangeKey`: first clean internal key (SLIP-25 for a coinjoin account wallet).
    pub fn next_change_key(&mut self, coinjoin_account: bool) -> Option<usize> {
        self.ensure_gap();
        let slip25 = self.has_slip25_account();
        self.keys.iter().position(|k| {
            k.state == KeyState::Clean
                && k.is_internal
                && k.kind != AccountKind::Other
                && if coinjoin_account { k.kind == AccountKind::Slip25 } else { !(slip25 && k.kind == AccountKind::Slip25) }
        })
    }

    pub fn save(&self) -> Result<(), WalletFileError> {
        let mut raw = self.raw.clone();
        let keys: Vec<Value> = self
            .keys
            .iter()
            .map(|k| {
                let mut o = Map::new();
                o.insert("PubKey".into(), json!(k.pubkey.to_string()));
                o.insert("FullKeyPath".into(), json!(k.path));
                o.insert("Label".into(), json!(k.label));
                o.insert("KeyState".into(), json!(k.state as i64));
                for (ek, ev) in &k.extra {
                    o.insert(ek.clone(), ev.clone());
                }
                Value::Object(o)
            })
            .collect();
        raw.insert("HdPubKeys".into(), Value::Array(keys));
        let text = serde_json::to_string_pretty(&Value::Object(raw))?;
        let tmp = self.path.with_extension("json.sabid-tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_match_known_vectors() {
        // BIP84 test vector: m/84'/0'/0'/0/0 -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
        let secp = Secp256k1::new();
        let pk: PublicKey = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c".parse().unwrap();
        let s = script_for(&secp, &pk, AccountKind::Segwit);
        assert_eq!(Address::from_script(&s, Network::Bitcoin).unwrap().to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        // BIP86 test vector: m/86'/0'/0'/0/0 -> bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
        let pk: PublicKey = "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115".parse().unwrap();
        let s = script_for(&secp, &pk, AccountKind::Taproot);
        assert_eq!(Address::from_script(&s, Network::Bitcoin).unwrap().to_string(), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    }
}
