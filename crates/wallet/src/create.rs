//! A Wasabi-format wallet file from a BIP 39 mnemonic (`KeyManager.CreateNew` / `Recover`):
//! the password is both the BIP 39 passphrase and the BIP 38 key for the stored master secret.

use crate::keymanager::KeyManager;
use base64::Engine;
use bip38::Encrypt;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use serde_json::{json, Map, Value};
use std::path::Path;
use zeroize::Zeroize;

/// Wasabi's `AbsoluteMinGapLimit`.
pub const MIN_GAP_LIMIT: u32 = 21;

fn network_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "Main",
        Network::Testnet => "TestNet",
        Network::Regtest => "RegTest",
        _ => "Signet",
    }
}

/// Account key paths as Wasabi writes them (`84'/0'/0'`, `86'/0'/0'`, SLIP-25 `10025'/0'/0'/1'`).
pub fn account_path(purpose: u32, network: Network) -> String {
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    if purpose == 10025 {
        format!("10025'/{coin}'/0'/1'")
    } else {
        format!("{purpose}'/{coin}'/0'")
    }
}

/// Wasabi's field order and defaults; secrets, xpubs and vendor fields are filled by the callers.
fn defaults(network: Network, birth_height: u32, segwit_path: &str) -> Map<String, Value> {
    json!({
        "EncryptedSecret": null,
        "ChainCode": null,
        "MasterFingerprint": null,
        "ExtPubKey": null,
        "TaprootExtPubKey": null,
        "SilentPaymentScanExtPubKey": null,
        "SilentPaymentSpendExtPubKey": null,
        "MinGapLimit": MIN_GAP_LIMIT,
        "AccountKeyPath": segwit_path,
        "TaprootAccountKeyPath": null,
        "BlockchainState": {"Network": network_name(network), "Height": birth_height.to_string(), "BirthHeight": birth_height},
        "PreferPsbtWorkflow": false,
        "AutoCoinJoin": false,
        "PlebStopThreshold": "0.005",
        "Icon": null,
        "AnonScoreTarget": 10,
        "CoinJoinDeviceMaxRounds": 50,
        "CoinJoinDeviceMaxMiningFeeRate": 5,
        "ColdcardMaxSatsLeaving": 100000,
        "ColdcardMaxTransactionsPerPeriod": 6,
        "ColdcardPeriodMinutes": 60,
        "ColdcardMinInputs": 21,
        "ColdcardActivePolicyHash": "",
        "ColdcardApprovedPolicyFingerprint": "",
        "CoinJoinVendor": 0,
        "CoinJoinDisabled": false,
        "RedCoinIsolation": false,
        "DefaultReceiveScriptType": "Taproot",
        "ChangeScriptPubKeyType": "Random",
        "DefaultSendWorkflow": "Automatic",
        "ExcludedCoinsFromCoinJoin": [],
        "HdPubKeys": [],
    })
    .as_object()
    .cloned()
    .expect("object")
}

/// A soft wallet's JSON, with no keys yet (`ensure_gap` fills them).
pub fn wallet_json(mnemonic: &bip39::Mnemonic, password: &str, network: Network, birth_height: u32) -> anyhow::Result<Map<String, Value>> {
    let secp = Secp256k1::new();
    let mut seed = mnemonic.to_seed(password);
    let master = Xpriv::new_master(network, &seed)?;
    seed.zeroize();
    let mut secret = master.private_key.secret_bytes();
    let encrypted = secret.encrypt(password, true).map_err(|e| anyhow::anyhow!("BIP 38: {e:?}"))?;
    secret.zeroize();
    let segwit_path = account_path(84, network);
    let taproot_path = account_path(86, network);
    let account_xpub = |p: &str| -> anyhow::Result<String> {
        let path: DerivationPath = format!("m/{p}").parse()?;
        Ok(Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?).to_string())
    };
    let mut m = defaults(network, birth_height, &segwit_path);
    m.insert("EncryptedSecret".into(), json!(encrypted));
    m.insert("ChainCode".into(), json!(base64::engine::general_purpose::STANDARD.encode(master.chain_code.as_bytes())));
    m.insert("MasterFingerprint".into(), json!(hex::encode(master.fingerprint(&secp).to_bytes())));
    m.insert("ExtPubKey".into(), json!(account_xpub(&segwit_path)?));
    m.insert("TaprootExtPubKey".into(), json!(account_xpub(&taproot_path)?));
    m.insert("TaprootAccountKeyPath".into(), json!(taproot_path));
    Ok(m)
}

/// A hardware wallet's watch-only JSON (`KeyManager.CreateNewHardwareWalletWatchOnly`): segwit account
/// always, a taproot or SLIP-25 account when the device gave one, `vendor` 1 = Trezor, 2 = Coldcard.
pub fn watch_only_json(network: Network, birth_height: u32, fingerprint_hex: &str, segwit_xpub: &str, taproot: Option<(&str, &str)>, icon: &str, vendor: i64) -> Map<String, Value> {
    let mut m = defaults(network, birth_height, &account_path(84, network));
    m.insert("MasterFingerprint".into(), json!(fingerprint_hex));
    m.insert("ExtPubKey".into(), json!(segwit_xpub));
    if let Some((path, xpub)) = taproot {
        m.insert("TaprootAccountKeyPath".into(), json!(path));
        m.insert("TaprootExtPubKey".into(), json!(xpub));
    } else {
        // Nothing to hand out from a taproot account the device has not given.
        m.insert("DefaultReceiveScriptType".into(), json!("Segwit"));
    }
    m.insert("Icon".into(), json!(icon));
    m.insert("CoinJoinVendor".into(), json!(vendor));
    m
}

/// Writes a new wallet file (refusing to overwrite) and derives its first keys.
pub fn write_json(path: &Path, map: Map<String, Value>) -> anyhow::Result<KeyManager> {
    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&Value::Object(map))?)?;
    let mut km = KeyManager::load(path)?;
    km.ensure_gap();
    km.save()?;
    Ok(km)
}

pub fn write_wallet(path: &Path, mnemonic: &bip39::Mnemonic, password: &str, network: Network, birth_height: u32) -> anyhow::Result<KeyManager> {
    write_json(path, wallet_json(mnemonic, password, network, birth_height)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip38::Decrypt;

    #[test]
    fn matches_the_bip84_test_vector_and_round_trips_the_secret() {
        let m = bip39::Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let dir = std::env::temp_dir().join(format!("sabid-create-{}", std::process::id()));
        let path = dir.join("Vector.json");
        let km = write_wallet(&path, &m, "", Network::Bitcoin, 800_000).unwrap();
        assert_eq!(km.master_fingerprint(), "73c5da0a");
        assert_eq!(km.segwit_xpub().to_string(), "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V");
        let first = km.keys.iter().find(|k| k.path == "84'/0'/0'/0/0").expect("first receive key");
        assert_eq!(bitcoin::Address::from_script(&first.script, Network::Bitcoin).unwrap().to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        let (key, compressed) = km.encrypted_secret().unwrap().decrypt("").unwrap();
        assert!(compressed);
        let master = Xpriv::new_master(Network::Bitcoin, &m.to_seed("")).unwrap();
        assert_eq!(key, master.private_key.secret_bytes());
        assert!(write_wallet(&path, &m, "", Network::Bitcoin, 1).is_err(), "never overwrite");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn watch_only_file_loads_as_a_hardware_wallet() {
        let dir = std::env::temp_dir().join(format!("sabid-hw-{}", std::process::id()));
        let segwit = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
        let km = write_json(&dir.join("Hw.json"), watch_only_json(Network::Bitcoin, 800_000, "73c5da0a", segwit, None, "Coldcard", 2)).unwrap();
        assert!(km.is_hardware_wallet() && km.is_watch_only());
        assert_eq!(km.i64_field("CoinJoinVendor", 0), 2);
        assert!(km.taproot_xpub().is_none());
        assert_eq!(km.keys.len() as u32, 2 * MIN_GAP_LIMIT);
        assert_eq!(account_path(10025, Network::Bitcoin), "10025'/0'/0'/1'");
        std::fs::remove_dir_all(dir).ok();
    }
}
