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

/// The file's JSON, in Wasabi's field order, with no keys yet (`ensure_gap` fills them).
pub fn wallet_json(mnemonic: &bip39::Mnemonic, password: &str, network: Network, birth_height: u32) -> anyhow::Result<Map<String, Value>> {
    let secp = Secp256k1::new();
    let mut seed = mnemonic.to_seed(password);
    let master = Xpriv::new_master(network, &seed)?;
    seed.zeroize();
    let mut secret = master.private_key.secret_bytes();
    let encrypted = secret.encrypt(password, true).map_err(|e| anyhow::anyhow!("BIP 38: {e:?}"))?;
    secret.zeroize();
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    let segwit_path = format!("84'/{coin}'/0'");
    let taproot_path = format!("86'/{coin}'/0'");
    let account_xpub = |p: &str| -> anyhow::Result<String> {
        let path: DerivationPath = format!("m/{p}").parse()?;
        Ok(Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?).to_string())
    };
    let obj = json!({
        "EncryptedSecret": encrypted,
        "ChainCode": base64::engine::general_purpose::STANDARD.encode(master.chain_code.as_bytes()),
        "MasterFingerprint": hex::encode(master.fingerprint(&secp).to_bytes()),
        "ExtPubKey": account_xpub(&segwit_path)?,
        "TaprootExtPubKey": account_xpub(&taproot_path)?,
        "SilentPaymentScanExtPubKey": null,
        "SilentPaymentSpendExtPubKey": null,
        "MinGapLimit": MIN_GAP_LIMIT,
        "AccountKeyPath": segwit_path,
        "TaprootAccountKeyPath": taproot_path,
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
    });
    Ok(obj.as_object().cloned().expect("object"))
}

/// Writes the wallet file (refusing to overwrite) and derives its first keys.
pub fn write_wallet(path: &Path, mnemonic: &bip39::Mnemonic, password: &str, network: Network, birth_height: u32) -> anyhow::Result<KeyManager> {
    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let map = wallet_json(mnemonic, password, network, birth_height)?;
    std::fs::write(path, serde_json::to_string_pretty(&Value::Object(map))?)?;
    let mut km = KeyManager::load(path)?;
    km.ensure_gap();
    km.save()?;
    Ok(km)
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
}
