//! `IKeyChain`: ownership proofs and coinjoin input signatures. `SoftKeyChain` is Wasabi's
//! `KeyChain` (BIP38-encrypted master key in the wallet file); device key chains come in M3.

use crate::ownership::{ownership_identifier, OwnershipProof};
use crate::units::{FeeRate, ScriptType};
use bitcoin::bip32::{ChainCode, DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, TapTweak, UntweakedKeypair};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{Network, NetworkKind, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum KeyChainError {
    #[error("the signing key for {0} was not found")]
    KeyNotFound(String),
    #[error("device: {0}")]
    Device(String),
    #[error("{0}")]
    Other(String),
}

/// The transaction to sign, with every input's prevout (coordinator-published) and the foreign
/// inputs' ownership proofs (a device verifies those).
pub struct UnsignedCoinJoin {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub ownership_proofs: HashMap<OutPoint, Vec<u8>>,
}

pub trait KeyChain: Send + Sync {
    /// True when signing needs device I/O; such a signer signs once up front.
    fn signing_takes_time(&self) -> bool {
        false
    }
    /// Fee cap the device was authorized with (sat/vB), if any.
    fn max_mining_fee_rate(&self) -> Option<FeeRate> {
        None
    }
    fn needs_authorization(&self) -> bool {
        false
    }
    fn min_round_inputs(&self) -> Option<i32> {
        None
    }
    fn can_sign(&self, _script_type: ScriptType) -> bool {
        true
    }
    fn get_ownership_proof(&self, script_pubkey: &ScriptBuf, commitment: &[u8]) -> Result<OwnershipProof, KeyChainError>;
    /// Witness for the input spending `outpoint`.
    fn sign(&self, unsigned: &UnsignedCoinJoin, outpoint: &OutPoint) -> Result<Witness, KeyChainError>;
}

pub struct SoftKeyChain {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    master: Xpriv,
    /// script -> full derivation path
    paths: HashMap<ScriptBuf, DerivationPath>,
}

impl SoftKeyChain {
    pub fn from_master(master: Xpriv, paths: HashMap<ScriptBuf, DerivationPath>) -> Self {
        Self { secp: Secp256k1::new(), master, paths }
    }

    /// `KeyManager.GetMasterExtKey`: BIP38 `EncryptedSecret` + base64 `ChainCode`. The only place a
    /// password is ever used.
    pub fn decrypt_master(encrypted_secret: &str, chain_code_b64: &str, password: &str, network: Network) -> Result<Xpriv, KeyChainError> {
        use base64::Engine;
        use bip38::Decrypt;
        let (key, _compressed) = encrypted_secret.decrypt(password).map_err(|e| KeyChainError::Other(format!("Invalid passphrase ({e:?})")))?;
        let cc = base64::engine::general_purpose::STANDARD.decode(chain_code_b64).map_err(|e| KeyChainError::Other(format!("ChainCode: {e}")))?;
        let cc: [u8; 32] = cc.try_into().map_err(|_| KeyChainError::Other("ChainCode must be 32 bytes".into()))?;
        let master = Xpriv {
            network: if network == Network::Bitcoin { NetworkKind::Main } else { NetworkKind::Test },
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
            private_key: SecretKey::from_slice(&key).map_err(|e| KeyChainError::Other(e.to_string()))?,
            chain_code: ChainCode::from(cc),
        };
        Ok(master)
    }

    pub fn add_path(&mut self, script: ScriptBuf, path: DerivationPath) {
        self.paths.insert(script, path);
    }

    fn secret_for(&self, script: &ScriptBuf) -> Result<SecretKey, KeyChainError> {
        let path = self.paths.get(script).ok_or_else(|| KeyChainError::KeyNotFound(script.to_string()))?;
        let child = self.master.derive_priv(&self.secp, path).map_err(|e| KeyChainError::Other(e.to_string()))?;
        Ok(child.private_key)
    }

    pub fn master_private_key(&self) -> [u8; 32] {
        self.master.private_key.secret_bytes()
    }
}

/// Wasabi `FullKeyPath` (`84'/0'/0'/0/5`) to a derivation path.
pub fn derivation_path(full_key_path: &str) -> Option<DerivationPath> {
    format!("m/{}", full_key_path.trim_start_matches("m/")).parse().ok()
}

impl KeyChain for SoftKeyChain {
    fn get_ownership_proof(&self, script_pubkey: &ScriptBuf, commitment: &[u8]) -> Result<OwnershipProof, KeyChainError> {
        let sk = self.secret_for(script_pubkey)?;
        let identifier = ownership_identifier(&self.master_private_key(), script_pubkey);
        OwnershipProof::generate(&sk, identifier, script_pubkey, commitment).map_err(|e| KeyChainError::Other(e.to_string()))
    }

    fn sign(&self, unsigned: &UnsignedCoinJoin, outpoint: &OutPoint) -> Result<Witness, KeyChainError> {
        let index = unsigned.tx.input.iter().position(|i| i.previous_output == *outpoint).ok_or_else(|| KeyChainError::Other("Missing input.".into()))?;
        let prevout = &unsigned.prevouts[index];
        let sk = self.secret_for(&prevout.script_pubkey)?;
        let mut cache = SighashCache::new(&unsigned.tx);
        if prevout.script_pubkey.is_p2wpkh() {
            let sighash = cache
                .p2wpkh_signature_hash(index, &prevout.script_pubkey, prevout.value, EcdsaSighashType::All)
                .map_err(|e| KeyChainError::Other(e.to_string()))?;
            let msg = Message::from_digest(sighash.to_byte_array());
            // NBitcoin's TransactionBuilder grinds low-R signatures.
            let sig = self.secp.sign_ecdsa_low_r(&msg, &sk);
            let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &sk);
            let mut der = sig.serialize_der().to_vec();
            der.push(EcdsaSighashType::All as u8);
            let mut w = Witness::new();
            w.push(der);
            w.push(pk.serialize());
            Ok(w)
        } else if prevout.script_pubkey.is_p2tr() {
            let sighash = cache
                .taproot_key_spend_signature_hash(index, &Prevouts::All(&unsigned.prevouts), TapSighashType::All)
                .map_err(|e| KeyChainError::Other(e.to_string()))?;
            let msg = Message::from_digest(sighash.to_byte_array());
            let kp = UntweakedKeypair::from_secret_key(&self.secp, &sk);
            let tweaked = kp.tap_tweak(&self.secp, None);
            let sig = self.secp.sign_schnorr(&msg, &tweaked.to_keypair());
            // Wasabi signs taproot inputs with TaprootSigHash.All: 64 bytes + 0x01.
            let mut bytes = sig.as_ref().to_vec();
            bytes.push(TapSighashType::All as u8);
            let mut w = Witness::new();
            w.push(bytes);
            Ok(w)
        } else {
            Err(KeyChainError::Other("Only P2WPKH and P2TR inputs can be signed.".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, TxIn, Txid};

    #[test]
    fn signs_p2wpkh_and_p2tr_inputs_that_verify() {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Main, &[9u8; 64]).unwrap();
        let mut paths = HashMap::new();
        let mut prevouts = Vec::new();
        for (p, taproot) in [("m/84'/0'/0'/0/0", false), ("m/86'/0'/0'/0/0", true)] {
            let path: DerivationPath = p.parse().unwrap();
            let child = master.derive_priv(&secp, &path).unwrap();
            let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &child.private_key);
            let spk = if taproot {
                ScriptBuf::new_p2tr(&secp, bitcoin::secp256k1::XOnlyPublicKey::from(pk), None)
            } else {
                ScriptBuf::new_p2wpkh(&bitcoin::key::CompressedPublicKey(pk).wpubkey_hash())
            };
            paths.insert(spk.clone(), path);
            prevouts.push(TxOut { value: Amount::from_sat(50_000), script_pubkey: spk });
        }
        let kc = SoftKeyChain { secp: Secp256k1::new(), master, paths };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: (0..2).map(|i| TxIn { previous_output: OutPoint { txid: Txid::from_slice(&[i as u8 + 1; 32]).unwrap(), vout: 0 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }).collect(),
            output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: prevouts[0].script_pubkey.clone() }],
        };
        let unsigned = UnsignedCoinJoin { tx: tx.clone(), prevouts: prevouts.clone(), ownership_proofs: HashMap::new() };
        let mut signed = tx.clone();
        for (i, input) in tx.input.iter().enumerate() {
            signed.input[i].witness = kc.sign(&unsigned, &input.previous_output).unwrap();
        }
        assert_eq!(signed.input[0].witness.len(), 2);
        assert_eq!(signed.input[1].witness.len(), 1);
        assert_eq!(signed.input[1].witness[0].len(), 65);
        // Verify the signatures against the sighashes the way a script interpreter would.
        let mut cache = SighashCache::new(&signed);
        let h0 = cache.p2wpkh_signature_hash(0, &prevouts[0].script_pubkey, prevouts[0].value, EcdsaSighashType::All).unwrap();
        let w = &signed.input[0].witness;
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&w[0][..w[0].len() - 1]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&w[1]).unwrap();
        secp.verify_ecdsa(&Message::from_digest(h0.to_byte_array()), &sig, &pk).unwrap();
        let h1 = cache.taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), TapSighashType::All).unwrap();
        let w = &signed.input[1].witness;
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&w[0][..64]).unwrap();
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&prevouts[1].script_pubkey.as_bytes()[2..34]).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(h1.to_byte_array()), &xonly).unwrap();
    }
}
