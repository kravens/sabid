//! `ColdcardKeyChain`: ownership proofs through `slp9`, rounds signed as a PSBT under the HSM policy.
//! Uses the wallet's ordinary segwit/taproot accounts (no SLIP-25 account like Trezor).

use super::device::{ColdcardDevice, AF_P2TR, AF_P2WPKH};
use super::transport::ColdcardError;
use bitcoin::bip32::{DerivationPath, Fingerprint, KeySource};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::{OutPoint, ScriptBuf, Txid, Witness};
use coinjoin::keychain::{derivation_path, KeyChain, KeyChainError, UnsignedCoinJoin};
use coinjoin::ownership::OwnershipProof;
use coinjoin::units::{FeeRate, ScriptType};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub path: String,
    pub pubkey: PublicKey,
}

pub struct ColdcardKeyChain {
    pub device: Arc<ColdcardDevice>,
    master_fingerprint: Fingerprint,
    /// script -> (full key path, pubkey)
    keys: Mutex<HashMap<ScriptBuf, KeyInfo>>,
    max_rounds: usize,
    rounds_signed: AtomicUsize,
    approved_max_fee: FeeRate,
    configured_max_fee: FeeRate,
    approved_min_inputs: i32,
    configured_min_inputs: i32,
    signed: Mutex<HashMap<Txid, HashMap<OutPoint, Witness>>>,
}

impl ColdcardKeyChain {
    pub fn new(device: Arc<ColdcardDevice>, master_fingerprint_hex: &str, keys: HashMap<ScriptBuf, KeyInfo>, max_rounds: usize, max_fee: FeeRate, min_inputs: i32) -> Result<Self, KeyChainError> {
        let fp = hex::decode(master_fingerprint_hex).map_err(|e| KeyChainError::Other(format!("master fingerprint: {e}")))?;
        let fp: [u8; 4] = fp.try_into().map_err(|_| KeyChainError::Other("master fingerprint must be 4 bytes".into()))?;
        Ok(Self {
            device,
            master_fingerprint: Fingerprint::from(fp),
            keys: Mutex::new(keys),
            max_rounds,
            rounds_signed: AtomicUsize::new(0),
            approved_max_fee: max_fee,
            configured_max_fee: max_fee,
            approved_min_inputs: min_inputs,
            configured_min_inputs: min_inputs,
            signed: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_keys(&self, keys: HashMap<ScriptBuf, KeyInfo>) {
        *self.keys.lock().unwrap() = keys;
    }

    fn budget_spent(&self) -> bool {
        self.rounds_signed.load(Ordering::SeqCst) >= self.max_rounds
    }

    fn is_policy_running(&self) -> bool {
        match self.device.hsm_status() {
            Ok(s) if s.active => true,
            Ok(_) => {
                tracing::info!("The Coldcard is not in HSM mode; the coinjoin policy has to be approved on it again.");
                false
            }
            Err(e) => {
                tracing::debug!("The Coldcard did not answer: {e}");
                false
            }
        }
    }

    /// The PSBT the device signs a round from, and which inputs are ours (Wasabi `ColdcardKeyChain.CreatePsbt`).
    /// Every input carries its witness UTXO: the 6.6.1X coinjoin firmware fails late ("Signing failed late")
    /// when a foreign input has none, measured 2026-10-18; the 5.6.0 line tolerated it. Costs ~30% more
    /// bytes and ~5-8% more device time.
    pub fn create_psbt(&self, unsigned: &UnsignedCoinJoin) -> Result<(Psbt, HashSet<OutPoint>), KeyChainError> {
        let keys = self.keys.lock().unwrap();
        let is_ours: Vec<bool> = unsigned.prevouts.iter().map(|o| keys.contains_key(&o.script_pubkey)).collect();
        let mut psbt = Psbt::from_unsigned_tx(unsigned.tx.clone()).map_err(|e| KeyChainError::Other(format!("psbt: {e}")))?;
        let mut ours = HashSet::new();
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            let prevout = &unsigned.prevouts[i];
            input.witness_utxo = Some(prevout.clone());
            if is_ours[i] {
                ours.insert(unsigned.tx.input[i].previous_output);
                let k = &keys[&prevout.script_pubkey];
                let path: DerivationPath = derivation_path(&k.path).ok_or_else(|| KeyChainError::Other(format!("bad key path {}", k.path)))?;
                let source: KeySource = (self.master_fingerprint, path);
                if prevout.script_pubkey.is_p2tr() {
                    let xonly = XOnlyPublicKey::from(k.pubkey);
                    input.tap_internal_key = Some(xonly);
                    input.tap_key_origins.insert(xonly, (vec![], source));
                } else {
                    input.bip32_derivation.insert(k.pubkey, source);
                }
            }
        }
        for (i, output) in psbt.outputs.iter_mut().enumerate() {
            let spk = &unsigned.tx.output[i].script_pubkey;
            if let Some(k) = keys.get(spk) {
                let path: DerivationPath = derivation_path(&k.path).ok_or_else(|| KeyChainError::Other(format!("bad key path {}", k.path)))?;
                let source: KeySource = (self.master_fingerprint, path);
                if spk.is_p2tr() {
                    let xonly = XOnlyPublicKey::from(k.pubkey);
                    output.tap_internal_key = Some(xonly);
                    output.tap_key_origins.insert(xonly, (vec![], source));
                } else {
                    output.bip32_derivation.insert(k.pubkey, source);
                }
            }
        }
        Ok((psbt, ours))
    }

    fn sign_on_device(&self, unsigned: &UnsignedCoinJoin) -> Result<HashMap<OutPoint, Witness>, KeyChainError> {
        let (psbt, ours) = self.create_psbt(unsigned)?;
        let bytes = psbt.serialize();
        let started = Instant::now();
        let signed = self.device.sign_psbt(&bytes, Instant::now() + Duration::from_secs(360)).map_err(|e| KeyChainError::Device(e.0))?;
        let elapsed = started.elapsed().as_secs_f64();
        let signed = Psbt::deserialize(&signed).map_err(|e| KeyChainError::Device(format!("signed psbt: {e}")))?;
        let mut witnesses: HashMap<OutPoint, Witness> = HashMap::new();
        for (i, input) in signed.inputs.iter().enumerate() {
            let op = signed.unsigned_tx.input[i].previous_output;
            if !ours.contains(&op) {
                continue;
            }
            if let Some(w) = &input.final_script_witness {
                witnesses.insert(op, w.clone());
            } else if let Some(sig) = &input.tap_key_sig {
                let mut w = Witness::new();
                w.push(sig.to_vec());
                witnesses.insert(op, w);
            } else if let Some((pk, sig)) = input.partial_sigs.iter().next() {
                let mut w = Witness::new();
                w.push(sig.to_vec());
                w.push(pk.inner.serialize());
                witnesses.insert(op, w);
            }
        }
        tracing::info!("Coldcard returned witnesses for {} of our {} input(s), from a {}-byte PSBT in {elapsed:.1}s.", witnesses.len(), ours.len(), bytes.len());
        if witnesses.len() < ours.len() {
            tracing::warn!("Coldcard returned no usable witness for {} of our input(s).", ours.len() - witnesses.len());
        }
        self.rounds_signed.fetch_add(1, Ordering::SeqCst);
        Ok(witnesses)
    }
}

impl KeyChain for ColdcardKeyChain {
    fn signing_takes_time(&self) -> bool {
        true
    }
    fn max_mining_fee_rate(&self) -> Option<FeeRate> {
        Some(self.approved_max_fee.min(self.configured_max_fee))
    }
    fn needs_authorization(&self) -> bool {
        self.budget_spent() || !self.is_policy_running()
    }
    fn min_round_inputs(&self) -> Option<i32> {
        let floor = self.approved_min_inputs.max(self.configured_min_inputs);
        (floor > 0).then_some(floor)
    }
    fn can_sign(&self, script_type: ScriptType) -> bool {
        matches!(script_type, ScriptType::P2WPKH | ScriptType::Taproot)
    }

    fn get_ownership_proof(&self, script_pubkey: &ScriptBuf, commitment: &[u8]) -> Result<OwnershipProof, KeyChainError> {
        if self.budget_spent() {
            return Err(KeyChainError::Device(format!("The authorized {} coinjoin rounds are used up. Authorize the Coldcard again to continue.", self.max_rounds)));
        }
        let path = self.keys.lock().unwrap().get(script_pubkey).map(|k| k.path.clone()).ok_or_else(|| KeyChainError::KeyNotFound(script_pubkey.to_string()))?;
        let af = if script_pubkey.is_p2tr() {
            AF_P2TR
        } else if script_pubkey.is_p2wpkh() {
            AF_P2WPKH
        } else {
            return Err(KeyChainError::Other(format!("A Coldcard cannot prove ownership of '{script_pubkey}'.")));
        };
        let bytes = self.device.ownership_proof(&path, af, commitment).map_err(|e| KeyChainError::Device(e.0))?;
        OwnershipProof::from_bytes(&bytes).map_err(|e| KeyChainError::Device(format!("device ownership proof: {e}")))
    }

    fn sign(&self, unsigned: &UnsignedCoinJoin, outpoint: &OutPoint) -> Result<Witness, KeyChainError> {
        let txid = unsigned.tx.compute_txid();
        if let Some(w) = self.signed.lock().unwrap().get(&txid).and_then(|m| m.get(outpoint)) {
            return Ok(w.clone());
        }
        let witnesses = self.sign_on_device(unsigned)?;
        let w = witnesses.get(outpoint).cloned().ok_or_else(|| KeyChainError::Device(format!("The device did not sign {outpoint}.")))?;
        self.signed.lock().unwrap().insert(txid, witnesses);
        Ok(w)
    }
}

impl From<ColdcardError> for KeyChainError {
    fn from(e: ColdcardError) -> Self {
        KeyChainError::Device(e.0)
    }
}

#[allow(dead_code)]
fn _unused(_: BTreeMap<u8, u8>) {}
