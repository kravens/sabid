//! `TrezorKeyChain`: ownership proofs and coinjoin signatures from the device's standing
//! authorization. All our inputs are signed in one preauthorized SignTx per round (each call spends
//! one authorized round); witnesses are cached so the per-input calls hit the device once.

use super::bridge::TrezorError;
use super::device::TrezorDevice;
use super::messages::{address_n, is_slip25, InputScriptType, OutputScriptType, TxInput, TxOutput};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid, Witness};
use coinjoin::keychain::{KeyChain, KeyChainError, UnsignedCoinJoin};
use coinjoin::ownership::OwnershipProof;
use coinjoin::units::FeeRate;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Firmware clamps the minimum registrable output amount to at most this (MIN_REGISTRABLE_OUTPUT_AMOUNT).
const MIN_REGISTRABLE_AMOUNT: u64 = 5000;

pub struct TrezorKeyChain {
    pub device: Arc<TrezorDevice>,
    network: Network,
    /// script -> full key path (Wasabi `FullKeyPath` string)
    paths: Mutex<HashMap<ScriptBuf, String>>,
    round_commitment: Mutex<Vec<u8>>,
    signed: Mutex<HashMap<Txid, HashMap<OutPoint, Witness>>>,
    pub max_mining_fee_rate: Mutex<Option<FeeRate>>,
    needs_authorization: AtomicBool,
    handle: tokio::runtime::Handle,
}

impl TrezorKeyChain {
    pub fn new(device: Arc<TrezorDevice>, network: Network, paths: HashMap<ScriptBuf, String>) -> Self {
        Self {
            device,
            network,
            paths: Mutex::new(paths),
            round_commitment: Mutex::new(vec![]),
            signed: Mutex::new(HashMap::new()),
            max_mining_fee_rate: Mutex::new(None),
            needs_authorization: AtomicBool::new(true),
            handle: tokio::runtime::Handle::current(),
        }
    }

    pub fn set_paths(&self, paths: HashMap<ScriptBuf, String>) {
        *self.paths.lock().unwrap() = paths;
    }

    /// Asks the device to authorize `max_rounds` rounds at most `max_fee_rate` (sat/vB) for the coordinator.
    pub async fn authorize(&self, coordinator_identifier: &str, max_rounds: u64, max_fee_rate: FeeRate, account_path: &str) -> Result<(), TrezorError> {
        let account = address_n(account_path).ok_or_else(|| TrezorError(format!("bad account path {account_path}")))?;
        self.device.authorize_coinjoin(coordinator_identifier, max_rounds, max_fee_rate.fee_per_k as u64, &account, self.network).await?;
        *self.max_mining_fee_rate.lock().unwrap() = Some(max_fee_rate);
        self.needs_authorization.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn block_on<T>(&self, fut: impl std::future::Future<Output = T>) -> T {
        tokio::task::block_in_place(|| self.handle.block_on(fut))
    }

    fn while_authorized<T>(&self, r: Result<T, TrezorError>) -> Result<T, KeyChainError> {
        r.map_err(|e| {
            self.needs_authorization.store(true, Ordering::SeqCst);
            KeyChainError::Device(e.0)
        })
    }

    fn sign_on_device(&self, unsigned: &UnsignedCoinJoin) -> Result<HashMap<OutPoint, Witness>, KeyChainError> {
        let paths = self.paths.lock().unwrap().clone();
        let commitment = self.round_commitment.lock().unwrap().clone();
        let mut inputs = Vec::with_capacity(unsigned.tx.input.len());
        for (i, input) in unsigned.tx.input.iter().enumerate() {
            let prevout = &unsigned.prevouts[i];
            let path = paths.get(&prevout.script_pubkey).and_then(|p| address_n(p));
            let mut prev_hash = input.previous_output.txid.to_byte_array().to_vec();
            prev_hash.reverse();
            let ours = path.is_some();
            inputs.push(TxInput {
                address_n: path.unwrap_or_default(),
                prev_hash,
                prev_index: input.previous_output.vout,
                sequence: input.sequence.0,
                script_type: if ours { InputScriptType::SpendTaproot } else { InputScriptType::External },
                amount: prevout.value.to_sat(),
                script_pubkey: prevout.script_pubkey.to_bytes(),
                ownership_proof: if ours {
                    vec![]
                } else {
                    unsigned.ownership_proofs.get(&input.previous_output).cloned().ok_or_else(|| KeyChainError::Other(format!("The ownership proof of the foreign input '{}' was not found.", input.previous_output)))?
                },
                commitment_data: if ours { vec![] } else { commitment.clone() },
            });
        }
        let mut outputs = Vec::with_capacity(unsigned.tx.output.len());
        for o in &unsigned.tx.output {
            let path = paths.get(&o.script_pubkey).and_then(|p| address_n(p)).filter(|p| is_slip25(p));
            match path {
                Some(p) => outputs.push(TxOutput { address_n: p, address: String::new(), amount: o.value.to_sat(), script_type: OutputScriptType::PayToTaproot }),
                None => {
                    let address = Address::from_script(&o.script_pubkey, self.network).map_err(|e| KeyChainError::Other(format!("output address: {e}")))?;
                    outputs.push(TxOutput { address_n: vec![], address: address.to_string(), amount: o.value.to_sat(), script_type: OutputScriptType::PayToAddress });
                }
            }
        }
        let sigs = self.while_authorized(self.block_on(self.device.sign_coinjoin(&inputs, &outputs, unsigned.tx.version.0 as u32, unsigned.tx.lock_time.to_consensus_u32(), MIN_REGISTRABLE_AMOUNT, self.network)))?;
        let mut witnesses = HashMap::new();
        for (index, sig) in sigs {
            let mut w = Witness::new();
            w.push(sig);
            witnesses.insert(unsigned.tx.input[index].previous_output, w);
        }
        Ok(witnesses)
    }
}

impl KeyChain for TrezorKeyChain {
    fn signing_takes_time(&self) -> bool {
        true
    }
    fn max_mining_fee_rate(&self) -> Option<FeeRate> {
        *self.max_mining_fee_rate.lock().unwrap()
    }
    fn needs_authorization(&self) -> bool {
        self.needs_authorization.load(Ordering::SeqCst)
    }

    fn get_ownership_proof(&self, script_pubkey: &ScriptBuf, commitment: &[u8]) -> Result<OwnershipProof, KeyChainError> {
        let path = self.paths.lock().unwrap().get(script_pubkey).cloned().ok_or_else(|| KeyChainError::KeyNotFound(script_pubkey.to_string()))?;
        let n = address_n(&path).ok_or_else(|| KeyChainError::Other(format!("bad key path {path}")))?;
        *self.round_commitment.lock().unwrap() = commitment.to_vec();
        let bytes = self.while_authorized(self.block_on(self.device.ownership_proof(&n, commitment, self.network)))?;
        OwnershipProof::from_bytes(&bytes).map_err(|e| KeyChainError::Device(format!("device ownership proof: {e}")))
    }

    fn sign(&self, unsigned: &UnsignedCoinJoin, outpoint: &OutPoint) -> Result<Witness, KeyChainError> {
        let txid = unsigned.tx.compute_txid();
        if let Some(w) = self.signed.lock().unwrap().get(&txid).and_then(|m| m.get(outpoint)) {
            return Ok(w.clone());
        }
        let witnesses = self.sign_on_device(unsigned)?;
        let w = witnesses.get(outpoint).cloned().ok_or_else(|| KeyChainError::Other(format!("The device did not sign {outpoint}.")))?;
        self.signed.lock().unwrap().insert(txid, witnesses);
        Ok(w)
    }
}
