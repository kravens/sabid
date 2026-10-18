//! `TrezorDevice`: the operations HWI cannot do, over the bridge.

use super::bridge::{BridgeDevice, BridgeTransport, TrezorError, DEFAULT_BRIDGE_URIS};
use super::messages::{self as msg, Features, InputScriptType, Message, MessageType, TxInput, TxOutput, TxRequest, TxRequestType, HARDENED, SLIP25_PURPOSE};
use bitcoin::Network;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;

const MIN_FIRMWARE: (u32, u32, u32) = (2, 7, 2);

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub model: String,
    pub firmware: String,
    pub fingerprint: String,
    pub passphrase_protection: bool,
    pub error: Option<String>,
}

pub struct TrezorDevice {
    transport: BridgeTransport,
    session: String,
    use_on_device_passphrase: bool,
    pub features: Option<Features>,
    lock: Mutex<()>,
}

pub fn coin_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "Bitcoin",
        Network::Regtest => "Regtest",
        _ => "Testnet",
    }
}

impl TrezorDevice {
    /// Finds and acquires the connected Trezor with the given master fingerprint (hex, 4 bytes).
    pub async fn find(master_fingerprint: Option<&str>) -> Result<TrezorDevice, TrezorError> {
        let mut error = None;
        let mut found: Option<(BridgeTransport, Vec<BridgeDevice>)> = None;
        for uri in DEFAULT_BRIDGE_URIS {
            let t = BridgeTransport::new(uri)?;
            match tokio::time::timeout(Duration::from_secs(5), t.enumerate()).await {
                Ok(Ok(devices)) => {
                    found = Some((t, devices));
                    break;
                }
                Ok(Err(e)) => error = Some(e.0),
                Err(_) => error = Some(format!("{uri} did not answer")),
            }
        }
        let Some((transport, devices)) = found else {
            return Err(TrezorError(format!("Trezor Bridge is not running. Start pytrezord or Trezor Suite and try again. ({})", error.unwrap_or_default())));
        };
        if devices.is_empty() {
            return Err(TrezorError("No Trezor device found. Connect the Trezor and unlock it with its PIN.".into()));
        }
        let mut last_error = None;
        let mut saw_passphrase = false;
        for bd in &devices {
            for on_device in [false, true] {
                let mut device = TrezorDevice { transport: transport.clone(), session: String::new(), use_on_device_passphrase: on_device, features: None, lock: Mutex::new(()) };
                match device.open(bd).await {
                    Ok(()) => {
                        let matches = match master_fingerprint {
                            None => true,
                            Some(fp) => match device.master_fingerprint().await {
                                Ok(found) => found.eq_ignore_ascii_case(fp),
                                Err(e) => {
                                    last_error = Some(e.0);
                                    false
                                }
                            },
                        };
                        if matches {
                            return Ok(device);
                        }
                        let pp = device.features.as_ref().map(|f| f.passphrase_protection).unwrap_or(false);
                        saw_passphrase |= pp;
                        device.release().await;
                        if on_device || !pp {
                            break;
                        }
                    }
                    Err(e) => {
                        last_error = Some(e.0);
                        device.release().await;
                        break;
                    }
                }
            }
        }
        let hint = if saw_passphrase { " If this wallet uses a passphrase, enter the exact same passphrase on the device." } else { "" };
        Err(TrezorError(match last_error {
            None => format!("No Trezor device with master fingerprint '{}' found.{hint}", master_fingerprint.unwrap_or("")),
            Some(e) => format!("No usable Trezor device found. Last error: {e}"),
        }))
    }

    /// Every Trezor the bridge lists, opened briefly for its features and fingerprint (standard wallet).
    pub async fn enumerate() -> Result<Vec<DeviceInfo>, TrezorError> {
        let mut found = None;
        let mut error = String::new();
        for uri in DEFAULT_BRIDGE_URIS {
            let t = BridgeTransport::new(uri)?;
            match tokio::time::timeout(Duration::from_secs(5), t.enumerate()).await {
                Ok(Ok(devices)) => {
                    found = Some((t, devices));
                    break;
                }
                Ok(Err(e)) => error = e.0,
                Err(_) => error = format!("{uri} did not answer"),
            }
        }
        let Some((transport, devices)) = found else { return Err(TrezorError(format!("Trezor Bridge is not running. ({error})"))) };
        let mut out = Vec::new();
        for bd in &devices {
            let mut device = TrezorDevice { transport: transport.clone(), session: String::new(), use_on_device_passphrase: false, features: None, lock: Mutex::new(()) };
            let mut info = DeviceInfo { path: bd.path.clone(), model: String::new(), firmware: String::new(), fingerprint: String::new(), passphrase_protection: false, error: None };
            match device.open(bd).await {
                Ok(()) => {
                    if let Some(f) = &device.features {
                        info.model = f.model.clone();
                        info.firmware = format!("{}.{}.{}", f.major, f.minor, f.patch);
                        info.passphrase_protection = f.passphrase_protection;
                    }
                    match device.master_fingerprint().await {
                        Ok(fp) => info.fingerprint = fp,
                        Err(e) => info.error = Some(e.0),
                    }
                }
                Err(e) => info.error = Some(e.0),
            }
            device.release().await;
            out.push(info);
        }
        Ok(out)
    }

    async fn open(&mut self, bd: &BridgeDevice) -> Result<(), TrezorError> {
        self.session = self.transport.acquire(bd).await?;
        let mut features = self.call_raw(&msg::initialize()).await?;
        // Drain replies a cancelled earlier call left queued on the bridge.
        for _ in 0..4 {
            if features.kind == MessageType::Features {
                break;
            }
            match tokio::time::timeout(Duration::from_secs(5), self.transport.read(&self.session)).await {
                Ok(Ok(m)) => features = m,
                _ => break,
            }
        }
        if features.kind != MessageType::Features {
            return Err(unexpected(&features, MessageType::Features));
        }
        let f = Features::from_message(&features);
        if f.model == "1" {
            return Err(TrezorError("Trezor Model One does not support coinjoin. A Trezor Model T or newer is required.".into()));
        }
        if f.version() < MIN_FIRMWARE {
            return Err(TrezorError(format!("Trezor firmware {}.{}.{} is too old for coinjoin with this coordinator. Version 2.7.2 or newer is required.", f.major, f.minor, f.patch)));
        }
        self.features = Some(f);
        Ok(())
    }

    pub async fn release(&mut self) {
        if !self.session.is_empty() {
            let _ = tokio::time::timeout(Duration::from_secs(3), self.transport.release(&self.session)).await;
            self.session.clear();
        }
    }

    /// Sends one message, answering button and passphrase requests transparently.
    async fn call_raw(&self, message: &Message) -> Result<Message, TrezorError> {
        let mut response = self.transport.call(&self.session, message).await?;
        loop {
            match response.kind {
                MessageType::ButtonRequest => response = self.transport.call(&self.session, &msg::button_ack()).await?,
                MessageType::PassphraseRequest => {
                    let ack = if self.use_on_device_passphrase { msg::passphrase_ack_on_device() } else { msg::passphrase_ack("") };
                    response = self.transport.call(&self.session, &ack).await?;
                }
                MessageType::Failure => return Err(TrezorError(format!("Trezor failure: {}", response.string(2)))),
                _ => return Ok(response),
            }
        }
    }

    async fn call(&self, message: &Message, expected: MessageType) -> Result<Message, TrezorError> {
        let r = self.call_raw(message).await?;
        if r.kind != expected {
            return Err(unexpected(&r, expected));
        }
        Ok(r)
    }

    /// Hex of the 4-byte master fingerprint, as Wasabi's `MasterFingerprint` string.
    pub async fn master_fingerprint(&self) -> Result<String, TrezorError> {
        let _g = self.lock.lock().await;
        let path = [84 | HARDENED, HARDENED, HARDENED];
        let r = self.call(&msg::get_public_key(&path, "Bitcoin", InputScriptType::SpendWitness), MessageType::PublicKey).await?;
        let fp = crate::proto::first_varint(&r.fields(), 3).unwrap_or(0) as u32;
        Ok(hex::encode(fp.to_be_bytes()))
    }

    /// Account xpub; a SLIP-25 path first needs UnlockPath (confirmed on the device).
    pub async fn account_xpub(&self, account: &[u32], network: Network) -> Result<String, TrezorError> {
        let _g = self.lock.lock().await;
        let slip25 = msg::is_slip25(account);
        if slip25 {
            self.call(&msg::unlock_path(&[SLIP25_PURPOSE]), MessageType::UnlockedPathRequest).await?;
        }
        let st = if slip25 { InputScriptType::SpendTaproot } else { InputScriptType::SpendWitness };
        let r = self.call(&msg::get_public_key(account, coin_name(network), st), MessageType::PublicKey).await?;
        Ok(r.string(2))
    }

    pub async fn show_address(&self, full_path: &[u32], network: Network) -> Result<String, TrezorError> {
        let _g = self.lock.lock().await;
        let slip25 = msg::is_slip25(full_path);
        if slip25 {
            self.call(&msg::unlock_path(&[SLIP25_PURPOSE]), MessageType::UnlockedPathRequest).await?;
        }
        let st = if slip25 { InputScriptType::SpendTaproot } else { InputScriptType::SpendWitness };
        let r = self.call(&msg::get_address(full_path, coin_name(network), st, true), MessageType::Address).await?;
        Ok(r.string(1))
    }

    /// Hold-to-confirm on the device: max rounds and max fee rate (sat per kvB) for the coordinator.
    pub async fn authorize_coinjoin(&self, coordinator: &str, max_rounds: u64, max_fee_per_kvbyte: u64, account: &[u32], network: Network) -> Result<(), TrezorError> {
        let _g = self.lock.lock().await;
        self.call(&msg::authorize_coinjoin(coordinator, max_rounds, 0, max_fee_per_kvbyte, account, coin_name(network)), MessageType::Success).await?;
        Ok(())
    }

    pub async fn ownership_proof(&self, full_path: &[u32], commitment: &[u8], network: Network) -> Result<Vec<u8>, TrezorError> {
        let _g = self.lock.lock().await;
        self.call(&msg::do_preauthorized(), MessageType::PreauthorizedRequest).await?;
        let r = self.call(&msg::get_ownership_proof(full_path, coin_name(network), commitment), MessageType::OwnershipProof).await?;
        Ok(r.bytes(1))
    }

    /// Signs a coinjoin with the standing authorization; 64-byte BIP-340 signatures by input index.
    pub async fn sign_coinjoin(&self, inputs: &[TxInput], outputs: &[TxOutput], version: u32, lock_time: u32, min_registrable_amount: u64, network: Network) -> Result<HashMap<usize, Vec<u8>>, TrezorError> {
        let _g = self.lock.lock().await;
        self.call(&msg::do_preauthorized(), MessageType::PreauthorizedRequest).await?;
        let sign = msg::sign_tx(inputs.len(), outputs.len(), coin_name(network), version, lock_time, Some((0, 0, min_registrable_amount)));
        self.run_signing_flow(&sign, inputs, outputs).await
    }

    async fn run_signing_flow(&self, sign_tx: &Message, inputs: &[TxInput], outputs: &[TxOutput]) -> Result<HashMap<usize, Vec<u8>>, TrezorError> {
        let mut signatures = HashMap::new();
        let mut response = self.call_raw(sign_tx).await?;
        loop {
            if response.kind != MessageType::TxRequest {
                return Err(unexpected(&response, MessageType::TxRequest));
            }
            let req = TxRequest::from_message(&response);
            if let Some(i) = req.signature_index {
                if i >= inputs.len() || inputs[i].script_type == InputScriptType::External {
                    return Err(TrezorError(format!("The device signed input {i}, which is not one of ours.")));
                }
                signatures.insert(i, req.signature.clone());
            }
            if req.tx_hash.is_some() {
                return Err(TrezorError("The device asked for a previous transaction, which a taproot-only coinjoin never needs.".into()));
            }
            response = match req.request_type {
                TxRequestType::TxInput => self.call_raw(&inputs.get(req.request_index).ok_or_else(|| TrezorError("input index out of range".into()))?.to_tx_ack()).await?,
                TxRequestType::TxOutput => self.call_raw(&outputs.get(req.request_index).ok_or_else(|| TrezorError("output index out of range".into()))?.to_tx_ack()).await?,
                TxRequestType::TxFinished => {
                    let ours = inputs.iter().filter(|i| i.script_type != InputScriptType::External).count();
                    if signatures.len() != ours {
                        return Err(TrezorError("The device finished without signing every input of ours.".into()));
                    }
                    return Ok(signatures);
                }
                other => return Err(TrezorError(format!("Unexpected transaction data request '{other:?}'."))),
            };
        }
    }

    pub async fn is_session_alive(&self) -> bool {
        if self.session.is_empty() {
            return false;
        }
        let _g = self.lock.lock().await;
        matches!(tokio::time::timeout(Duration::from_secs(5), self.transport.call(&self.session, &msg::get_features())).await, Ok(Ok(m)) if m.kind == MessageType::Features)
    }
}

fn unexpected(r: &Message, expected: MessageType) -> TrezorError {
    TrezorError(format!("Unexpected message '{:?}' ({}) from Trezor, expected '{expected:?}'.", r.kind, r.raw_type))
}

impl Drop for TrezorDevice {
    fn drop(&mut self) {
        if !self.session.is_empty() {
            let t = self.transport.clone();
            let s = std::mem::take(&mut self.session);
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(3), t.release(&s)).await;
                });
            }
        }
    }
}
