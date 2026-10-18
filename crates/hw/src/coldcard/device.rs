//! `ColdcardDevice`: the typed commands the coinjoin flow needs (Wasabi's `ColdcardDevice`).
//! One USB pipe and no request/response correlation, so every exchange is serialised.

use super::hid::HidDevice;
use super::transport::{ColdcardError, Transport};
use bitcoin::hashes::{sha256, Hash};
use serde_json::Value;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const AF_P2WPKH: u32 = 0x07;
pub const AF_P2TR: u32 = 0x23;

#[derive(Debug, Clone, Default)]
pub struct HsmStatus {
    pub active: bool,
    pub approval_wait: bool,
    pub policy_hash: Option<String>,
    pub summary: Option<String>,
    pub last_refusal: Option<String>,
}

pub struct ColdcardDevice {
    transport: Mutex<Transport>,
    /// Hex, as Wasabi's `MasterFingerprint` string (the handshake delivers it little-endian).
    pub master_fingerprint: String,
    pub master_xpub: String,
    installed_policy_hash: Mutex<Option<String>>,
}

impl ColdcardDevice {
    pub fn open() -> Result<Self, ColdcardError> {
        let mut t = Transport::new(HidDevice::open()?);
        let (fp, xpub) = t.start_encryption()?;
        Ok(Self { transport: Mutex::new(t), master_fingerprint: hex::encode(fp.to_le_bytes()), master_xpub: xpub, installed_policy_hash: Mutex::new(None) })
    }

    /// Reconnects when the AES-CTR link lost sync; an active HSM policy lives on the device and survives.
    fn ensure_healthy(&self, t: &mut Transport) -> Result<(), ColdcardError> {
        if t.healthy {
            return Ok(());
        }
        tracing::warn!("The Coldcard link lost sync; reconnecting to the device.");
        let mut fresh = Transport::new(HidDevice::open()?);
        let (fp, _) = fresh.start_encryption()?;
        if hex::encode(fp.to_le_bytes()) != self.master_fingerprint {
            return Err(ColdcardError("a different Coldcard is now connected. Reconnect the wallet's own device.".into()));
        }
        *t = fresh;
        Ok(())
    }

    fn call(&self, t: &mut Transport, message: &[u8], timeout_ms: i32) -> Result<(String, Vec<u8>), ColdcardError> {
        self.ensure_healthy(t)?;
        t.send_receive(message, timeout_ms)
    }

    pub fn version(&self) -> Result<String, ColdcardError> {
        let mut t = self.transport.lock().unwrap();
        let (_, p) = self.call(&mut t, b"vers", 15_000)?;
        Ok(String::from_utf8_lossy(&p).to_string())
    }

    pub fn xpub(&self, path: &str) -> Result<String, ColdcardError> {
        let mut t = self.transport.lock().unwrap();
        let (_, p) = self.call(&mut t, format!("xpubm/{}", path.trim_start_matches("m/")).as_bytes(), 15_000)?;
        Ok(String::from_utf8_lossy(&p).trim_end_matches('\0').to_string())
    }

    /// `slp9`: a SLIP-19 ownership proof for one of our inputs (serialized, ready for the coordinator).
    pub fn ownership_proof(&self, full_key_path: &str, address_format: u32, commitment: &[u8]) -> Result<Vec<u8>, ColdcardError> {
        let mut t = self.transport.lock().unwrap();
        let subpath = format!("m/{}", full_key_path.trim_start_matches("m/"));
        let mut req = b"slp9".to_vec();
        req.extend_from_slice(&address_format.to_le_bytes());
        req.extend_from_slice(&1u32.to_le_bytes()); // user confirmation flag, required for coinjoin proofs
        req.extend_from_slice(&(subpath.len() as u32).to_le_bytes());
        req.extend_from_slice(&(commitment.len() as u32).to_le_bytes());
        req.extend_from_slice(subpath.as_bytes());
        req.extend_from_slice(commitment);
        let (tag, payload) = self.call(&mut t, &req, 60_000)?;
        if tag != "biny" {
            t.healthy = false;
            return Err(ColdcardError(format!("expected an ownership proof but the device replied '{tag}'.")));
        }
        Ok(payload)
    }

    fn hsm_status_locked(&self, t: &mut Transport) -> Result<HsmStatus, ColdcardError> {
        let (_, payload) = match self.call(t, b"hsts", 15_000) {
            Ok(r) => r,
            Err(e) if e.0.contains("HSM commands disabled") => {
                return Err(ColdcardError("HSM commands are disabled on this Coldcard. Enable them on the device at Settings > Advanced/Tools > Spending Policy > HSM Mode > Enable, then try again.".into()))
            }
            Err(e) => return Err(e),
        };
        let v: Value = serde_json::from_slice(&payload).map_err(|e| ColdcardError(format!("hsts: {e}")))?;
        Ok(HsmStatus {
            active: v.get("active").and_then(Value::as_bool).unwrap_or(false),
            approval_wait: v.get("approval_wait").and_then(Value::as_bool).unwrap_or(false),
            policy_hash: v.get("policy_hash").and_then(Value::as_str).map(str::to_string),
            summary: v.get("summary").and_then(Value::as_str).map(str::to_string),
            last_refusal: v.get("last_refusal").and_then(Value::as_str).map(str::to_string),
        })
    }

    pub fn hsm_status(&self) -> Result<HsmStatus, ColdcardError> {
        let mut t = self.transport.lock().unwrap();
        self.hsm_status_locked(&mut t)
    }

    /// Installs the HSM policy and waits for the on-device approval. Returns the active policy hash when
    /// this wallet approved it (now, or earlier and matched), None when the device runs somebody else's.
    pub fn start_hsm(&self, policy_json: &str, previously_approved_hash: Option<&str>) -> Result<Option<String>, ColdcardError> {
        let mut t = self.transport.lock().unwrap();
        let current = self.hsm_status_locked(&mut t)?;
        if current.active {
            let installed = self.installed_policy_hash.lock().unwrap().clone();
            let approved = installed.or_else(|| previously_approved_hash.map(str::to_string));
            if approved.is_some() && approved == current.policy_hash {
                tracing::info!("The Coldcard is running the policy this wallet approved (hash {}).", approved.unwrap());
                return Ok(current.policy_hash);
            }
            tracing::warn!(
                "The Coldcard is already in HSM mode under a policy this wallet did not approve (device reports hash {}). The limits it enforces are not the ones configured here. Reboot the Coldcard and authorize again to apply these limits.",
                current.policy_hash.clone().unwrap_or_else(|| "unknown".into())
            );
            return Ok(None);
        }
        let data = policy_json.as_bytes();
        let sha = self.upload_locked(&mut t, data)?;
        let mut req = b"hsms".to_vec();
        req.extend_from_slice(&(data.len() as u32).to_le_bytes());
        req.extend_from_slice(&sha);
        self.call(&mut t, &req, 15_000)?;
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let status = self.hsm_status_locked(&mut t)?;
            if status.active {
                *self.installed_policy_hash.lock().unwrap() = status.policy_hash.clone();
                tracing::info!("The Coldcard accepted the coinjoin policy (hash {}).", status.policy_hash.clone().unwrap_or_default());
                if let Some(s) = &status.summary {
                    tracing::info!("Policy the device will enforce:\n{s}");
                }
                return Ok(status.policy_hash);
            }
            if !status.approval_wait {
                return Err(ColdcardError("The HSM policy was refused on the device.".into()));
            }
            if Instant::now() > deadline {
                return Err(ColdcardError("Timed out waiting for the HSM policy approval on the device.".into()));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// `stxn` with flags 0: sign under the policy, return the signed (not finalized) PSBT.
    pub fn sign_psbt(&self, psbt: &[u8], deadline: Instant) -> Result<Vec<u8>, ColdcardError> {
        let mut t = self.transport.lock().unwrap();
        let sha = self.upload_locked(&mut t, psbt)?;
        let mut req = b"stxn".to_vec();
        req.extend_from_slice(&(psbt.len() as u32).to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(&sha);
        self.call(&mut t, &req, 15_000)?;
        loop {
            if Instant::now() > deadline {
                return Err(ColdcardError("signing took longer than the round allows.".into()));
            }
            // A device deep in signing stops answering USB reads for a while; nothing is wrong.
            let (tag, payload) = self.call(&mut t, b"stok", 300_000)?;
            match tag.as_str() {
                "strx" => {
                    if payload.len() < 36 {
                        return Err(ColdcardError(format!("the device sent a {}-byte signing result header; expected 36.", payload.len())));
                    }
                    let len = u32::from_le_bytes(payload[..4].try_into().unwrap());
                    let sha: [u8; 32] = payload[4..36].try_into().unwrap();
                    return self.download_locked(&mut t, len, &sha);
                }
                "refu" => {
                    let reason = self.hsm_status_locked(&mut t).ok().and_then(|s| s.last_refusal).filter(|s| !s.is_empty());
                    let reason = match reason {
                        Some(r) if r.to_lowercase().contains("transaction count") => format!("{r}. The authorized number of transactions is used up: reboot the Coldcard and authorize coinjoining again."),
                        Some(r) => r,
                        None => "Check the device screen for the reason.".into(),
                    };
                    return Err(ColdcardError(format!("signing was refused by the device. {reason}")));
                }
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }

    fn upload_locked(&self, t: &mut Transport, data: &[u8]) -> Result<[u8; 32], ColdcardError> {
        const BLOCK: usize = 1024;
        let mut offset = 0;
        while offset < data.len() {
            let here = BLOCK.min(data.len() - offset);
            let mut req = b"upld".to_vec();
            req.extend_from_slice(&(offset as u32).to_le_bytes());
            req.extend_from_slice(&(data.len() as u32).to_le_bytes());
            req.extend_from_slice(&data[offset..offset + here]);
            self.call(t, &req, 15_000)?;
            offset += here;
        }
        let expected = sha256::Hash::hash(data).to_byte_array();
        let (_, device_sha) = self.call(t, b"sha2", 15_000)?;
        if device_sha != expected {
            t.healthy = false;
            return Err(ColdcardError("checksum mismatch during file upload; the link may have lost sync.".into()));
        }
        Ok(expected)
    }

    fn download_locked(&self, t: &mut Transport, len: u32, expected: &[u8; 32]) -> Result<Vec<u8>, ColdcardError> {
        if len > 2 * 1024 * 1024 {
            return Err(ColdcardError(format!("the device reported an implausible {len}-byte result; refusing it.")));
        }
        const BLOCK: u32 = 1024;
        let mut out = Vec::with_capacity(len as usize);
        let mut offset = 0u32;
        while offset < len {
            let here = BLOCK.min(len - offset);
            let mut req = b"dwld".to_vec();
            req.extend_from_slice(&offset.to_le_bytes());
            req.extend_from_slice(&here.to_le_bytes());
            req.extend_from_slice(&1u32.to_le_bytes());
            let (_, chunk) = self.call(t, &req, 15_000)?;
            out.extend_from_slice(&chunk);
            offset += here;
        }
        if sha256::Hash::hash(&out).to_byte_array() != *expected {
            t.healthy = false;
            return Err(ColdcardError("checksum mismatch during file download; the link may have lost sync.".into()));
        }
        Ok(out)
    }
}
