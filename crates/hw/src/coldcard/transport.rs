//! ckcc link: framing over HID reports and AES-256-CTR link encryption after an ECDH handshake
//! (Wasabi's `CkccFraming`, `CkccEncryption`, `ColdcardTransport`).

use super::hid::{HidDevice, HidError, INPUT_REPORT_LEN, OUTPUT_REPORT_LEN};
use aes::cipher::{KeyIvInit, StreamCipher};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{ecdh, PublicKey, Secp256k1, SecretKey};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const PAYLOAD_PER_REPORT: usize = 63;
const LAST_FLAG: u8 = 0x80;
const ENCRYPT_FLAG: u8 = 0x40;
const LENGTH_MASK: u8 = 0x3f;
const MAX_MESSAGE_LEN: usize = 2060 + PAYLOAD_PER_REPORT;

#[derive(Debug, thiserror::Error)]
#[error("Coldcard: {0}")]
pub struct ColdcardError(pub String);

impl From<HidError> for ColdcardError {
    fn from(e: HidError) -> Self {
        ColdcardError(e.to_string())
    }
}

pub struct Transport {
    hid: HidDevice,
    encrypt: Option<Aes256Ctr>,
    decrypt: Option<Aes256Ctr>,
    pub healthy: bool,
}

impl Transport {
    pub fn new(hid: HidDevice) -> Self {
        Self { hid, encrypt: None, decrypt: None, healthy: true }
    }

    /// `ncry` v1 handshake; returns (master fingerprint as the device sends it, little-endian u32; master xpub).
    pub fn start_encryption(&mut self) -> Result<(u32, String), ColdcardError> {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand_core_os());
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let our_xy = &pk.serialize_uncompressed()[1..];
        let mut request = b"ncry".to_vec();
        request.extend_from_slice(&[1, 0, 0, 0]);
        request.extend_from_slice(our_xy);
        let (tag, payload) = self.send_receive_raw(&request, false, 15_000)?;
        if tag != "mypb" {
            self.healthy = false;
            return Err(ColdcardError(format!("unexpected reply to encrypt-start: '{tag}'.")));
        }
        if payload.len() < 72 {
            self.healthy = false;
            return Err(ColdcardError(format!("the handshake reply ({} bytes) does not fit the mypb layout.", payload.len())));
        }
        let xpub_len = u32::from_le_bytes(payload[68..72].try_into().unwrap()) as usize;
        if xpub_len > payload.len() - 72 {
            self.healthy = false;
            return Err(ColdcardError("the handshake reply does not fit the mypb layout.".into()));
        }
        let mut device_pub = vec![0x04];
        device_pub.extend_from_slice(&payload[..64]);
        let device_pk = PublicKey::from_slice(&device_pub).map_err(|e| ColdcardError(format!("device public key: {e}")))?;
        let fingerprint = u32::from_le_bytes(payload[64..68].try_into().unwrap());
        let xpub = String::from_utf8_lossy(&payload[72..72 + xpub_len]).trim_end_matches('\0').to_string();
        // Session key = SHA256(x || y) of the shared point.
        let shared = ecdh::shared_secret_point(&device_pk, &sk);
        let key = sha256::Hash::hash(&shared).to_byte_array();
        let iv = [0u8; 16];
        self.encrypt = Some(Aes256Ctr::new(&key.into(), &iv.into()));
        self.decrypt = Some(Aes256Ctr::new(&key.into(), &iv.into()));
        Ok((fingerprint, xpub))
    }

    pub fn send_receive(&mut self, message: &[u8], timeout_ms: i32) -> Result<(String, Vec<u8>), ColdcardError> {
        let encrypted = self.encrypt.is_some();
        self.send_receive_raw(message, encrypted, timeout_ms)
    }

    fn send_receive_raw(&mut self, message: &[u8], encrypt: bool, timeout_ms: i32) -> Result<(String, Vec<u8>), ColdcardError> {
        let mut framed = message.to_vec();
        if encrypt {
            self.encrypt.as_mut().unwrap().apply_keystream(&mut framed);
        }
        let result: Result<Vec<u8>, HidError> = (|| {
            let mut offset = 0;
            loop {
                let here = PAYLOAD_PER_REPORT.min(framed.len() - offset);
                let mut report = [0u8; OUTPUT_REPORT_LEN];
                let last = offset + here == framed.len();
                report[1] = (here as u8) | if last { LAST_FLAG } else { 0 } | if encrypt { ENCRYPT_FLAG } else { 0 };
                report[2..2 + here].copy_from_slice(&framed[offset..offset + here]);
                self.hid.write_report(&report)?;
                offset += here;
                if offset >= framed.len() {
                    break;
                }
            }
            let mut response = Vec::new();
            loop {
                let report = self.hid.read_report(timeout_ms)?;
                let header = report[0];
                let len = (header & LENGTH_MASK) as usize;
                if response.len() + len > MAX_MESSAGE_LEN {
                    return Err(HidError::Io("Coldcard response grew past the protocol maximum without ending.".into()));
                }
                response.extend_from_slice(&report[1..1 + len.min(INPUT_REPORT_LEN - 1)]);
                if header & LAST_FLAG != 0 {
                    return Ok(response);
                }
            }
        })();
        let mut response = match result {
            Ok(r) => r,
            Err(e) => {
                self.healthy = false;
                return Err(e.into());
            }
        };
        if encrypt {
            self.decrypt.as_mut().unwrap().apply_keystream(&mut response);
        }
        if response.len() < 4 {
            self.healthy = false;
            return Err(ColdcardError("truncated response.".into()));
        }
        if !response[..4].iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_') {
            self.healthy = false;
            return Err(ColdcardError("the reply could not be read, so the encrypted link has lost sync. Reconnecting to the device.".into()));
        }
        let tag = String::from_utf8_lossy(&response[..4]).to_string();
        let payload = response[4..].to_vec();
        if tag == "err_" {
            return Err(ColdcardError(String::from_utf8_lossy(&payload).to_string()));
        }
        Ok((tag, payload))
    }
}

/// `rand_core` 0.6 adapter around the OS rng for secp256k1's key generation.
fn rand_core_os() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}
