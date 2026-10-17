//! Trezor message ids and builders (trezor-firmware common/protob), as Wasabi's `TrezorMessages`.

use crate::proto::{first_bytes, first_string, first_varint, read_fields, Fields, ProtoWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Initialize = 0,
    Success = 2,
    Failure = 3,
    GetPublicKey = 11,
    PublicKey = 12,
    SignTx = 15,
    Features = 17,
    TxRequest = 21,
    TxAck = 22,
    ButtonRequest = 26,
    ButtonAck = 27,
    GetAddress = 29,
    Address = 30,
    PassphraseRequest = 41,
    PassphraseAck = 42,
    GetOwnershipProof = 49,
    OwnershipProof = 50,
    AuthorizeCoinJoin = 51,
    GetFeatures = 55,
    DoPreauthorized = 84,
    PreauthorizedRequest = 85,
    UnlockPath = 93,
    UnlockedPathRequest = 94,
    Unknown = 0xffff,
}

impl MessageType {
    pub fn from_u16(n: u16) -> MessageType {
        use MessageType::*;
        match n {
            0 => Initialize,
            2 => Success,
            3 => Failure,
            11 => GetPublicKey,
            12 => PublicKey,
            15 => SignTx,
            17 => Features,
            21 => TxRequest,
            22 => TxAck,
            26 => ButtonRequest,
            27 => ButtonAck,
            29 => GetAddress,
            30 => Address,
            41 => PassphraseRequest,
            42 => PassphraseAck,
            49 => GetOwnershipProof,
            50 => OwnershipProof,
            51 => AuthorizeCoinJoin,
            55 => GetFeatures,
            84 => DoPreauthorized,
            85 => PreauthorizedRequest,
            93 => UnlockPath,
            94 => UnlockedPathRequest,
            _ => Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InputScriptType {
    External = 2,
    SpendWitness = 3,
    SpendTaproot = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OutputScriptType {
    PayToAddress = 0,
    PayToWitness = 4,
    PayToTaproot = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxRequestType {
    TxInput,
    TxOutput,
    TxMeta,
    TxFinished,
    Other(u64),
}

#[derive(Debug, Clone)]
pub struct Message {
    pub kind: MessageType,
    pub raw_type: u16,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(kind: MessageType, payload: Vec<u8>) -> Self {
        Self { kind, raw_type: kind as u16, payload }
    }
    pub fn empty(kind: MessageType) -> Self {
        Self::new(kind, vec![])
    }
    pub fn fields(&self) -> Fields {
        read_fields(&self.payload).unwrap_or_default()
    }
    pub fn string(&self, field: u32) -> String {
        first_string(&self.fields(), field)
    }
    pub fn bytes(&self, field: u32) -> Vec<u8> {
        first_bytes(&self.fields(), field).map(|b| b.to_vec()).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct Features {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub model: String,
    pub passphrase_protection: bool,
}

impl Features {
    pub fn from_message(m: &Message) -> Self {
        let f = m.fields();
        Self {
            major: first_varint(&f, 2).unwrap_or(0) as u32,
            minor: first_varint(&f, 3).unwrap_or(0) as u32,
            patch: first_varint(&f, 4).unwrap_or(0) as u32,
            model: first_string(&f, 21),
            passphrase_protection: first_varint(&f, 8).unwrap_or(0) != 0,
        }
    }
    pub fn version(&self) -> (u32, u32, u32) {
        (self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
pub struct TxRequest {
    pub request_type: TxRequestType,
    pub request_index: usize,
    pub signature_index: Option<usize>,
    pub signature: Vec<u8>,
    /// Display-order hash of a PREVIOUS transaction the device wants streamed.
    pub tx_hash: Option<Vec<u8>>,
}

impl TxRequest {
    pub fn from_message(m: &Message) -> Self {
        let f = m.fields();
        let request_type = match first_varint(&f, 1).unwrap_or(0) {
            0 => TxRequestType::TxInput,
            1 => TxRequestType::TxOutput,
            2 => TxRequestType::TxMeta,
            3 => TxRequestType::TxFinished,
            n => TxRequestType::Other(n),
        };
        let mut request_index = 0;
        let mut tx_hash = None;
        if let Some(details) = first_bytes(&f, 2) {
            if let Ok(d) = read_fields(details) {
                request_index = first_varint(&d, 1).unwrap_or(0) as usize;
                tx_hash = first_bytes(&d, 2).map(|b| b.to_vec());
            }
        }
        let mut signature_index = None;
        let mut signature = vec![];
        if let Some(serialized) = first_bytes(&f, 3) {
            if let Ok(s) = read_fields(serialized) {
                signature_index = first_varint(&s, 1).map(|n| n as usize);
                signature = first_bytes(&s, 2).map(|b| b.to_vec()).unwrap_or_default();
            }
        }
        Self { request_type, request_index, signature_index, signature, tx_hash }
    }
}

/// Transaction input as streamed to the device during SignTx.
#[derive(Debug, Clone)]
pub struct TxInput {
    pub address_n: Vec<u32>,
    /// display order (big-endian) txid
    pub prev_hash: Vec<u8>,
    pub prev_index: u32,
    pub sequence: u32,
    pub script_type: InputScriptType,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub ownership_proof: Vec<u8>,
    pub commitment_data: Vec<u8>,
}

impl TxInput {
    pub fn to_tx_ack(&self) -> Message {
        let mut input = ProtoWriter::new()
            .repeated_varint_field(1, &self.address_n)
            .bytes_field(2, &self.prev_hash)
            .varint_field(3, self.prev_index as u64)
            .varint_field(5, self.sequence as u64)
            .varint_field(6, self.script_type as u64)
            .varint_field(8, self.amount);
        if self.script_type == InputScriptType::External {
            input = input.bytes_field(14, &self.ownership_proof).bytes_field(15, &self.commitment_data).bytes_field(19, &self.script_pubkey);
        }
        let wrapper = ProtoWriter::new().message_field(2, &input);
        Message::new(MessageType::TxAck, ProtoWriter::new().message_field(1, &wrapper).to_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    pub address_n: Vec<u32>,
    pub address: String,
    pub amount: u64,
    pub script_type: OutputScriptType,
}

impl TxOutput {
    pub fn to_tx_ack(&self) -> Message {
        let mut output = ProtoWriter::new();
        if !self.address_n.is_empty() {
            output = output.repeated_varint_field(2, &self.address_n);
        } else {
            output = output.string_field(1, &self.address);
        }
        output = output.varint_field(3, self.amount).varint_field(4, self.script_type as u64);
        let wrapper = ProtoWriter::new().message_field(5, &output);
        Message::new(MessageType::TxAck, ProtoWriter::new().message_field(1, &wrapper).to_bytes())
    }
}

pub const HARDENED: u32 = 0x8000_0000;
pub const SLIP25_PURPOSE: u32 = 10025 | HARDENED;

pub fn initialize() -> Message {
    Message::empty(MessageType::Initialize)
}
pub fn get_features() -> Message {
    Message::empty(MessageType::GetFeatures)
}
pub fn button_ack() -> Message {
    Message::empty(MessageType::ButtonAck)
}
pub fn passphrase_ack(passphrase: &str) -> Message {
    Message::new(MessageType::PassphraseAck, ProtoWriter::new().string_field(1, passphrase).to_bytes())
}
pub fn passphrase_ack_on_device() -> Message {
    Message::new(MessageType::PassphraseAck, ProtoWriter::new().bool_field(3, true).to_bytes())
}
pub fn do_preauthorized() -> Message {
    Message::empty(MessageType::DoPreauthorized)
}
pub fn unlock_path(address_n: &[u32]) -> Message {
    Message::new(MessageType::UnlockPath, ProtoWriter::new().repeated_varint_field(1, address_n).to_bytes())
}
pub fn get_public_key(address_n: &[u32], coin: &str, script_type: InputScriptType) -> Message {
    Message::new(
        MessageType::GetPublicKey,
        ProtoWriter::new().repeated_varint_field(1, address_n).string_field(4, coin).varint_field(5, script_type as u64).bool_field(6, true).to_bytes(),
    )
}
pub fn get_address(address_n: &[u32], coin: &str, script_type: InputScriptType, show_display: bool) -> Message {
    Message::new(
        MessageType::GetAddress,
        ProtoWriter::new().repeated_varint_field(1, address_n).string_field(2, coin).bool_field(3, show_display).varint_field(5, script_type as u64).to_bytes(),
    )
}
pub fn authorize_coinjoin(coordinator: &str, max_rounds: u64, max_coordinator_fee_rate: u64, max_fee_per_kvbyte: u64, address_n: &[u32], coin: &str) -> Message {
    Message::new(
        MessageType::AuthorizeCoinJoin,
        ProtoWriter::new()
            .string_field(1, coordinator)
            .varint_field(2, max_rounds)
            .varint_field(3, max_coordinator_fee_rate)
            .varint_field(4, max_fee_per_kvbyte)
            .repeated_varint_field(5, address_n)
            .string_field(6, coin)
            .varint_field(7, InputScriptType::SpendTaproot as u64)
            .to_bytes(),
    )
}
pub fn get_ownership_proof(address_n: &[u32], coin: &str, commitment: &[u8]) -> Message {
    Message::new(
        MessageType::GetOwnershipProof,
        ProtoWriter::new()
            .repeated_varint_field(1, address_n)
            .string_field(2, coin)
            .varint_field(3, InputScriptType::SpendTaproot as u64)
            .bool_field(5, true)
            .bytes_field(7, commitment)
            .to_bytes(),
    )
}
pub fn sign_tx(input_count: usize, output_count: usize, coin: &str, version: u32, lock_time: u32, coinjoin_request: Option<(u64, u64, u64)>) -> Message {
    let mut w = ProtoWriter::new()
        .varint_field(1, output_count as u64)
        .varint_field(2, input_count as u64)
        .string_field(3, coin)
        .varint_field(4, version as u64)
        .varint_field(5, lock_time as u64)
        .bool_field(13, false);
    if let Some((fee_rate, no_fee_threshold, min_registrable)) = coinjoin_request {
        w = w.message_field(14, &ProtoWriter::new().varint_field(1, fee_rate).varint_field(2, no_fee_threshold).varint_field(3, min_registrable));
    }
    Message::new(MessageType::SignTx, w.to_bytes())
}
pub fn tx_ack_prev_meta(version: u32, lock_time: u32, inputs: usize, outputs: usize) -> Message {
    let tx = ProtoWriter::new().varint_field(1, version as u64).varint_field(4, lock_time as u64).varint_field(6, inputs as u64).varint_field(7, outputs as u64);
    Message::new(MessageType::TxAck, ProtoWriter::new().message_field(1, &tx).to_bytes())
}
pub fn tx_ack_prev_input(prev_hash: &[u8], prev_index: u32, script_sig: &[u8], sequence: u32) -> Message {
    let input = ProtoWriter::new().bytes_field(2, prev_hash).varint_field(3, prev_index as u64).bytes_field(4, script_sig).varint_field(5, sequence as u64);
    let tx = ProtoWriter::new().message_field(2, &input);
    Message::new(MessageType::TxAck, ProtoWriter::new().message_field(1, &tx).to_bytes())
}
pub fn tx_ack_prev_output(amount: u64, script_pubkey: &[u8]) -> Message {
    let output = ProtoWriter::new().varint_field(1, amount).bytes_field(2, script_pubkey);
    let tx = ProtoWriter::new().message_field(3, &output);
    Message::new(MessageType::TxAck, ProtoWriter::new().message_field(1, &tx).to_bytes())
}

/// Wasabi `FullKeyPath` (`10025'/0'/0'/1'/0/5`) to Trezor `address_n`.
pub fn address_n(full_key_path: &str) -> Option<Vec<u32>> {
    full_key_path
        .trim_start_matches("m/")
        .split('/')
        .map(|p| {
            let hardened = p.ends_with('\'') || p.ends_with('h');
            let n: u32 = p.trim_end_matches(['\'', 'h']).parse().ok()?;
            Some(if hardened { n | HARDENED } else { n })
        })
        .collect()
}

pub fn is_slip25(address_n: &[u32]) -> bool {
    address_n.first() == Some(&SLIP25_PURPOSE)
}
