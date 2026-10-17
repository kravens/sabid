//! Port of WalletWasabi `RoundHasher` + `StrobeHasher`: recomputes a round id from its
//! parameters so a client can refuse a round whose id does not match (tagging defence).
//!
//! Quirks reproduced on purpose: every string field is absorbed under the label
//! `"<field>.Cw"`, ints are 4-byte LE, longs 8-byte LE, timespans are .NET ticks (100 ns),
//! timestamps are unix milliseconds, and the dummy coordination fee is still hashed.

use strobe_rs::{SecParam, Strobe};

pub const PROTOCOL_IDENTIFIER: &[u8] = b"WabiSabi_v1.0";

pub struct StrobeHasher(Strobe);

impl StrobeHasher {
    pub fn new(domain: &str) -> Self {
        let mut h = StrobeHasher(Strobe::new(PROTOCOL_IDENTIFIER, SecParam::B128));
        h.append_str("domain-separator", domain);
        h
    }

    pub fn append_bytes(&mut self, field: &str, value: &[u8]) -> &mut Self {
        self.0.meta_ad(field.as_bytes(), false);
        self.0.meta_ad(&(value.len() as i32).to_le_bytes(), true);
        self.0.ad(value, false);
        self
    }

    /// C# `Append(string fieldName, string str)` labels the value `"{fieldName}.Cw"`.
    pub fn append_str(&mut self, field: &str, value: &str) -> &mut Self {
        self.append_bytes(&format!("{field}.Cw"), value.as_bytes())
    }

    pub fn append_i64(&mut self, field: &str, value: i64) -> &mut Self {
        self.append_bytes(field, &value.to_le_bytes())
    }

    pub fn append_i32(&mut self, field: &str, value: i32) -> &mut Self {
        self.append_bytes(field, &value.to_le_bytes())
    }

    pub fn finish(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.prf(&mut out, false);
        out
    }
}

/// NBitcoin `ScriptType` enum member names, indexed by their integer value.
pub const SCRIPT_TYPE_NAMES: [&str; 8] =
    ["Witness", "P2PKH", "P2SH", "P2PK", "P2WPKH", "P2WSH", "MultiSig", "Taproot"];

/// The round parameters that go into the round id, in Wasabi's primitive units.
#[derive(Debug, Clone)]
pub struct RoundHashInput<'a> {
    pub input_registration_start_unix_ms: i64,
    pub input_registration_timeout_ticks: i64,
    pub connection_confirmation_timeout_ticks: i64,
    pub output_registration_timeout_ticks: i64,
    pub transaction_signing_timeout_ticks: i64,
    pub allowed_input_amounts: (i64, i64),
    /// Sorted ascending, NBitcoin enum values.
    pub allowed_input_types: &'a [u8],
    pub allowed_output_amounts: (i64, i64),
    pub allowed_output_types: &'a [u8],
    pub network: &'a str,
    pub fee_per_k: i64,
    pub max_transaction_size: i32,
    pub min_relay_tx_fee_per_k: i64,
    pub max_amount_credential_value: i64,
    pub max_vsize_credential_value: i64,
    pub max_vsize_allocation_per_alice: i64,
    pub max_suggested_amount: i64,
    pub coordination_identifier: &'a str,
    pub amount_issuer_cw: &'a [u8],
    pub amount_issuer_i: &'a [u8],
    pub vsize_issuer_cw: &'a [u8],
    pub vsize_issuer_i: &'a [u8],
}

/// Returns the hash in the byte order `new uint256(bytes)` consumes (little-endian);
/// Wasabi prints a uint256 reversed, see [`round_id_hex`].
pub fn round_hash(p: &RoundHashInput) -> [u8; 32] {
    let mut h = StrobeHasher::new("round-parameters");
    h.append_i64("input-registration-start", p.input_registration_start_unix_ms)
        .append_i64("input-registration-timeout", p.input_registration_timeout_ticks)
        .append_i64("connection-confirmation-timeout", p.connection_confirmation_timeout_ticks)
        .append_i64("output-registration-timeout", p.output_registration_timeout_ticks)
        .append_i64("transaction-signing-timeout", p.transaction_signing_timeout_ticks)
        .append_i64("allowed-input-amounts-min", p.allowed_input_amounts.0)
        .append_i64("allowed-input-amounts-max", p.allowed_input_amounts.1);
    append_script_types(&mut h, "allowed-input-types", p.allowed_input_types);
    h.append_i64("allowed-output-amounts-min", p.allowed_output_amounts.0)
        .append_i64("allowed-output-amounts-max", p.allowed_output_amounts.1);
    append_script_types(&mut h, "allowed-output-types", p.allowed_output_types);
    h.append_str("network", p.network)
        .append_i64("fee-rate", p.fee_per_k)
        .append_i64("coordination-fee-rate.Rate", 0)
        .append_i64("coordination-fee-rate.PlebsDontPayThreshold", 0)
        .append_i32("max-transaction-size", p.max_transaction_size)
        .append_i64("min-relay-tx-fee", p.min_relay_tx_fee_per_k)
        .append_i64("maximum-amount-credential-value", p.max_amount_credential_value)
        .append_i64("maximum-vsize-credential-value", p.max_vsize_credential_value)
        .append_i64("per-alice-vsize-allocation", p.max_vsize_allocation_per_alice)
        .append_i64("maximum-suggested-amount", p.max_suggested_amount)
        .append_str("coordination-identifier", p.coordination_identifier)
        .append_bytes("amount-credential-issuer-parameters.Cw", p.amount_issuer_cw)
        .append_bytes("amount-credential-issuer-parameters.I", p.amount_issuer_i)
        .append_bytes("vsize-credential-issuer-parameters.Cw", p.vsize_issuer_cw)
        .append_bytes("vsize-credential-issuer-parameters.I", p.vsize_issuer_i);
    h.finish()
}

fn append_script_types(h: &mut StrobeHasher, field: &str, types: &[u8]) {
    for (idx, t) in types.iter().enumerate() {
        let name = SCRIPT_TYPE_NAMES.get(*t as usize).copied().unwrap_or("Unknown");
        h.append_str(&format!("{field}-{idx}"), name);
    }
}

/// The round id as the coordinator prints it (`uint256.ToString()` = reversed hex).
pub fn round_id_hex(p: &RoundHashInput) -> String {
    let mut h = round_hash(p);
    h.reverse();
    hex::encode(h)
}

/// .NET ticks (100 ns) for a whole number of seconds.
pub const fn ticks_from_secs(secs: i64) -> i64 {
    secs * 10_000_000
}
