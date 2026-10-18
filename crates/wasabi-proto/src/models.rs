//! Coordinator messages, key for key as `WalletWasabi/Serialization/Coordination.cs` writes them.
//! Requests are PascalCase, responses camelCase, the round's `coinjoinState` is PascalCase again.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use wabisabi::wire::{CredentialsResponse, RealCredentialsRequest, ZeroCredentialsRequest};

/// `"0d 0h 21m 0s"`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSpan(pub Duration);

impl TimeSpan {
    pub fn secs(&self) -> i64 {
        self.0.as_secs() as i64
    }
    pub fn ticks(&self) -> i64 {
        self.secs() * 10_000_000
    }
}

impl Serialize for TimeSpan {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let t = self.0.as_secs();
        s.serialize_str(&format!("{}d {}h {}m {}s", t / 86400, (t / 3600) % 24, (t / 60) % 60, t % 60))
    }
}

impl<'de> Deserialize<'de> for TimeSpan {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let mut secs: u64 = 0;
        for part in s.split_whitespace() {
            let (num, mult) = match part.chars().last() {
                Some('d') => (&part[..part.len() - 1], 86400),
                Some('h') => (&part[..part.len() - 1], 3600),
                Some('m') => (&part[..part.len() - 1], 60),
                Some('s') => (&part[..part.len() - 1], 1),
                _ => return Err(serde::de::Error::custom(format!("bad timespan {s}"))),
            };
            let n: u64 = num.trim().parse().map_err(serde::de::Error::custom)?;
            secs = n.checked_mul(mult).and_then(|v| secs.checked_add(v)).ok_or_else(|| serde::de::Error::custom(format!("bad timespan {s}")))?;
        }
        Ok(TimeSpan(Duration::from_secs(secs)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MoneyRange {
    pub min: i64,
    pub max: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RoundParameters {
    pub network: String,
    /// satoshis per 1000 vbytes
    pub mining_fee_rate: i64,
    pub max_suggested_amount: i64,
    pub min_input_count_by_round: i32,
    pub max_input_count_by_round: i32,
    pub allowed_input_amounts: MoneyRange,
    pub allowed_output_amounts: MoneyRange,
    pub allowed_input_types: Vec<u8>,
    pub allowed_output_types: Vec<u8>,
    pub standard_input_registration_timeout: TimeSpan,
    pub connection_confirmation_timeout: TimeSpan,
    pub output_registration_timeout: TimeSpan,
    pub transaction_signing_timeout: TimeSpan,
    pub blame_input_registration_timeout: TimeSpan,
    pub min_amount_credential_value: i64,
    pub max_amount_credential_value: i64,
    pub max_vsize_allocation_per_alice: i64,
    pub coordination_identifier: String,
    #[serde(default)]
    pub delay_transaction_signing: bool,
    /// Not read by Wasabi's decoder (it uses the default); kept so the hash can use it.
    #[serde(default = "default_max_transaction_size")]
    pub max_transaction_size: i32,
    #[serde(default = "default_min_relay_tx_fee")]
    pub min_relay_tx_fee: i64,
}

fn default_max_transaction_size() -> i32 {
    100_000
}
fn default_min_relay_tx_fee() -> i64 {
    1000
}

impl RoundParameters {
    pub fn max_vsize_credential_value(&self) -> i64 {
        self.max_vsize_allocation_per_alice
    }
    pub fn fee_rate_sat_per_vb(&self) -> f64 {
        self.mining_fee_rate as f64 / 1000.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxOut {
    /// NBitcoin `Script.ToString()` asm form, e.g. `"0 <20-byte hex>"` or `"1 <32-byte hex>"`.
    pub script_pub_key: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Coin {
    /// hex of NBitcoin OutPoint bytes: txid (32, little-endian) || vout (4, LE)
    pub outpoint: String,
    pub tx_out: TxOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "Type")]
pub enum RoundEvent {
    RoundCreated {
        #[serde(rename = "RoundParameters")]
        round_parameters: RoundParameters,
    },
    InputAdded {
        #[serde(rename = "Coin")]
        coin: Coin,
        /// hex of the serialized ownership proof
        #[serde(rename = "OwnershipProof")]
        ownership_proof: String,
    },
    OutputAdded {
        #[serde(rename = "Output")]
        output: TxOut,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "Type")]
pub enum CoinjoinState {
    ConstructionState {
        #[serde(rename = "Events")]
        events: Vec<RoundEvent>,
    },
    SigningState {
        #[serde(rename = "Events")]
        events: Vec<RoundEvent>,
        #[serde(rename = "Witnesses", default)]
        witnesses: std::collections::BTreeMap<String, String>,
        #[serde(rename = "IsFullySigned", default)]
        is_fully_signed: bool,
    },
}

impl CoinjoinState {
    pub fn events(&self) -> &[RoundEvent] {
        match self {
            CoinjoinState::ConstructionState { events } | CoinjoinState::SigningState { events, .. } => events,
        }
    }
    pub fn parameters(&self) -> Option<&RoundParameters> {
        self.events().iter().find_map(|e| match e {
            RoundEvent::RoundCreated { round_parameters } => Some(round_parameters),
            _ => None,
        })
    }
    pub fn inputs(&self) -> impl Iterator<Item = (&Coin, &str)> {
        self.events().iter().filter_map(|e| match e {
            RoundEvent::InputAdded { coin, ownership_proof } => Some((coin, ownership_proof.as_str())),
            _ => None,
        })
    }
    pub fn outputs(&self) -> impl Iterator<Item = &TxOut> {
        self.events().iter().filter_map(|e| match e {
            RoundEvent::OutputAdded { output } => Some(output),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum Phase {
    InputRegistration = 0,
    ConnectionConfirmation = 1,
    OutputRegistration = 2,
    TransactionSigning = 3,
    Ended = 4,
}

impl Phase {
    pub fn from_i32(n: i32) -> Option<Phase> {
        Some(match n {
            0 => Phase::InputRegistration,
            1 => Phase::ConnectionConfirmation,
            2 => Phase::OutputRegistration,
            3 => Phase::TransactionSigning,
            4 => Phase::Ended,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndRoundState {
    None = 0,
    AbortedWithError = 1,
    AbortedNotEnoughAlices = 2,
    TransactionBroadcastFailed = 3,
    TransactionBroadcasted = 4,
    NotAllAlicesSign = 5,
    AbortedNotEnoughAlicesSigned = 6,
    AbortedNotAllAlicesConfirmed = 7,
    AbortedLoadBalancing = 8,
}

impl EndRoundState {
    pub fn from_i32(n: i32) -> EndRoundState {
        use EndRoundState::*;
        match n {
            1 => AbortedWithError,
            2 => AbortedNotEnoughAlices,
            3 => TransactionBroadcastFailed,
            4 => TransactionBroadcasted,
            5 => NotAllAlicesSign,
            6 => AbortedNotEnoughAlicesSigned,
            7 => AbortedNotAllAlicesConfirmed,
            8 => AbortedLoadBalancing,
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuerParameters {
    pub cw: String,
    pub i: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundState {
    pub id: String,
    pub blame_of: String,
    pub amount_credential_issuer_parameters: CredentialIssuerParameters,
    pub vsize_credential_issuer_parameters: CredentialIssuerParameters,
    pub phase: i32,
    pub end_round_state: i32,
    pub input_registration_start: chrono::DateTime<chrono::FixedOffset>,
    pub input_registration_timeout: TimeSpan,
    pub coinjoin_state: CoinjoinState,
    #[serde(default)]
    pub input_registration_end: Option<chrono::DateTime<chrono::FixedOffset>>,
    #[serde(default)]
    pub is_blame: bool,
}

impl RoundState {
    pub fn phase(&self) -> Option<Phase> {
        Phase::from_i32(self.phase)
    }
    pub fn end_round_state(&self) -> EndRoundState {
        EndRoundState::from_i32(self.end_round_state)
    }
    pub fn parameters(&self) -> &RoundParameters {
        self.coinjoin_state.parameters().expect("round without RoundCreated event")
    }
    pub fn is_blame(&self) -> bool {
        self.blame_of.chars().any(|c| c != '0')
    }
    pub fn input_registration_end(&self) -> chrono::DateTime<chrono::FixedOffset> {
        chrono::Duration::from_std(self.input_registration_timeout.0)
            .ok()
            .and_then(|d| self.input_registration_start.checked_add_signed(d))
            .unwrap_or(self.input_registration_start)
    }

    /// Recomputes the round id from the parameters (Wasabi `RoundState.IsRoundIdMatching`).
    pub fn computed_id(&self) -> Result<String, hex::FromHexError> {
        let p = self.parameters();
        let a_cw = hex::decode(&self.amount_credential_issuer_parameters.cw)?;
        let a_i = hex::decode(&self.amount_credential_issuer_parameters.i)?;
        let v_cw = hex::decode(&self.vsize_credential_issuer_parameters.cw)?;
        let v_i = hex::decode(&self.vsize_credential_issuer_parameters.i)?;
        let mut in_types = p.allowed_input_types.clone();
        in_types.sort_unstable();
        let mut out_types = p.allowed_output_types.clone();
        out_types.sort_unstable();
        Ok(wabisabi::round_hash::round_id_hex(&wabisabi::round_hash::RoundHashInput {
            input_registration_start_unix_ms: self.input_registration_start.timestamp_millis(),
            input_registration_timeout_ticks: self.input_registration_timeout.ticks(),
            connection_confirmation_timeout_ticks: p.connection_confirmation_timeout.ticks(),
            output_registration_timeout_ticks: p.output_registration_timeout.ticks(),
            transaction_signing_timeout_ticks: p.transaction_signing_timeout.ticks(),
            allowed_input_amounts: (p.allowed_input_amounts.min, p.allowed_input_amounts.max),
            allowed_input_types: &in_types,
            allowed_output_amounts: (p.allowed_output_amounts.min, p.allowed_output_amounts.max),
            allowed_output_types: &out_types,
            network: &p.network,
            fee_per_k: p.mining_fee_rate,
            max_transaction_size: p.max_transaction_size,
            min_relay_tx_fee_per_k: p.min_relay_tx_fee,
            max_amount_credential_value: p.max_amount_credential_value,
            max_vsize_credential_value: p.max_vsize_credential_value(),
            max_vsize_allocation_per_alice: p.max_vsize_allocation_per_alice,
            max_suggested_amount: p.max_suggested_amount,
            coordination_identifier: &p.coordination_identifier,
            amount_issuer_cw: &a_cw,
            amount_issuer_i: &a_i,
            vsize_issuer_cw: &v_cw,
            vsize_issuer_i: &v_i,
        }))
    }

    pub fn is_round_id_matching(&self) -> bool {
        self.computed_id().map(|c| c.eq_ignore_ascii_case(&self.id)).unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RoundStateCheckpoint {
    pub round_id: String,
    pub state_id: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RoundStateRequest {
    pub round_checkpoints: Vec<RoundStateCheckpoint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundStateResponse {
    pub round_states: Vec<RoundState>,
    #[serde(default)]
    pub coin_join_fee_rate_medians: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InputRegistrationRequest {
    pub round_id: String,
    /// hex OutPoint bytes
    pub input: String,
    /// hex serialized ownership proof
    pub ownership_proof: String,
    pub zero_amount_credential_requests: ZeroCredentialsRequest,
    pub zero_vsize_credential_requests: ZeroCredentialsRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputRegistrationResponse {
    pub alice_id: String,
    pub amount_credentials: CredentialsResponse,
    pub vsize_credentials: CredentialsResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionConfirmationRequest {
    pub round_id: String,
    pub alice_id: String,
    pub zero_amount_credential_requests: ZeroCredentialsRequest,
    pub real_amount_credential_requests: RealCredentialsRequest,
    pub zero_vsize_credential_requests: ZeroCredentialsRequest,
    pub real_vsize_credential_requests: RealCredentialsRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionConfirmationResponse {
    pub zero_amount_credentials: CredentialsResponse,
    pub zero_vsize_credentials: CredentialsResponse,
    #[serde(default)]
    pub real_amount_credentials: Option<CredentialsResponse>,
    #[serde(default)]
    pub real_vsize_credentials: Option<CredentialsResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct OutputRegistrationRequest {
    pub round_id: String,
    /// NBitcoin asm form
    pub script: String,
    pub amount_credential_requests: RealCredentialsRequest,
    pub vsize_credential_requests: RealCredentialsRequest,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ReissueCredentialRequest {
    pub round_id: String,
    pub real_amount_credential_requests: RealCredentialsRequest,
    pub real_vsize_credential_requests: RealCredentialsRequest,
    pub zero_amount_credential_requests: ZeroCredentialsRequest,
    pub zero_vsize_credentials_requests: ZeroCredentialsRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueCredentialResponse {
    pub real_amount_credentials: CredentialsResponse,
    pub real_vsize_credentials: CredentialsResponse,
    pub zero_amount_credentials: CredentialsResponse,
    pub zero_vsize_credentials: CredentialsResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InputsRemovalRequest {
    pub round_id: String,
    pub alice_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TransactionSignaturesRequest {
    pub round_id: String,
    pub input_index: u32,
    /// hex of the serialized witness stack
    pub witness: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ReadyToSignRequestRequest {
    pub round_id: String,
    pub alice_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "Type")]
pub enum ExceptionData {
    InputBannedExceptionData {
        #[serde(rename = "BannedUntil")]
        banned_until: chrono::DateTime<chrono::FixedOffset>,
    },
    WrongPhaseExceptionData {
        #[serde(rename = "CurrentPhase")]
        current_phase: i32,
    },
    EmptyExceptionData {},
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    #[serde(rename = "type")]
    pub error_type: String,
    pub error_code: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub exception_data: Option<ExceptionData>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HumanMonitorRound {
    pub round_id: String,
    pub is_blame_round: bool,
    pub input_count: i32,
    pub max_suggested_amount: f64,
    pub input_registration_remaining: TimeSpan,
    pub phase: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HumanMonitorResponse {
    pub round_states: Vec<HumanMonitorRound>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn timespan_rejects_garbage_without_panicking() {
        for bad in ["\"0d 0h 1m 0\u{e9}\"", "\"\u{e9}\"", "\"99999999999999999999d\"", "\"5x\""] {
            assert!(serde_json::from_str::<super::TimeSpan>(bad).is_err(), "{bad}");
        }
        assert_eq!(serde_json::from_str::<super::TimeSpan>("\"0d 0h 21m 0s\"").unwrap().0.as_secs(), 1260);
    }
}
