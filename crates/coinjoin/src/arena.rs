//! `ArenaClient`, `AliceClient`, `BobClient`: coordinator requests with credential bookkeeping.

use crate::keychain::KeyChain;
use crate::ownership::commitment_data;
use crate::selector::CjCoin;
use crate::units::FeeRate;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wabisabi::{Credential, CredentialClient, IssuerParameters};
use wasabi_proto::{
    ApiError, ConnectionConfirmationRequest, CoordinatorClient, InputRegistrationRequest, InputsRemovalRequest, OutputRegistrationRequest, ReadyToSignRequestRequest,
    ReissueCredentialRequest, RoundState, TransactionSignaturesRequest,
};

#[derive(Debug, thiserror::Error)]
pub enum ArenaError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("credential: {0}")]
    Credential(#[from] wabisabi::Error),
    #[error("{0}")]
    Other(String),
}

pub struct ArenaClient {
    pub amount_client: CredentialClient,
    pub vsize_client: CredentialClient,
    pub coordinator_identifier: String,
    pub http: CoordinatorClient,
}

pub struct Issued {
    pub amount: Vec<Credential>,
    pub vsize: Vec<Credential>,
}

impl ArenaClient {
    pub fn new(round: &RoundState, coordinator_identifier: &str, http: CoordinatorClient) -> Result<Self, ArenaError> {
        let p = round.parameters();
        let amount_params = IssuerParameters::from_hex(&round.amount_credential_issuer_parameters.cw, &round.amount_credential_issuer_parameters.i)?;
        let vsize_params = IssuerParameters::from_hex(&round.vsize_credential_issuer_parameters.cw, &round.vsize_credential_issuer_parameters.i)?;
        Ok(Self {
            amount_client: CredentialClient::new(amount_params, p.max_amount_credential_value),
            vsize_client: CredentialClient::new(vsize_params, p.max_vsize_credential_value()),
            coordinator_identifier: coordinator_identifier.to_string(),
            http,
        })
    }

    pub async fn register_input(&self, round_id: &str, outpoint_hex: &str, ownership_proof_hex: &str) -> Result<(String, Issued), ArenaError> {
        let zero_amount = self.amount_client.create_request_for_zero_amount()?;
        let zero_vsize = self.vsize_client.create_request_for_zero_amount()?;
        let resp = self
            .http
            .register_input(&InputRegistrationRequest {
                round_id: round_id.to_string(),
                input: outpoint_hex.to_string(),
                ownership_proof: ownership_proof_hex.to_string(),
                zero_amount_credential_requests: zero_amount.request,
                zero_vsize_credential_requests: zero_vsize.request,
            })
            .await?;
        let amount = self.amount_client.handle_response(&resp.amount_credentials, &zero_amount.validation)?;
        let vsize = self.vsize_client.handle_response(&resp.vsize_credentials, &zero_vsize.validation)?;
        Ok((resp.alice_id, Issued { amount, vsize }))
    }

    pub async fn remove_input(&self, round_id: &str, alice_id: &str) -> Result<(), ArenaError> {
        Ok(self.http.remove_input(&InputsRemovalRequest { round_id: round_id.to_string(), alice_id: alice_id.to_string() }).await?)
    }

    /// Returns `(confirmed, issued)`; before the confirmation phase only zero credentials come back.
    pub async fn confirm_connection(
        &self,
        round_id: &str,
        alice_id: &str,
        amounts_to_request: &[i64],
        vsizes_to_request: &[i64],
        amount_to_present: &[Credential],
        vsize_to_present: &[Credential],
    ) -> Result<(bool, Issued), ArenaError> {
        let real_amount = self.amount_client.create_request(amounts_to_request, amount_to_present)?;
        let real_vsize = self.vsize_client.create_request(vsizes_to_request, vsize_to_present)?;
        let zero_amount = self.amount_client.create_request_for_zero_amount()?;
        let zero_vsize = self.vsize_client.create_request_for_zero_amount()?;
        let resp = self
            .http
            .confirm_connection(&ConnectionConfirmationRequest {
                round_id: round_id.to_string(),
                alice_id: alice_id.to_string(),
                zero_amount_credential_requests: zero_amount.request,
                real_amount_credential_requests: real_amount.request,
                zero_vsize_credential_requests: zero_vsize.request,
                real_vsize_credential_requests: real_vsize.request,
            })
            .await?;
        let zero_amount_creds = self.amount_client.handle_response(&resp.zero_amount_credentials, &zero_amount.validation)?;
        let zero_vsize_creds = self.vsize_client.handle_response(&resp.zero_vsize_credentials, &zero_vsize.validation)?;
        if let (Some(ra), Some(rv)) = (&resp.real_amount_credentials, &resp.real_vsize_credentials) {
            let mut amount = self.amount_client.handle_response(ra, &real_amount.validation)?;
            let mut vsize = self.vsize_client.handle_response(rv, &real_vsize.validation)?;
            amount.extend(zero_amount_creds);
            vsize.extend(zero_vsize_creds);
            return Ok((true, Issued { amount, vsize }));
        }
        Ok((false, Issued { amount: zero_amount_creds, vsize: zero_vsize_creds }))
    }

    pub async fn reissue(
        &self,
        round_id: &str,
        amounts_to_request: &[i64],
        vsizes_to_request: &[i64],
        amount_to_present: &[Credential],
        vsize_to_present: &[Credential],
    ) -> Result<Issued, ArenaError> {
        let presented_amount: i64 = amount_to_present.iter().map(|c| c.value()).sum();
        if amounts_to_request.iter().sum::<i64>() != presented_amount {
            return Err(ArenaError::Other("Reissuance amounts sum must equal the sum of the presented ones.".into()));
        }
        let presented_vsize: i64 = vsize_to_present.iter().map(|c| c.value()).sum();
        if vsizes_to_request.iter().sum::<i64>() > presented_vsize {
            return Err(ArenaError::Other("Reissuance vsizes sum can not be greater than the sum of the presented ones.".into()));
        }
        let real_vsize = self.vsize_client.create_request(vsizes_to_request, vsize_to_present)?;
        let real_amount = self.amount_client.create_request(amounts_to_request, amount_to_present)?;
        let zero_amount = self.amount_client.create_request_for_zero_amount()?;
        let zero_vsize = self.vsize_client.create_request_for_zero_amount()?;
        let resp = self
            .http
            .reissue(&ReissueCredentialRequest {
                round_id: round_id.to_string(),
                real_amount_credential_requests: real_amount.request,
                real_vsize_credential_requests: real_vsize.request,
                zero_amount_credential_requests: zero_amount.request,
                zero_vsize_credentials_requests: zero_vsize.request,
            })
            .await?;
        let mut amount = self.amount_client.handle_response(&resp.real_amount_credentials, &real_amount.validation)?;
        let mut vsize = self.vsize_client.handle_response(&resp.real_vsize_credentials, &real_vsize.validation)?;
        amount.extend(self.amount_client.handle_response(&resp.zero_amount_credentials, &zero_amount.validation)?);
        vsize.extend(self.vsize_client.handle_response(&resp.zero_vsize_credentials, &zero_vsize.validation)?);
        Ok(Issued { amount, vsize })
    }

    pub async fn register_output(&self, round_id: &str, script_asm: &str, amount_to_present: &[Credential], vsize_to_present: &[Credential]) -> Result<(), ArenaError> {
        let amount = self.amount_client.create_request(&[], amount_to_present)?;
        let vsize = self.vsize_client.create_request(&[], vsize_to_present)?;
        Ok(self
            .http
            .register_output(&OutputRegistrationRequest { round_id: round_id.to_string(), script: script_asm.to_string(), amount_credential_requests: amount.request, vsize_credential_requests: vsize.request })
            .await?)
    }

    pub async fn sign_transaction(&self, round_id: &str, input_index: u32, witness_hex: &str) -> Result<(), ArenaError> {
        Ok(self.http.sign_transaction(&TransactionSignaturesRequest { round_id: round_id.to_string(), input_index, witness: witness_hex.to_string() }).await?)
    }

    pub async fn ready_to_sign(&self, round_id: &str, alice_id: &str) -> Result<(), ArenaError> {
        Ok(self.http.ready_to_sign(&ReadyToSignRequestRequest { round_id: round_id.to_string(), alice_id: alice_id.to_string() }).await?)
    }
}

pub struct AliceClient {
    pub alice_id: String,
    pub round_id: String,
    pub arena: ArenaClient,
    pub coin: CjCoin,
    pub fee_rate: FeeRate,
    pub issued_amount: Vec<Credential>,
    pub issued_vsize: Vec<Credential>,
    pub max_vsize_allocation: i64,
    pub confirmation_timeout: Duration,
    pub last_successful_confirmation: Instant,
}

impl AliceClient {
    pub fn effective_value(&self) -> i64 {
        self.coin.effective_value(self.fee_rate)
    }

    pub async fn register(round: &RoundState, arena: ArenaClient, coin: CjCoin, key_chain: &Arc<dyn KeyChain>) -> Result<Self, ArenaError> {
        let p = round.parameters();
        let commitment = commitment_data(&arena.coordinator_identifier, &round.id).map_err(|e| ArenaError::Other(e.to_string()))?;
        let proof = {
            // Device key chains block on USB for up to a minute; keep that off the async workers.
            let (kc, script, c) = (key_chain.clone(), coin.script.clone(), commitment.clone());
            tokio::task::spawn_blocking(move || kc.get_ownership_proof(&script, &c)).await.map_err(|e| ArenaError::Other(e.to_string()))?.map_err(|e| ArenaError::Other(e.to_string()))?
        };
        let outpoint_hex = wasabi_proto::script::outpoint_to_hex(&coin.outpoint);
        let (alice_id, issued) = arena.register_input(&round.id, &outpoint_hex, &hex::encode_upper(proof.to_bytes())).await?;
        tracing::info!("round {}: registered {}", &round.id[..8], coin.outpoint);
        Ok(Self {
            alice_id,
            round_id: round.id.clone(),
            arena,
            coin,
            fee_rate: FeeRate::from_fee_per_k(p.mining_fee_rate),
            issued_amount: issued.amount,
            issued_vsize: issued.vsize,
            max_vsize_allocation: p.max_vsize_allocation_per_alice,
            confirmation_timeout: p.connection_confirmation_timeout.0 / 2,
            last_successful_confirmation: Instant::now(),
        })
    }

    /// One connection confirmation attempt (`TryConfirmConnectionAsync`); true once the coordinator
    /// issued the real credentials.
    pub async fn try_confirm(&mut self) -> Result<bool, ArenaError> {
        let amounts = [self.effective_value()];
        let vsizes = [self.max_vsize_allocation - self.coin.script_type.input_vsize()];
        let (confirmed, issued) = self.arena.confirm_connection(&self.round_id, &self.alice_id, &amounts, &vsizes, &self.issued_amount, &self.issued_vsize).await?;
        self.issued_amount = issued.amount;
        self.issued_vsize = issued.vsize;
        self.last_successful_confirmation = Instant::now();
        Ok(confirmed)
    }

    pub async fn try_unregister(&self) {
        match tokio::time::timeout(Duration::from_secs(7), self.arena.remove_input(&self.round_id, &self.alice_id)).await {
            Ok(Ok(())) => tracing::info!("round {}: unregistered {}", &self.round_id[..8], self.coin.outpoint),
            Ok(Err(e)) => tracing::debug!("unregistration failed for {}: {e}", self.coin.outpoint),
            Err(_) => tracing::debug!("unregistration of {} timed out", self.coin.outpoint),
        }
    }
}

pub struct BobClient {
    pub round_id: String,
    pub arena: ArenaClient,
}

impl BobClient {
    pub async fn register_output(&self, script_asm: &str, amount: &[Credential], vsize: &[Credential]) -> Result<(), ArenaError> {
        self.arena.register_output(&self.round_id, script_asm, amount, vsize).await
    }
    pub async fn reissue(&self, amounts: &[i64], vsizes: &[i64], amount: &[Credential], vsize: &[Credential]) -> Result<Issued, ArenaError> {
        self.arena.reissue(&self.round_id, amounts, vsizes, amount, vsize).await
    }
}
