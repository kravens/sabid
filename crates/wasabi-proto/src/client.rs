//! HTTP client for the coordinator (`WabiSabiHttpApiClient`). One client per identity so
//! each alice/bob gets its own Tor circuit (SOCKS5 username isolation).

use crate::models::*;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("coordinator protocol error {error_code}: {description}")]
    Protocol { error_code: String, description: String, exception_data: Option<ExceptionData> },
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("bad json: {0}")]
    Json(#[from] serde_json::Error),
}

impl ApiError {
    pub fn error_code(&self) -> Option<&str> {
        match self {
            ApiError::Protocol { error_code, .. } => Some(error_code),
            _ => None,
        }
    }
    pub fn wrong_phase(&self) -> Option<Phase> {
        match self {
            ApiError::Protocol { exception_data: Some(ExceptionData::WrongPhaseExceptionData { current_phase }), .. } => {
                Phase::from_i32(*current_phase)
            }
            _ => None,
        }
    }
    pub fn banned_until(&self) -> Option<chrono::DateTime<chrono::FixedOffset>> {
        match self {
            ApiError::Protocol { exception_data: Some(ExceptionData::InputBannedExceptionData { banned_until }), .. } => {
                Some(*banned_until)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// e.g. `127.0.0.1:37150`
    pub socks5: String,
}

#[derive(Clone)]
pub struct CoordinatorClient {
    base: String,
    http: reqwest::Client,
}

impl CoordinatorClient {
    /// `identity` selects the Tor circuit (ignored without a proxy).
    pub fn new(base_uri: &str, proxy: Option<&ProxyConfig>, identity: &str) -> Result<Self, ApiError> {
        let mut b = reqwest::Client::builder()
            .user_agent("")
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(45));
        if let Some(p) = proxy {
            // socks5h: the proxy resolves the host, so onion coordinators work and no DNS leaks.
            let url = format!("socks5h://{}:{}@{}", identity, "sabid", p.socks5);
            b = b.proxy(reqwest::Proxy::all(url)?);
        }
        Ok(Self { base: base_uri.trim_end_matches('/').to_string(), http: b.build()? })
    }

    async fn post_raw<T: Serialize>(&self, action: &str, req: &T) -> Result<String, ApiError> {
        let url = format!("{}/wabisabi/{}", self.base, action);
        let body = serde_json::to_string(req)?;
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            if let Ok(e) = serde_json::from_str::<Error>(&text) {
                return Err(ApiError::Protocol {
                    error_code: e.error_code,
                    description: e.description,
                    exception_data: e.exception_data,
                });
            }
            return Err(ApiError::Http { status: status.as_u16(), body: text });
        }
        Ok(text)
    }

    async fn post<T: Serialize, R: DeserializeOwned>(&self, action: &str, req: &T) -> Result<R, ApiError> {
        let text = self.post_raw(action, req).await?;
        Ok(serde_json::from_str(&text)?)
    }

    pub async fn get_status(&self, req: &RoundStateRequest) -> Result<RoundStateResponse, ApiError> {
        self.post("status", req).await
    }
    pub async fn register_input(&self, req: &InputRegistrationRequest) -> Result<InputRegistrationResponse, ApiError> {
        self.post("input-registration", req).await
    }
    pub async fn remove_input(&self, req: &InputsRemovalRequest) -> Result<(), ApiError> {
        self.post_raw("input-unregistration", req).await.map(|_| ())
    }
    pub async fn confirm_connection(
        &self,
        req: &ConnectionConfirmationRequest,
    ) -> Result<ConnectionConfirmationResponse, ApiError> {
        self.post("connection-confirmation", req).await
    }
    pub async fn register_output(&self, req: &OutputRegistrationRequest) -> Result<(), ApiError> {
        self.post_raw("output-registration", req).await.map(|_| ())
    }
    pub async fn reissue(&self, req: &ReissueCredentialRequest) -> Result<ReissueCredentialResponse, ApiError> {
        self.post("credential-issuance", req).await
    }
    pub async fn sign_transaction(&self, req: &TransactionSignaturesRequest) -> Result<(), ApiError> {
        self.post_raw("transaction-signature", req).await.map(|_| ())
    }
    pub async fn ready_to_sign(&self, req: &ReadyToSignRequestRequest) -> Result<(), ApiError> {
        self.post_raw("ready-to-sign", req).await.map(|_| ())
    }
    pub async fn human_monitor(&self) -> Result<HumanMonitorResponse, ApiError> {
        let url = format!("{}/wabisabi/human-monitor", self.base);
        let text = self.http.get(&url).send().await?.error_for_status()?.text().await?;
        Ok(serde_json::from_str(&text)?)
    }
}
