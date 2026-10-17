//! Classic Trezor Bridge HTTP API (trezord / pytrezord on 21325, Trezor Suite's on 21328).
//! Frames: u16 BE message type || u32 BE length || protobuf payload, hex in the body.

use super::messages::{Message, MessageType};
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_BRIDGE_URIS: [&str; 2] = ["http://127.0.0.1:21325", "http://127.0.0.1:21328"];

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TrezorError(pub String);

impl From<reqwest::Error> for TrezorError {
    fn from(e: reqwest::Error) -> Self {
        TrezorError(format!("Trezor Bridge is not reachable. Make sure Trezor Suite or trezord is running. ({e})"))
    }
}

#[derive(Debug, Clone)]
pub struct BridgeDevice {
    pub path: String,
    pub session: Option<String>,
}

#[derive(Clone)]
pub struct BridgeTransport {
    uri: String,
    http: reqwest::Client,
    protocol_messages: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
}

impl BridgeTransport {
    pub fn new(uri: &str) -> Result<Self, TrezorError> {
        // Device calls block until the user interacts with the device: no request timeout.
        let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(24 * 3600)).connect_timeout(Duration::from_secs(5)).build()?;
        Ok(Self { uri: uri.trim_end_matches('/').to_string(), http, protocol_messages: Default::default() })
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    async fn post(&self, path: &str, body: String) -> Result<String, TrezorError> {
        // Standalone trezord rejects requests without a whitelisted origin with 403.
        let resp = self.http.post(format!("{}/{}", self.uri, path)).header("Origin", "https://wallet.trezor.io").body(body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(TrezorError(format!("Trezor Bridge request '{path}' failed with status {}: {text}", status.as_u16())));
        }
        Ok(text)
    }

    /// Whether the bridge wants a JSON envelope on /call and /read (trezord-node in Trezor Suite).
    async fn ensure_bridge(&self) -> Result<bool, TrezorError> {
        if let Some(known) = *self.protocol_messages.lock().unwrap() {
            return Ok(known);
        }
        let text = self.post("", String::new()).await?;
        let v: Value = serde_json::from_str(&text).map_err(|_| TrezorError(format!("Something answers at {}, but it is not a Trezor Bridge.", self.uri)))?;
        if v.get("version").and_then(Value::as_str).is_none() {
            return Err(TrezorError(format!("Something answers at {}, but it is not a Trezor Bridge.", self.uri)));
        }
        let flag = v.get("protocolMessages").and_then(Value::as_bool).unwrap_or(false);
        *self.protocol_messages.lock().unwrap() = Some(flag);
        Ok(flag)
    }

    pub async fn enumerate(&self) -> Result<Vec<BridgeDevice>, TrezorError> {
        self.ensure_bridge().await?;
        let text = self.post("enumerate", String::new()).await?;
        let v: Value = serde_json::from_str(&text).map_err(|e| TrezorError(format!("bridge enumerate: {e}")))?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|d| Some(BridgeDevice { path: d.get("path")?.as_str()?.to_string(), session: d.get("session").and_then(Value::as_str).map(str::to_string) }))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn acquire(&self, device: &BridgeDevice) -> Result<String, TrezorError> {
        let text = self.post(&format!("acquire/{}/{}", device.path, device.session.as_deref().unwrap_or("null")), String::new()).await?;
        let v: Value = serde_json::from_str(&text).map_err(|e| TrezorError(format!("bridge acquire: {e}")))?;
        v.get("session").and_then(Value::as_str).map(str::to_string).ok_or_else(|| TrezorError("bridge acquire: no session".into()))
    }

    pub async fn release(&self, session: &str) -> Result<(), TrezorError> {
        self.post(&format!("release/{session}"), String::new()).await.map(|_| ())
    }

    async fn post_device_message(&self, path: &str, hex_frame: Option<&str>) -> Result<String, TrezorError> {
        if !self.ensure_bridge().await? {
            return self.post(path, hex_frame.unwrap_or("").to_string()).await;
        }
        let body = match hex_frame {
            None => r#"{"protocol":"bridge"}"#.to_string(),
            Some(h) => format!(r#"{{"protocol":"bridge","data":"{h}"}}"#),
        };
        let text = self.post(path, body).await?;
        let v: Value = serde_json::from_str(&text).map_err(|e| TrezorError(format!("bridge call: {e}")))?;
        Ok(v.get("data").and_then(Value::as_str).unwrap_or("").to_string())
    }

    fn parse_frame(hex_frame: &str) -> Result<Message, TrezorError> {
        let frame = hex::decode(hex_frame.trim()).map_err(|_| TrezorError("The Trezor or its bridge sent an answer that cannot be read. (frame hex)".into()))?;
        if frame.len() < 6 {
            return Err(TrezorError("The Trezor or its bridge sent an answer that cannot be read. (short frame)".into()));
        }
        let raw_type = u16::from_be_bytes([frame[0], frame[1]]);
        Ok(Message { kind: MessageType::from_u16(raw_type), raw_type, payload: frame[6..].to_vec() })
    }

    pub async fn call(&self, session: &str, message: &Message) -> Result<Message, TrezorError> {
        let mut frame = Vec::with_capacity(6 + message.payload.len());
        frame.extend_from_slice(&message.raw_type.to_be_bytes());
        frame.extend_from_slice(&(message.payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&message.payload);
        let text = self.post_device_message(&format!("call/{session}"), Some(&hex::encode(frame))).await?;
        Self::parse_frame(&text)
    }

    pub async fn read(&self, session: &str) -> Result<Message, TrezorError> {
        let text = self.post_device_message(&format!("read/{session}"), None).await?;
        Self::parse_frame(&text)
    }
}
