//! Wasabi-compatible JSON-RPC server: HTTP POST on `/` or `/<wallet>/`, Basic auth, JSON-RPC 2.0
//! single or batch, positional or named params, Wasabi's method names and result keys.

use crate::daemon::{Daemon, LoadedWallet};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn internal(msg: impl ToString) -> Self {
        Self { code: -32603, message: msg.to_string() }
    }
    pub fn invalid_params(msg: impl ToString) -> Self {
        Self { code: -32602, message: msg.to_string() }
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        RpcError::internal(e)
    }
}

/// Positional (array) or named (object) parameters, read by position + name like Wasabi binds them.
pub struct Params {
    v: Value,
}

impl Params {
    pub fn get(&self, idx: usize, name: &str) -> Option<&Value> {
        match &self.v {
            Value::Array(a) => a.get(idx),
            Value::Object(o) => o.get(name),
            _ => None,
        }
    }
    pub fn str(&self, idx: usize, name: &str) -> Result<String, RpcError> {
        self.get(idx, name).and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| RpcError::invalid_params(format!("missing parameter '{name}'")))
    }
    pub fn str_opt(&self, idx: usize, name: &str) -> Option<String> {
        self.get(idx, name).and_then(|v| v.as_str()).map(str::to_string)
    }
    pub fn u64_or(&self, idx: usize, name: &str, default: u64) -> u64 {
        self.v.get(idx).or_else(|| self.v.get(name)).and_then(Value::as_u64).unwrap_or(default)
    }
    pub fn bool_or(&self, idx: usize, name: &str, default: bool) -> bool {
        self.get(idx, name).and_then(|v| v.as_bool()).unwrap_or(default)
    }
    pub fn i64(&self, idx: usize, name: &str) -> Result<i64, RpcError> {
        self.get(idx, name).and_then(|v| v.as_i64()).ok_or_else(|| RpcError::invalid_params(format!("missing parameter '{name}'")))
    }
}

pub struct Ctx {
    pub daemon: Arc<Daemon>,
    pub wallet_name: Option<String>,
}

impl Ctx {
    pub async fn wallet(&self) -> Result<Arc<tokio::sync::Mutex<LoadedWallet>>, RpcError> {
        let name = self.wallet_name.as_deref().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
        self.daemon.get_wallet(name).await.ok_or_else(|| RpcError::internal(format!("Wallet '{name}' is not loaded.")))
    }
}

pub async fn dispatch(ctx: &Ctx, method: &str, params: Params) -> Result<Value, RpcError> {
    crate::methods::call(ctx, method, params).await
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": id})
}

async fn handle_one(ctx: &Ctx, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return error_response(id, -32600, "Invalid Request");
    };
    let params = Params { v: req.get("params").cloned().unwrap_or(Value::Array(vec![])) };
    match dispatch(ctx, method, params).await {
        Ok(result) => match crate::secrets::looks_secret(&result) {
            Some(what) => {
                tracing::error!("{method}: refused to answer with {what}");
                error_response(id, -32000, "refused: the answer contained key material")
            }
            None => json!({"jsonrpc": "2.0", "result": result, "id": id}),
        },
        Err(e) => error_response(id, e.code, &e.message),
    }
}

/// Equal without an early exit on the first differing byte (length still shows).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle(daemon: Arc<Daemon>, wallet_name: Option<String>, headers: HeaderMap, body: Bytes) -> Response {
    if !daemon.cfg.json_rpc_user.is_empty() {
        let expected = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", daemon.cfg.json_rpc_user, daemon.cfg.json_rpc_password));
        let ok = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Basic "))
            .map(|b| ct_eq(b.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"sabid\"")], "").into_response();
        }
    }
    let ctx = Ctx { daemon, wallet_name };
    let parsed: Result<Value, _> = serde_json::from_slice(&body);
    let out = match parsed {
        Err(_) => error_response(Value::Null, -32700, "Parse error"),
        Ok(Value::Array(batch)) => {
            let mut results = Vec::with_capacity(batch.len());
            for r in &batch {
                results.push(handle_one(&ctx, r).await);
            }
            Value::Array(results)
        }
        Ok(single) => handle_one(&ctx, &single).await,
    };
    ([(header::CONTENT_TYPE, "application/json-rpc")], out.to_string()).into_response()
}

async fn root(State(d): State<Arc<Daemon>>, headers: HeaderMap, body: Bytes) -> Response {
    handle(d, None, headers, body).await
}

async fn with_wallet(State(d): State<Arc<Daemon>>, Path(wallet): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    handle(d, Some(wallet), headers, body).await
}

pub fn router(daemon: Arc<Daemon>) -> Router {
    Router::new()
        .route("/", post(root))
        .route("/{wallet}", post(with_wallet))
        .route("/{wallet}/", post(with_wallet))
        .with_state(daemon)
}
