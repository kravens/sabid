//! Minimal bitcoind JSON-RPC client (what Wasabi 2.6+ uses its node for), over Tor when the
//! endpoint is an onion service.

use bitcoin::consensus::encode::deserialize;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("bitcoind rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("bad response: {0}")]
    Bad(String),
}

#[derive(Clone)]
pub struct Bitcoind {
    url: String,
    auth: Option<(String, String)>,
    http: reqwest::Client,
    proxy: Option<String>,
}

impl Bitcoind {
    /// `endpoint` like `http://host:8332/`; `credentials` is `user:pass` or `cookiefile=/path`.
    pub fn new(endpoint: &str, credentials: &str, socks5: Option<&str>) -> Result<Self, RpcError> {
        let url = if endpoint.contains("://") { endpoint.to_string() } else { format!("http://{endpoint}") };
        let auth = if let Some(path) = credentials.strip_prefix("cookiefile=") {
            let cookie = std::fs::read_to_string(path).map_err(|e| RpcError::Bad(format!("cookie file {path}: {e}")))?;
            cookie.trim().split_once(':').map(|(u, p)| (u.to_string(), p.to_string()))
        } else {
            credentials.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()))
        };
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(300)).connect_timeout(Duration::from_secs(60));
        let is_onion = url.contains(".onion");
        let mut proxy = None;
        if let Some(s) = socks5 {
            if is_onion || !url.contains("127.0.0.1") && !url.contains("localhost") {
                let p = format!("socks5h://sabid-bitcoind:x@{s}");
                b = b.proxy(reqwest::Proxy::all(p.clone())?);
                proxy = Some(p);
            }
        }
        Ok(Self { url, auth, http: b.build()?, proxy })
    }

    pub fn endpoint(&self) -> &str {
        &self.url
    }

    async fn send(&self, body: Value) -> Result<Value, RpcError> {
        let mut req = self.http.post(&self.url).json(&body);
        if let Some((u, p)) = &self.auth {
            req = req.basic_auth(u, Some(p));
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text).map_err(|_| RpcError::Bad(format!("http {status}: {}", text.chars().take(200).collect::<String>())))?;
        Ok(v)
    }

    fn unwrap(v: Value) -> Result<Value, RpcError> {
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Rpc {
                code: e.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: e.get("message").and_then(Value::as_str).unwrap_or("").to_string(),
            });
        }
        v.get("result").cloned().ok_or_else(|| RpcError::Bad("no result".into()))
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let v = self.send(json!({"jsonrpc": "1.0", "id": "sabid", "method": method, "params": params})).await?;
        Self::unwrap(v)
    }

    /// One HTTP round trip for many calls; results in request order.
    pub async fn batch(&self, calls: &[(&str, Value)]) -> Result<Vec<Result<Value, RpcError>>, RpcError> {
        let body: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(i, (m, p))| json!({"jsonrpc": "1.0", "id": i, "method": m, "params": p}))
            .collect();
        let v = self.send(Value::Array(body)).await?;
        let arr = v.as_array().ok_or_else(|| RpcError::Bad("batch response is not an array".into()))?;
        let mut out: Vec<Option<Result<Value, RpcError>>> = (0..calls.len()).map(|_| None).collect();
        for item in arr {
            if let Some(i) = item.get("id").and_then(Value::as_u64) {
                if (i as usize) < out.len() {
                    out[i as usize] = Some(Self::unwrap(item.clone()));
                }
            }
        }
        Ok(out.into_iter().map(|o| o.unwrap_or_else(|| Err(RpcError::Bad("missing batch item".into())))).collect())
    }

    pub async fn get_block_count(&self) -> Result<u32, RpcError> {
        Ok(self.call("getblockcount", json!([])).await?.as_u64().unwrap_or(0) as u32)
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<BlockHash, RpcError> {
        let s = self.call("getblockhash", json!([height])).await?;
        s.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| RpcError::Bad("getblockhash".into()))
    }

    /// `(filter bytes, filter header)`; needs `blockfilterindex=1` on the node.
    pub async fn get_block_filter(&self, hash: &BlockHash) -> Result<(Vec<u8>, [u8; 32]), RpcError> {
        let v = self.call("getblockfilter", json!([hash.to_string(), "basic"])).await?;
        Self::parse_filter(&v)
    }

    pub fn parse_filter(v: &Value) -> Result<(Vec<u8>, [u8; 32]), RpcError> {
        let f = v.get("filter").and_then(Value::as_str).ok_or_else(|| RpcError::Bad("filter".into()))?;
        let h = v.get("header").and_then(Value::as_str).ok_or_else(|| RpcError::Bad("header".into()))?;
        let header: BlockHash = h.parse().map_err(|_| RpcError::Bad("filter header".into()))?;
        Ok((hex::decode(f).map_err(|_| RpcError::Bad("filter hex".into()))?, *header.as_ref()))
    }

    pub async fn get_block(&self, hash: &BlockHash) -> Result<Block, RpcError> {
        // A multi-megabyte body over a Tor stream fails now and then; the second try uses a fresh connection.
        let mut last = RpcError::Bad("getblock".into());
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(5 * attempt as u64)).await;
            }
            let client = if attempt == 0 { self.clone() } else { self.fresh()? };
            match client.call("getblock", json!([hash.to_string(), 0])).await {
                Ok(v) => {
                    let raw = hex::decode(v.as_str().unwrap_or("")).map_err(|_| RpcError::Bad("block hex".into()))?;
                    return deserialize(&raw).map_err(|e| RpcError::Bad(format!("block: {e}")));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Same endpoint, a new client without pooled connections and (through Tor) a new circuit:
    /// the SOCKS username selects the circuit, so a torn-down onion circuit is not reused.
    fn fresh(&self) -> Result<Self, RpcError> {
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(300)).connect_timeout(Duration::from_secs(60)).pool_max_idle_per_host(0);
        if let Some(p) = &self.proxy {
            let nonce: u32 = rand::random();
            let p = p.replace("sabid-bitcoind:", &format!("sabid-bitcoind-{nonce:08x}:"));
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
        Ok(Self { url: self.url.clone(), auth: self.auth.clone(), http: b.build()?, proxy: self.proxy.clone() })
    }

    pub async fn get_block_header_time(&self, hash: &BlockHash) -> Result<i64, RpcError> {
        let v = self.call("getblockheader", json!([hash.to_string(), true])).await?;
        Ok(v.get("time").and_then(Value::as_i64).unwrap_or(0))
    }

    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, RpcError> {
        let v = self.call("getrawtransaction", json!([txid.to_string(), false])).await?;
        let raw = hex::decode(v.as_str().unwrap_or("")).map_err(|_| RpcError::Bad("tx hex".into()))?;
        deserialize(&raw).map_err(|e| RpcError::Bad(format!("tx: {e}")))
    }

    pub async fn send_raw_transaction(&self, tx_hex: &str) -> Result<Txid, RpcError> {
        let v = self.call("sendrawtransaction", json!([tx_hex])).await?;
        v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| RpcError::Bad("sendrawtransaction".into()))
    }

    /// `gettxout` for many outpoints in one round trip: the scriptPubKey of each unspent one.
    pub async fn get_tx_outs(&self, outpoints: &[bitcoin::OutPoint]) -> Result<Vec<Option<bitcoin::ScriptBuf>>, RpcError> {
        let calls: Vec<(&str, Value)> = outpoints.iter().map(|o| ("gettxout", json!([o.txid.to_string(), o.vout, true]))).collect();
        let results = self.batch(&calls).await?;
        let mut out = Vec::with_capacity(results.len());
        for r in results {
            let v = r?;
            let spk = v.get("scriptPubKey").and_then(|s| s.get("hex")).and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).map(bitcoin::ScriptBuf::from_bytes);
            out.push(spk);
        }
        Ok(out)
    }

    /// sat/vB for a confirmation target, if the node has an estimate.
    pub async fn estimate_fee(&self, target: u32) -> Result<Option<f64>, RpcError> {
        let v = self.call("estimatesmartfee", json!([target, "ECONOMICAL"])).await?;
        Ok(v.get("feerate").and_then(Value::as_f64).map(|btc_per_kvb| btc_per_kvb * 100_000.0))
    }
}
