//! `sabid mcp`: a Model Context Protocol server on stdio (newline-delimited JSON-RPC 2.0) that
//! exposes the daemon's wallet RPC as tools for agents. It is a thin client of a running daemon.

use serde_json::{json, Value};
use std::io::{BufRead, Write};

struct Tool {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

fn tools() -> Vec<Tool> {
    let wallet_prop = json!({"wallet": {"type": "string", "description": "wallet name (file name without .json)"}});
    vec![
        Tool { name: "getstatus", description: "Daemon status: Tor, best block height, filters left, network.", schema: json!({"type": "object", "properties": {}}) },
        Tool { name: "listwallets", description: "Wallet files the daemon can load.", schema: json!({"type": "object", "properties": {}}) },
        Tool { name: "loadwallet", description: "Load (and start syncing) a wallet.", schema: json!({"type": "object", "properties": wallet_prop, "required": ["wallet"]}) },
        Tool { name: "getwalletinfo", description: "Wallet info: loaded, balance (sat), coinjoin status, unlocked (soft wallets), device settings, accounts.", schema: json!({"type": "object", "properties": wallet_prop, "required": ["wallet"]}) },
        Tool { name: "listunspentcoins", description: "Unspent coins with amount (sat), anonymity score, label, confirmations.", schema: json!({"type": "object", "properties": wallet_prop, "required": ["wallet"]}) },
        Tool { name: "gethistory", description: "Transaction history (amount delta in sat, height, coinjoin flag).", schema: json!({"type": "object", "properties": wallet_prop, "required": ["wallet"]}) },
        Tool {
            name: "getnewaddress",
            description: "A fresh receive address; a label is required.",
            schema: json!({"type": "object", "properties": {"wallet": {"type": "string"}, "label": {"type": "string"}, "taproot": {"type": "boolean", "default": true}}, "required": ["wallet", "label"]}),
        },
        Tool {
            name: "startcoinjoin",
            description: "Start coinjoining a wallet. A soft wallet must be unlocked on the daemon host first (`sabid unlock --wallet NAME`, see getwalletinfo.unlocked); a hardware wallet asks on the device. No password is ever passed here.",
            schema: json!({"type": "object", "properties": {"wallet": {"type": "string"}, "stopWhenAllMixed": {"type": "boolean", "default": true}, "overridePlebStop": {"type": "boolean", "default": true}}, "required": ["wallet"]}),
        },
        Tool { name: "stopcoinjoin", description: "Stop coinjoining a wallet (after the critical phase).", schema: json!({"type": "object", "properties": wallet_prop, "required": ["wallet"]}) },
        Tool { name: "enumeratedevices", description: "Hardware wallets reachable through the Trezor bridge.", schema: json!({"type": "object", "properties": {}}) },
        Tool {
            name: "rpc",
            description: "Any Wasabi-compatible JSON-RPC method on the daemon (method, params array or object, optional wallet).",
            schema: json!({"type": "object", "properties": {"method": {"type": "string"}, "params": {}, "wallet": {"type": "string"}}, "required": ["method"]}),
        },
    ]
}

pub struct McpClient {
    pub base: String,
    pub user: String,
    pub password: String,
}

impl McpClient {
    async fn call(&self, method: &str, params: Value, wallet: Option<&str>) -> Result<Value, String> {
        let target = match wallet {
            Some(w) => format!("{}/{}/", self.base.trim_end_matches('/'), w),
            None => self.base.clone(),
        };
        let body = json!({"jsonrpc": "2.0", "id": "mcp", "method": method, "params": params});
        let mut req = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().map_err(|e| e.to_string())?.post(&target).body(body.to_string());
        if !self.user.is_empty() {
            req = req.basic_auth(&self.user, Some(&self.password));
        }
        let text = req.send().await.map_err(|e| format!("daemon not reachable at {}: {e}", self.base))?.text().await.map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("bad daemon answer: {e}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(err.get("message").and_then(Value::as_str).unwrap_or("error").to_string());
        }
        let result = v.get("result").cloned().unwrap_or(Value::Null);
        if let Some(what) = crate::secrets::looks_secret(&result) {
            return Err(format!("refused: the daemon answer contained {what}"));
        }
        Ok(result)
    }

    async fn handle_tool(&self, name: &str, args: &Value) -> Result<Value, String> {
        let wallet = args.get("wallet").and_then(Value::as_str);
        let need_wallet = || wallet.ok_or_else(|| "wallet is required".to_string());
        match name {
            "getstatus" | "listwallets" => self.call(name, json!([]), None).await,
            "enumeratedevices" => self.call(name, json!([]), None).await,
            "loadwallet" => self.call("loadwallet", json!([need_wallet()?]), None).await,
            "getwalletinfo" | "listunspentcoins" | "gethistory" | "stopcoinjoin" => self.call(name, json!([]), Some(need_wallet()?)).await,
            "getnewaddress" => {
                let label = args.get("label").and_then(Value::as_str).ok_or("label is required")?;
                let taproot = args.get("taproot").and_then(Value::as_bool).unwrap_or(true);
                self.call("getnewaddress", json!([label, taproot]), Some(need_wallet()?)).await
            }
            "startcoinjoin" => {
                let stop = args.get("stopWhenAllMixed").and_then(Value::as_bool).unwrap_or(true);
                let pleb = args.get("overridePlebStop").and_then(Value::as_bool).unwrap_or(true);
                self.call("startcoinjoin", json!(["", stop, pleb]), Some(need_wallet()?)).await
            }
            "rpc" => {
                let method = args.get("method").and_then(Value::as_str).ok_or("method is required")?;
                let mut params = args.get("params").cloned().unwrap_or(json!([]));
                crate::secrets::agent_call(method, &mut params)?;
                self.call(method, params, wallet).await
            }
            _ => Err(format!("unknown tool {name}")),
        }
    }

    pub async fn serve_stdio(&self) -> anyhow::Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    writeln!(stdout, "{}", json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}}))?;
                    continue;
                }
            };
            let id = req.get("id").cloned();
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let result: Result<Value, (i64, String)> = match method {
                "initialize" => Ok(json!({
                    "protocolVersion": params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2025-06-18"),
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "sabid", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Wasabi-compatible coinjoin daemon. Amounts are satoshis. startcoinjoin on a hardware wallet needs the user to confirm on the device."
                })),
                "ping" => Ok(json!({})),
                "tools/list" => Ok(json!({"tools": tools().iter().map(|t| json!({"name": t.name, "description": t.description, "inputSchema": t.schema})).collect::<Vec<_>>()})),
                "tools/call" => {
                    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                    let args = params.get("arguments").cloned().unwrap_or(json!({}));
                    match self.handle_tool(name, &args).await {
                        Ok(v) => Ok(json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}], "isError": false})),
                        Err(e) => Ok(json!({"content": [{"type": "text", "text": e}], "isError": true})),
                    }
                }
                m if m.starts_with("notifications/") => continue,
                _ => Err((-32601, format!("Method not found: {method}"))),
            };
            if id.is_none() {
                continue;
            }
            let resp = match result {
                Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
                Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
            };
            writeln!(stdout, "{resp}")?;
            stdout.flush()?;
        }
        Ok(())
    }
}
