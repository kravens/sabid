//! RPC methods, result keys as in `WasabiJsonRpcService`.

use crate::rpc::{Ctx, Params, RpcError};
use serde_json::{json, Value};
use wallet::KeyState;

pub async fn call(ctx: &Ctx, method: &str, p: Params) -> Result<Value, RpcError> {
    let d = &ctx.daemon;
    match method {
        "getstatus" => {
            let (tip_height, tip_hash, count) = {
                let f = d.filters.lock().await;
                let tip = f.tip();
                (tip.as_ref().map(|t| t.height).unwrap_or(0), tip.as_ref().map(|t| t.block_hash.to_string()).unwrap_or_default(), f.count())
            };
            let node_height = *d.node_height.read().await;
            let left = node_height.map(|n| n.saturating_sub(tip_height)).unwrap_or(0);
            let tor_status = if !d.tor_enabled { "Turned off" } else if d.socks.is_some() { "Running" } else { "Not running" };
            Ok(json!({
                "torStatus": tor_status,
                "onionService": "Unavailable",
                "bestBlockchainHeight": tip_height.to_string(),
                "bestBlockchainHash": tip_hash,
                "filtersCount": count,
                "filtersLeft": left,
                "network": network_name(d.network),
                "exchangeRate": 0,
                "peers": d.bitcoind.as_ref().map(|b| vec![json!({"isConnected": node_height.is_some(), "lastSeen": chrono::Utc::now().to_rfc3339(), "endpoint": b.endpoint(), "userAgent": "bitcoind rpc"})]).unwrap_or_default(),
            }))
        }
        "listwallets" => Ok(Value::Array(d.wallet_files().into_iter().map(|n| json!({"walletName": n})).collect())),
        "loadwallet" | "selectwallet" => {
            let name = p.str(0, "walletName")?;
            d.load_wallet(&name).await?;
            Ok(Value::Null)
        }
        "getwalletinfo" => {
            let w = ctx.wallet().await?;
            let lw = w.lock().await;
            let km = &lw.km;
            let mut info = json!({
                "walletName": km.wallet_name(),
                "walletFile": km.path.to_string_lossy(),
                "loaded": lw.loaded,
                "masterKeyFingerprint": km.master_fingerprint(),
                "anonScoreTarget": km.i64_field("AnonScoreTarget", 10),
                "isWatchOnly": km.is_watch_only(),
                "isHardwareWallet": km.is_hardware_wallet(),
                "isAutoCoinjoin": km.bool_field("AutoCoinJoin", false),
                "isNonPrivateCoinIsolation": km.bool_field("RedCoinIsolation", false),
                "onlyUsePrivateFundsForPayments": km.bool_field("OnlyUsePrivateFundsForPayments", false),
                "coinjoinSignedByDevice": km.i64_field("CoinJoinVendor", 0) != 0,
                "coinjoinDeviceVendor": vendor_name(km.i64_field("CoinJoinVendor", 0)),
                "coinjoinDeviceMaxRounds": km.i64_field("CoinJoinDeviceMaxRounds", 50),
                "coinjoinDeviceMaxMiningFeeRate": km.f64_field("CoinJoinDeviceMaxMiningFeeRate", 5.0),
                "accounts": accounts(km),
            });
            if lw.loaded {
                info["balance"] = json!(lw.state.balance());
                info["coinjoinStatus"] = json!(lw.coinjoin_status);
            }
            if let Some((h, tip)) = lw.sync_progress {
                info["syncProgress"] = json!({"height": h, "tip": tip});
            }
            if let Some(e) = &lw.last_error {
                info["lastError"] = json!(e);
            }
            Ok(info)
        }
        "listunspentcoins" | "listcoins" => {
            let w = ctx.wallet().await?;
            let lw = w.lock().await;
            let tip = d.filters.lock().await.tip_height().unwrap_or(0);
            let all = method == "listcoins";
            Ok(Value::Array(
                lw.state
                    .coins
                    .iter()
                    .filter(|c| all || !c.is_spent())
                    .map(|c| {
                        let address = bitcoin::Address::from_script(&c.script, d.network).map(|a| a.to_string()).unwrap_or_default();
                        let mut v = json!({
                            "txid": c.outpoint.txid.to_string(),
                            "index": c.outpoint.vout,
                            "amount": c.amount,
                            "anonymityScore": c.anonymity_set,
                            "confirmed": true,
                            "confirmations": tip.saturating_sub(c.height) + 1,
                            "keyPath": c.key_path,
                            "address": address,
                        });
                        if all {
                            v["spentBy"] = c.spender.map(|t| json!(t.to_string())).unwrap_or(Value::Null);
                        } else {
                            v["label"] = json!(c.label);
                            v["excludedFromCoinjoin"] = json!(c.excluded_from_coinjoin);
                        }
                        v
                    })
                    .collect(),
            ))
        }
        "gethistory" => {
            let w = ctx.wallet().await?;
            let lw = w.lock().await;
            Ok(Value::Array(
                lw.state
                    .history
                    .iter()
                    .map(|t| {
                        json!({
                            "datetime": chrono::DateTime::from_timestamp(t.time, 0).map(|d| d.to_rfc3339()).unwrap_or_default(),
                            "height": t.height.to_string(),
                            "amount": t.amount,
                            "label": t.labels,
                            "tx": t.txid.to_string(),
                            "islikelycoinjoin": t.is_own_coinjoin,
                        })
                    })
                    .collect(),
            ))
        }
        "getnewaddress" => {
            let label = p.str(0, "label")?;
            if label.trim().is_empty() {
                return Err(RpcError::invalid_params("label is required"));
            }
            let taproot = p.bool_or(1, "taproot", true);
            let w = ctx.wallet().await?;
            let mut lw = w.lock().await;
            let idx = lw.km.next_receive_key(label.trim(), taproot).ok_or_else(|| RpcError::internal("Taproot is not supported in this wallet."))?;
            lw.km.save().map_err(RpcError::internal)?;
            let k = &lw.km.keys[idx];
            Ok(json!({
                "address": k.address(d.network).map(|a| a.to_string()).unwrap_or_default(),
                "keyPath": k.path,
                "label": k.label,
                "publicKey": k.pubkey.to_string(),
                "scriptPubKey": hex::encode(k.script.as_bytes()),
            }))
        }
        "listkeys" => {
            let w = ctx.wallet().await?;
            let lw = w.lock().await;
            Ok(Value::Array(
                lw.km
                    .keys
                    .iter()
                    .filter(|k| k.kind != wallet::AccountKind::Other)
                    .map(|k| {
                        json!({
                            "fullKeyPath": k.path,
                            "internal": k.is_internal,
                            "keyState": k.state as i64,
                            "label": k.label,
                            "scriptPubKey": wasabi_proto::script::script_to_asm(&k.script),
                            "pubkey": k.pubkey.to_string(),
                            "pubKeyHash": k.pubkey.pubkey_hash().to_string(),
                            "address": k.address(d.network).map(|a| a.to_string()).unwrap_or_default(),
                        })
                    })
                    .collect(),
            ))
        }
        "excludefromcoinjoin" => {
            let txid: bitcoin::Txid = p.str(0, "transactionId")?.parse().map_err(|_| RpcError::invalid_params("transactionId"))?;
            let n = p.i64(1, "n")? as u32;
            let exclude = p.bool_or(2, "exclude", true);
            let w = ctx.wallet().await?;
            let mut lw = w.lock().await;
            let op = bitcoin::OutPoint { txid, vout: n };
            lw.km.set_excluded(op, exclude);
            lw.km.save().map_err(RpcError::internal)?;
            for c in &mut lw.state.coins {
                if c.outpoint == op {
                    c.excluded_from_coinjoin = exclude;
                }
            }
            Ok(Value::Null)
        }
        "getfeerates" => {
            let rates = d.fee_rates.read().await;
            Ok(Value::Object(rates.iter().map(|(k, v)| (k.to_string(), json!(v))).collect()))
        }
        "stop" => {
            d.shutdown.notify_waiters();
            Ok(Value::Null)
        }
        _ => Err(RpcError { code: -32601, message: format!("'{method}' method not found.") }),
    }
}

fn network_name(n: bitcoin::Network) -> &'static str {
    match n {
        bitcoin::Network::Bitcoin => "Main",
        bitcoin::Network::Testnet => "TestNet",
        bitcoin::Network::Regtest => "RegTest",
        bitcoin::Network::Signet => "Signet",
        _ => "Main",
    }
}

fn vendor_name(n: i64) -> &'static str {
    match n {
        1 => "Trezor",
        2 => "Coldcard",
        3 => "Passport",
        4 => "Krux",
        _ => "None",
    }
}

fn accounts(km: &wallet::KeyManager) -> Value {
    let mut a = vec![json!({"name": "segwit", "publicKey": km.segwit_xpub().to_string(), "keyPath": format!("m/{}", km.segwit_account_path())})];
    if let (Some(x), Some(p)) = (km.taproot_xpub(), km.taproot_account_path()) {
        a.push(json!({"name": "taproot", "publicKey": x.to_string(), "keyPath": format!("m/{p}")}));
    }
    Value::Array(a)
}

#[allow(dead_code)]
fn _unused(_: KeyState) {}
