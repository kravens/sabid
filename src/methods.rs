//! RPC methods, result keys as in `WasabiJsonRpcService`.

use crate::rpc::{Ctx, Params, RpcError};
use serde_json::{json, Value};

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
                let status = d.managers.read().await.get(&km.wallet_name()).map(|m| m.status().as_wasabi()).unwrap_or("Idle");
                info["coinjoinStatus"] = json!(status);
            }
            if !km.is_hardware_wallet() && !km.is_watch_only() {
                info["unlocked"] = json!(lw.is_unlocked());
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
            let tip = d.filters.lock().await.tip_height().unwrap_or(0);
            let w = ctx.wallet().await?;
            let lw = w.lock().await;
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
                            "confirmed": c.height != wallet::store::MEMPOOL_HEIGHT,
                            "confirmations": if c.height == wallet::store::MEMPOOL_HEIGHT { 0 } else { tip.saturating_sub(c.height) + 1 },
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
                            "height": if t.height == wallet::store::MEMPOOL_HEIGHT { "Mempool".to_string() } else { t.height.to_string() },
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
        "startcoinjoin" => {
            let password = p.str_opt(0, "password");
            let stop_when_all_mixed = p.bool_or(1, "stopWhenAllMixed", true);
            let override_pleb_stop = p.bool_or(2, "overridePlebStop", true);
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            let w = ctx.wallet().await?;
            if !w.lock().await.loaded {
                return Err(RpcError::internal("Wallet is not fully synchronized yet."));
            }
            let m = d.manager(&name).await.map_err(RpcError::internal)?;
            m.start(password, stop_when_all_mixed, override_pleb_stop).await.map_err(RpcError::internal)?;
            Ok(Value::Null)
        }
        "unlockwallet" => {
            const MAX_UNLOCK_SECS: u64 = 24 * 3600;
            let password = p.str_opt(0, "password").unwrap_or_default();
            let ttl = p.u64_or(1, "ttlSeconds", 3600).min(MAX_UNLOCK_SECS);
            let w = ctx.wallet().await?;
            let (enc, cc, network) = {
                let lw = w.lock().await;
                if lw.km.is_hardware_wallet() {
                    return Err(RpcError::internal("A hardware wallet has no password to unlock."));
                }
                let (Some(enc), Some(cc)) = (lw.km.encrypted_secret(), lw.km.chain_code()) else { return Err(RpcError::internal("This is a watch-only wallet.")) };
                (enc.to_string(), cc.to_string(), lw.km.network())
            };
            let master = crate::coinjoin_manager::decrypt_master_blocking(enc, cc, password, network).await.map_err(RpcError::internal)?;
            w.lock().await.unlocked = Some((master, std::time::SystemTime::now() + std::time::Duration::from_secs(ttl)));
            Ok(Value::Null)
        }
        "lockwallet" => {
            let w = ctx.wallet().await?;
            w.lock().await.lock();
            // A running coinjoin holds its own copy of the key: end it (after the critical phase).
            if let Some(name) = &ctx.wallet_name {
                if let Some(m) = d.managers.read().await.get(name) {
                    m.stop();
                }
            }
            Ok(Value::Null)
        }
        "stopcoinjoin" => {
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            if let Some(m) = d.managers.read().await.get(&name) {
                m.stop();
            }
            Ok(Value::Null)
        }
        "enumeratedevices" => {
            let devices = hw::TrezorDevice::enumerate().await.map_err(|e| RpcError::internal(e.0))?;
            Ok(Value::Array(
                devices
                    .into_iter()
                    .map(|dv| {
                        json!({
                            "model": if dv.model.is_empty() { "Trezor".to_string() } else { format!("Trezor {}", dv.model) },
                            "masterKeyFingerprint": dv.fingerprint,
                            "initialized": dv.error.is_none(),
                            "canSignCoinJoins": true,
                            "vendor": "Trezor",
                            "needsPin": false,
                            "needsPassphrase": dv.passphrase_protection,
                            "firmware": dv.firmware,
                            "path": dv.path,
                            "error": dv.error.unwrap_or_default(),
                        })
                    })
                    .collect(),
            ))
        }
        "setcoinjoinlimits" => {
            let w = ctx.wallet().await?;
            let mut lw = w.lock().await;
            if let Some(v) = p.get(0, "maxRounds").and_then(Value::as_i64) {
                lw.km.set_field("CoinJoinDeviceMaxRounds", json!(v));
            }
            if let Some(v) = p.get(1, "maxMiningFeeRate").and_then(Value::as_f64) {
                lw.km.set_field("CoinJoinDeviceMaxMiningFeeRate", json!(v));
            }
            if let Some(v) = p.get(2, "maxSatsLeaving").and_then(Value::as_i64) {
                lw.km.set_field("ColdcardMaxSatsLeaving", json!(v));
            }
            if let Some(v) = p.get(3, "maxTransactionsPerPeriod").and_then(Value::as_i64) {
                lw.km.set_field("ColdcardMaxTransactionsPerPeriod", json!(v));
            }
            if let Some(v) = p.get(4, "minRoundInputs").and_then(Value::as_i64) {
                lw.km.set_field("ColdcardMinInputs", json!(v));
            }
            lw.km.save().map_err(RpcError::internal)?;
            Ok(json!({
                "maxRounds": lw.km.i64_field("CoinJoinDeviceMaxRounds", 50),
                "maxMiningFeeRate": lw.km.f64_field("CoinJoinDeviceMaxMiningFeeRate", 5.0),
                "maxSatsLeaving": lw.km.i64_field("ColdcardMaxSatsLeaving", 100000),
                "maxTransactionsPerPeriod": lw.km.i64_field("ColdcardMaxTransactionsPerPeriod", 6),
                "minRoundInputs": lw.km.i64_field("ColdcardMinInputs", 21),
                "appliesFromNextAuthorization": true
            }))
        }
        "displayaddress" => {
            let address = p.str(0, "address")?;
            let w = ctx.wallet().await?;
            let (fingerprint, network, key) = {
                let lw = w.lock().await;
                let addr: bitcoin::Address = address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>().map_err(|_| RpcError::invalid_params("address"))?.assume_checked();
                let key = lw.km.key_for_script(&addr.script_pubkey()).ok_or_else(|| RpcError::internal("The address does not belong to this wallet."))?.clone();
                if !lw.km.is_hardware_wallet() {
                    return Err(RpcError::internal("This is not a hardware wallet."));
                }
                (lw.km.master_fingerprint(), lw.km.network(), key)
            };
            let device = hw::TrezorDevice::find(Some(&fingerprint)).await.map_err(|e| RpcError::internal(e.0))?;
            let n = hw::trezor::messages::address_n(&key.path).ok_or_else(|| RpcError::internal("bad key path"))?;
            let shown = device.show_address(&n, network).await.map_err(|e| RpcError::internal(e.0))?;
            if !shown.eq_ignore_ascii_case(&address) {
                return Err(RpcError::internal(format!("The device showed a different address ({shown}).")));
            }
            Ok(json!({"address": address, "keyPath": key.path, "verified": true}))
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
