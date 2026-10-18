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
        "createwallet" => {
            let name = p.str(0, "walletName")?;
            let password = p.str_opt(1, "password").unwrap_or_default();
            let mnemonic = bip39::Mnemonic::generate(12).map_err(|e| RpcError::internal(e.to_string()))?;
            // Fresh wallet: nothing to find before today's tip.
            let birth = d.filters.lock().await.tip_height().unwrap_or(wallet::filters::first_height(d.network));
            d.create_wallet(&name, &mnemonic, &password, birth).map_err(RpcError::internal)?;
            Ok(Value::String(mnemonic.to_string()))
        }
        "recoverwallet" => {
            let name = p.str(0, "walletName")?;
            let words = p.str(1, "mnemonic")?;
            let password = p.str_opt(2, "password").unwrap_or_default();
            let mnemonic = bip39::Mnemonic::parse(words.trim()).map_err(|_| RpcError::internal("Invalid value for mnemonic"))?;
            let birth = p.u64_or(3, "birthHeight", wallet::filters::first_height(d.network) as u64) as u32;
            d.create_wallet(&name, &mnemonic, &password, birth).map_err(RpcError::internal)?;
            Ok(Value::Null)
        }
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
            m.start(password, stop_when_all_mixed, override_pleb_stop, None).await.map_err(RpcError::internal)?;
            Ok(Value::Null)
        }
        "startcoinjoinsweep" => {
            // Wasabi: coinjoin every coin (private ones too) into another wallet, until stopped.
            let password = p.str_opt(0, "password");
            let out_name = p.str_opt(1, "outputWalletName").filter(|n| !n.is_empty()).ok_or_else(|| RpcError::internal("Output wallet name is invalid."))?;
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            if out_name == name {
                return Err(RpcError::internal("Output wallet name is invalid."));
            }
            let w = ctx.wallet().await?;
            if !w.lock().await.loaded {
                return Err(RpcError::internal("Wallet is not fully synchronized yet."));
            }
            let out = d.load_wallet(&out_name).await.map_err(RpcError::internal)?;
            let m = d.manager(&name).await.map_err(RpcError::internal)?;
            m.start(password, false, true, Some(out)).await.map_err(RpcError::internal)?;
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
        "build" | "send" => {
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            let payments: Vec<crate::send::Payment> = p
                .get(0, "payments")
                .and_then(Value::as_array)
                .ok_or_else(|| RpcError::invalid_params("missing parameter 'payments'"))?
                .iter()
                .map(|pm| {
                    let addr = pm.get("sendto").and_then(Value::as_str).ok_or_else(|| RpcError::invalid_params("payment without 'sendto'"))?;
                    let script = addr.parse::<bitcoin::Address<_>>().map_err(|e| RpcError::invalid_params(format!("address: {e}")))?.require_network(d.network).map_err(|e| RpcError::invalid_params(e.to_string()))?.script_pubkey();
                    let amount = pm.get("amount").and_then(Value::as_u64).ok_or_else(|| RpcError::invalid_params("payment without 'amount' (satoshis)"))?;
                    Ok(crate::send::Payment { script, amount, subtract_fee: pm.get("subtractFee").and_then(Value::as_bool).unwrap_or(false) })
                })
                .collect::<Result<_, RpcError>>()?;
            let label: String = p.get(0, "payments").and_then(Value::as_array).map(|a| a.iter().filter_map(|pm| pm.get("label").and_then(Value::as_str)).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let outpoints: Vec<bitcoin::OutPoint> = p
                .get(1, "coins")
                .and_then(Value::as_array)
                .ok_or_else(|| RpcError::invalid_params("missing parameter 'coins'"))?
                .iter()
                .map(|c| {
                    let txid = c.get("transactionid").and_then(Value::as_str).and_then(|s| s.parse().ok()).ok_or_else(|| RpcError::invalid_params("coin without 'transactionid'"))?;
                    let vout = c.get("index").and_then(Value::as_u64).ok_or_else(|| RpcError::invalid_params("coin without 'index'"))? as u32;
                    Ok(bitcoin::OutPoint { txid, vout })
                })
                .collect::<Result<_, RpcError>>()?;
            let fee_rate = match (p.get(3, "feeRate").and_then(Value::as_f64), p.get(2, "feeTarget").and_then(Value::as_u64)) {
                (Some(r), _) => r,
                (None, Some(t)) => {
                    let rates = d.fee_rates.read().await;
                    rates.range(t as u32..).next().or_else(|| rates.iter().next_back()).map(|(_, v)| *v as f64).ok_or_else(|| RpcError::internal("No fee estimate available (is a Bitcoin Core node configured?); pass feeRate."))?
                }
                (None, None) => return Err(RpcError::invalid_params("Fee parameters are missing: feeTarget or feeRate.")),
            };
            let password = p.str_opt(4, "password");
            let w = ctx.wallet().await?;
            let (coins, change, hardware) = {
                let mut lw = w.lock().await;
                if !lw.loaded {
                    return Err(RpcError::internal("Wallet is not fully synchronized yet."));
                }
                let hardware = lw.km.is_hardware_wallet();
                if hardware && lw.km.i64_field("CoinJoinVendor", 0) != 2 {
                    return Err(RpcError::internal("Sending from this hardware wallet is not supported yet (a Coldcard can sign plain transactions here; a Trezor only coinjoins)."));
                }
                let coins: Vec<wallet::store::Coin> = outpoints
                    .iter()
                    .map(|op| lw.state.unspent().find(|c| c.outpoint == *op).cloned().ok_or_else(|| RpcError::internal(format!("Coin {op} is not an unspent coin of this wallet."))))
                    .collect::<Result<_, _>>()?;
                let idx = lw.km.next_change_key(false).ok_or_else(|| RpcError::internal("No change key available."))?;
                lw.km.keys[idx].state = wallet::KeyState::Locked;
                lw.km.keys[idx].label = label.clone();
                lw.km.save().map_err(RpcError::internal)?;
                (coins, lw.km.keys[idx].script.clone(), hardware)
            };
            let dust = (d.cfg.dust_threshold.parse::<f64>().unwrap_or(0.00001) * 1e8).round() as u64;
            let built = crate::send::build(&coins, &payments, fee_rate, change.clone(), dust).map_err(RpcError::internal)?;
            let kc: std::sync::Arc<dyn coinjoin::keychain::KeyChain> = if hardware {
                crate::devices::coldcard_signer(&w).await.map_err(RpcError::internal)?
            } else {
                crate::coinjoin_manager::soft_key_chain(&w, password, &name).await.map_err(RpcError::internal)?
            };
            let fee = built.fee;
            let tx = tokio::task::spawn_blocking(move || crate::send::sign(&*kc, &built)).await.map_err(|e| RpcError::internal(e.to_string()))?.map_err(RpcError::internal)?;
            let hex = bitcoin::consensus::encode::serialize_hex(&tx);
            tracing::info!("{name}: {method} {} input(s), {} output(s), fee {fee} sat at {fee_rate} sat/vB", tx.input.len(), tx.output.len());
            if method == "build" {
                return Ok(Value::String(hex));
            }
            let node = d.bitcoind.as_ref().ok_or_else(|| RpcError::internal("No Bitcoin Core node configured: use build and broadcast the transaction elsewhere."))?;
            let txid = node.send_raw_transaction(&hex).await.map_err(|e| RpcError::internal(format!("broadcast: {e}")))?;
            d.note_broadcast(&tx).await;
            Ok(json!({"txid": txid.to_string(), "tx": hex}))
        }
        "canceltransaction" | "speeduptransaction" => {
            // RBF replacement of an unconfirmed transaction of ours: cancel sends everything back to a
            // fresh internal key; speed up keeps the payments and takes the extra fee from the change.
            let txid: bitcoin::Txid = p.str(0, "txId")?.parse().map_err(|_| RpcError::invalid_params("txId"))?;
            let password = p.str_opt(1, "password");
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            let w = ctx.wallet().await?;
            let dust = (d.cfg.dust_threshold.parse::<f64>().unwrap_or(0.00001) * 1e8).round() as u64;
            let (coins, payments, change, old_fee, old_vsize, hardware) = {
                let mut lw = w.lock().await;
                if !lw.store.mempool_txs().unwrap_or_default().iter().any(|(t, _)| *t == txid) {
                    return Err(RpcError::internal("Transaction is not an unconfirmed transaction of this wallet."));
                }
                let tx = lw.store.get_tx(&txid).ok_or_else(|| RpcError::internal("Transaction not found."))?;
                let coins: Vec<wallet::store::Coin> = tx
                    .input
                    .iter()
                    .map(|i| lw.state.coins.iter().find(|c| c.outpoint == i.previous_output).cloned().ok_or_else(|| RpcError::internal("Not every input of the transaction belongs to this wallet.")))
                    .collect::<Result<_, _>>()?;
                let prevouts: Vec<bitcoin::TxOut> = coins.iter().map(|c| bitcoin::TxOut { value: bitcoin::Amount::from_sat(c.amount), script_pubkey: c.script.clone() }).collect();
                let total_in: u64 = coins.iter().map(|c| c.amount).sum();
                let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                let old_fee = total_in.saturating_sub(total_out);
                let old_vsize = crate::send::vsize(&tx, &prevouts);
                let hardware = lw.km.is_hardware_wallet();
                if hardware && lw.km.i64_field("CoinJoinVendor", 0) != 2 {
                    return Err(RpcError::internal("Only a soft wallet or a Coldcard can sign the replacement here."));
                }
                let idx = lw.km.next_change_key(false).ok_or_else(|| RpcError::internal("No change key available."))?;
                lw.km.keys[idx].state = wallet::KeyState::Locked;
                let fresh = lw.km.keys[idx].script.clone();
                let payments: Vec<crate::send::Payment> = if method == "canceltransaction" {
                    lw.km.keys[idx].label = "cancelled transaction".into();
                    vec![crate::send::Payment { script: fresh.clone(), amount: total_in, subtract_fee: true }]
                } else {
                    // The extra fee comes from an output that is ours (the change); the rest stay as they are.
                    let is_ours = |s: &bitcoin::ScriptBuf| lw.km.key_for_script(s).is_some();
                    let payer = tx.output.iter().rposition(|o| is_ours(&o.script_pubkey)).ok_or_else(|| RpcError::internal("No change output to take the extra fee from; cancel the transaction instead."))?;
                    tx.output.iter().enumerate().map(|(i, o)| crate::send::Payment { script: o.script_pubkey.clone(), amount: o.value.to_sat(), subtract_fee: i == payer }).collect()
                };
                lw.km.save().map_err(RpcError::internal)?;
                (coins, payments, fresh, old_fee, old_vsize, hardware)
            };
            let new_vsize = crate::send::vsize(&bitcoin::Transaction { version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![], output: payments.iter().map(|pm| bitcoin::TxOut { value: bitcoin::Amount::from_sat(pm.amount), script_pubkey: pm.script.clone() }).collect() }, &coins.iter().map(|c| bitcoin::TxOut { value: bitcoin::Amount::from_sat(c.amount), script_pubkey: c.script.clone() }).collect::<Vec<_>>());
            let rate = crate::send::replacement_rate(old_fee, old_vsize, new_vsize);
            let built = crate::send::build(&coins, &payments, rate, change, dust).map_err(|e| RpcError::internal(format!("{e} (replacement at {rate:.1} sat/vB)")))?;
            let kc: std::sync::Arc<dyn coinjoin::keychain::KeyChain> = if hardware {
                crate::devices::coldcard_signer(&w).await.map_err(RpcError::internal)?
            } else {
                crate::coinjoin_manager::soft_key_chain(&w, password, &name).await.map_err(RpcError::internal)?
            };
            let tx = tokio::task::spawn_blocking(move || crate::send::sign(&*kc, &built)).await.map_err(|e| RpcError::internal(e.to_string()))?.map_err(RpcError::internal)?;
            tracing::info!("{name}: {method} of {txid} built at {rate:.1} sat/vB");
            Ok(Value::String(bitcoin::consensus::encode::serialize_hex(&tx)))
        }
        "broadcast" => {
            let hex = p.str(0, "txHex")?;
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&hex).map_err(|e| RpcError::invalid_params(format!("txHex: {e}")))?;
            let node = d.bitcoind.as_ref().ok_or_else(|| RpcError::internal("No Bitcoin Core node configured."))?;
            let txid = node.send_raw_transaction(&hex).await.map_err(|e| RpcError::internal(format!("broadcast: {e}")))?;
            d.note_broadcast(&tx).await;
            Ok(json!({"txid": txid.to_string()}))
        }
        "payincoinjoin" => {
            // Wasabi: the payment rides along in a later round as one of its outputs. Soft wallets only:
            // a signing device approves how much may leave, never where to, so it refuses such rounds.
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            let addr = p.str(0, "address")?;
            let script = addr.parse::<bitcoin::Address<_>>().map_err(|e| RpcError::invalid_params(format!("address: {e}")))?.require_network(d.network).map_err(|e| RpcError::invalid_params(e.to_string()))?.script_pubkey();
            let amount = match p.get(1, "amount") {
                Some(Value::Number(n)) => n.as_i64().ok_or_else(|| RpcError::invalid_params("amount"))?,
                Some(Value::String(s)) => (s.parse::<f64>().map_err(|_| RpcError::invalid_params("amount"))? * 1e8).round() as i64,
                _ => return Err(RpcError::invalid_params("missing parameter 'amount' (satoshis)")),
            };
            if amount <= 0 {
                return Err(RpcError::invalid_params("amount must be positive"));
            }
            let password = p.str_opt(2, "password");
            let w = ctx.wallet().await?;
            if w.lock().await.km.is_hardware_wallet() {
                return Err(RpcError::internal("Payments in coinjoin are not possible when a device signs the rounds."));
            }
            // The same check Wasabi makes: the password (or the unlocked key) must open the wallet.
            crate::coinjoin_manager::soft_key_chain(&w, password, &name).await.map_err(RpcError::internal)?;
            let m = d.manager(&name).await.map_err(RpcError::internal)?;
            Ok(Value::String(m.payments.add(script, amount)))
        }
        "listpaymentsincoinjoin" => {
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            let Some(m) = d.managers.read().await.get(&name).cloned() else { return Ok(Value::Array(vec![])) };
            Ok(Value::Array(
                m.payments
                    .list()
                    .into_iter()
                    .map(|pm| {
                        use coinjoin::payments::PaymentState as S;
                        // Newest state first, as Wasabi walks the chain of previous states.
                        let states: Vec<Value> = pm
                            .states
                            .iter()
                            .rev()
                            .map(|s| match s {
                                S::Pending => json!({"status": "Pending"}),
                                S::InProgress { round_id } => json!({"status": "In progress", "round": round_id}),
                                S::Signed { txid } => json!({"status": "Signed", "txid": txid.to_string()}),
                                S::Finished { txid } => json!({"status": "Finished", "txid": txid.to_string()}),
                            })
                            .collect();
                        let address = bitcoin::Address::from_script(&pm.script, d.network).map(|a| a.to_string()).unwrap_or_default();
                        json!({"id": pm.id, "amount": pm.amount, "destination": hex::encode(pm.script.as_bytes()), "state": states, "address": address})
                    })
                    .collect(),
            ))
        }
        "cancelpaymentincoinjoin" => {
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            let id = p.str(0, "paymentId")?;
            let m = d.managers.read().await.get(&name).cloned().ok_or_else(|| RpcError::internal("Payment was not found."))?;
            m.payments.abort(&id).map_err(RpcError::internal)?;
            Ok(Value::Null)
        }
        "stopcoinjoin" => {
            let name = ctx.wallet_name.clone().ok_or_else(|| RpcError::internal("Wallet name is invalid or not allowed."))?;
            if let Some(m) = d.managers.read().await.get(&name) {
                m.stop();
            }
            Ok(Value::Null)
        }
        "importhardwarewallet" => {
            let name = p.str(0, "walletName")?;
            let enable_coinjoin = p.bool_or(1, "enableCoinjoin", false);
            let birth = p.u64_or(2, "birthHeight", wallet::filters::first_height(d.network) as u64) as u32;
            let path = d.new_wallet_path(&name).map_err(RpcError::internal)?;
            let (dev, fp) = crate::devices::find(None).await.map_err(RpcError::internal)?;
            let segwit = crate::devices::account_xpub(&dev, &wallet::create::account_path(84, d.network), d.network).await.map_err(RpcError::internal)?;
            // Trezor coinjoins from its SLIP-25 account; a Coldcard from this segwit account under its HSM policy.
            let slip25 = wallet::create::account_path(10025, d.network);
            let taproot = match (&dev, enable_coinjoin) {
                (crate::devices::Device::Trezor(_), true) => Some((slip25.as_str(), crate::devices::account_xpub(&dev, &slip25, d.network).await.map_err(RpcError::internal)?)),
                _ => None,
            };
            let vendor = if enable_coinjoin { dev.vendor() } else { 0 };
            let km = wallet::create::write_json(&path, wallet::create::watch_only_json(d.network, birth, &fp, &segwit, taproot.as_ref().map(|(p, x)| (*p, x.as_str())), dev.icon(), vendor)).map_err(RpcError::internal)?;
            Ok(json!({"walletName": name, "masterKeyFingerprint": fp, "accounts": accounts(&km), "verifiedAddresses": []}))
        }
        "enablecoinjoin" | "enabletaproot" => {
            let w = ctx.wallet().await?;
            let mut lw = w.lock().await;
            if !lw.km.is_hardware_wallet() {
                return Err(RpcError::internal("Only a hardware wallet needs this; a soft wallet coinjoins as it is."));
            }
            if method == "enablecoinjoin" && lw.km.i64_field("CoinJoinVendor", 0) != 0 {
                return Ok(json!({"accounts": accounts(&lw.km), "verifiedAddresses": []}));
            }
            let fp = lw.km.master_fingerprint();
            let (dev, _) = crate::devices::find(Some(&fp)).await.map_err(|e| RpcError::internal(format!("The device of this wallet is not connected: {e}")))?;
            let add_account = |lw: &mut crate::daemon::LoadedWallet, purpose: u32, xpub: String| {
                lw.km.set_field("TaprootAccountKeyPath", json!(wallet::create::account_path(purpose, d.network)));
                lw.km.set_field("TaprootExtPubKey", json!(xpub));
                lw.km.set_field("DefaultReceiveScriptType", json!("Taproot"));
            };
            match (method, &dev) {
                ("enablecoinjoin", crate::devices::Device::Coldcard(_)) => lw.km.set_field("CoinJoinVendor", json!(2)),
                ("enablecoinjoin", crate::devices::Device::Trezor(_)) => {
                    if lw.km.taproot_xpub().is_some() {
                        return Err(RpcError::internal("Only a hardware wallet without a taproot account can take a coinjoin account."));
                    }
                    let xpub = crate::devices::account_xpub(&dev, &wallet::create::account_path(10025, d.network), d.network).await.map_err(RpcError::internal)?;
                    add_account(&mut lw, 10025, xpub);
                    lw.km.set_field("ChangeScriptPubKeyType", json!("Segwit"));
                    lw.km.set_field("CoinJoinVendor", json!(1));
                }
                (_, crate::devices::Device::Coldcard(_)) => {
                    if lw.km.taproot_xpub().is_some() {
                        return Err(RpcError::internal("This wallet already has a taproot account."));
                    }
                    let xpub = crate::devices::account_xpub(&dev, &wallet::create::account_path(86, d.network), d.network).await.map_err(RpcError::internal)?;
                    add_account(&mut lw, 86, xpub);
                }
                _ => return Err(RpcError::internal("A Trezor's taproot account comes with its coinjoin account (enablecoinjoin).")),
            }
            lw.km.save().map_err(RpcError::internal)?;
            if lw.km.taproot_xpub().is_none() && method == "enablecoinjoin" {
                // Coldcard: the file changed but no account did, nothing to scan again.
                return Ok(json!({"accounts": accounts(&lw.km), "verifiedAddresses": []}));
            }
            d.reload_wallet_for_rescan(&mut lw).await.map_err(RpcError::internal)?;
            Ok(json!({"accounts": accounts(&lw.km), "verifiedAddresses": []}))
        }
        "enumeratedevices" => {
            let mut list = Vec::new();
            if let Ok(Ok(cc)) = tokio::task::spawn_blocking(hw::ColdcardDevice::open).await {
                list.push(json!({"model": "Coldcard Mk4", "masterKeyFingerprint": cc.master_fingerprint, "initialized": true, "canSignCoinJoins": true, "vendor": "Coldcard", "needsPin": false, "needsPassphrase": false, "firmware": "", "path": "hidraw", "error": ""}));
            }
            let devices = hw::TrezorDevice::enumerate().await.unwrap_or_default();
            list.extend(
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
                    }),
            );
            Ok(Value::Array(list))
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
