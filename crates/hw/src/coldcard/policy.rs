//! HSM policy JSON for unattended coinjoin signing (Wasabi's `ColdcardHsmPolicy` + `ColdcardBackend.ComposePolicy`).

use bitcoin::hashes::{sha256, Hash};

pub const DEFAULT_MIN_SELF_TRANSFER_PERCENT: f64 = 50.0;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_sats_leaving: i64,
    pub max_transactions: i64,
    pub max_transactions_per_period: i64,
    pub period_minutes: i64,
    pub min_inputs: Option<i64>,
    pub max_fee_per_kvbyte: i64,
}

/// sat/vB -> sats per 1000 vbytes, rounded up so the device cap is never tighter than the setting.
pub fn fee_rate_to_per_kvbyte(sat_per_vb: f64) -> i64 {
    (sat_per_vb * 1000.0).ceil() as i64
}

pub fn compose(account_paths: &[String], limits: &Limits) -> String {
    let paths: Vec<String> = account_paths.iter().flat_map(|a| [format!("m/{a}/0/*"), format!("m/{a}/1/*")]).collect();
    let mut rule = serde_json::Map::new();
    rule.insert("min_pct_self_transfer".into(), serde_json::json!(DEFAULT_MIN_SELF_TRANSFER_PERCENT));
    rule.insert("max_sats_leaving".into(), serde_json::json!(limits.max_sats_leaving));
    rule.insert("max_txn".into(), serde_json::json!(limits.max_transactions));
    rule.insert("max_txn_per_period".into(), serde_json::json!(limits.max_transactions_per_period));
    if let Some(m) = limits.min_inputs {
        rule.insert("min_inputs".into(), serde_json::json!(m));
    }
    rule.insert("max_fee_per_kvbyte".into(), serde_json::json!(limits.max_fee_per_kvbyte));
    let policy = serde_json::json!({
        "warnings_ok": true,
        "slip19_paths": paths,
        "rules": [rule],
        "period": limits.period_minutes,
    });
    policy.to_string()
}

pub fn fingerprint(policy_json: &str) -> String {
    hex::encode(sha256::Hash::hash(policy_json.as_bytes()).to_byte_array())
}

/// Mk3 and older, and the Q, cannot run this policy; name the reason instead of an obscure device error.
pub fn ensure_firmware_supports_policy(version_reply: &str) -> Result<(), String> {
    let v = version_reply.to_lowercase();
    if v.contains("q1") {
        return Err("This Coldcard Q disables the HSM commands coinjoin needs (it uses SSSP / Co-Sign instead). A Coldcard Mk4 is required.".into());
    }
    if v.contains("mk1") || v.contains("mk2") || v.contains("mk3") {
        return Err("This Coldcard (Mk3 or older) cannot sign coinjoins: its firmware line ended before the 'min_pct_self_transfer' HSM rule existed. A Coldcard Mk4 is required.".into());
    }
    Ok(())
}
