//! Key material never leaves the daemon: a guard over every RPC and MCP answer, and the rule that
//! keeps passwords out of the MCP channel (soft wallets are unlocked on the daemon host instead).

use serde_json::Value;

/// Field names that carry key material: these anywhere in the name, ...
const SECRET_KEY_PARTS: [&str; 9] = ["secret", "chaincode", "mnemonic", "privkey", "privatekey", "xprv", "password", "passphrase", "recoverywords"];
/// ... and these only as the whole name or its end (`masterKeyFingerprint` is public, `masterKey` is not).
const SECRET_KEY_ENDS: [&str; 3] = ["seed", "masterkey", "wif"];

fn secret_field_name(k: &str) -> bool {
    let lk = k.to_lowercase();
    SECRET_KEY_PARTS.iter().any(|s| lk.contains(s)) || SECRET_KEY_ENDS.iter().any(|s| lk.ends_with(s))
}

/// Methods an agent may call through the MCP `rpc` tool: nothing that takes a password (soft
/// wallets are unlocked on the daemon host) and nothing that stops the daemon.
const AGENT_METHODS: [&str; 19] = [
    "getstatus", "listwallets", "loadwallet", "selectwallet", "getwalletinfo", "listunspentcoins", "listcoins", "gethistory", "getnewaddress", "listkeys",
    "excludefromcoinjoin", "getfeerates", "startcoinjoin", "startcoinjoinsweep", "stopcoinjoin", "enumeratedevices", "setcoinjoinlimits", "displayaddress", "lockwallet",
];

fn is_base58(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() && !b"0OIl".contains(&b))
}

/// Why `v` looks like key material, if it does: a field name that smells of secrets, or a string
/// shaped like an extended private key (BIP 32 / SLIP-132), a WIF key or a BIP 38 blob.
pub fn looks_secret(v: &Value) -> Option<String> {
    match v {
        Value::Object(m) => m.iter().find_map(|(k, v)| if secret_field_name(k) { Some(format!("field '{k}'")) } else { looks_secret(v) }),
        Value::Array(a) => a.iter().find_map(looks_secret),
        Value::String(s) => {
            let b = s.as_bytes();
            let ext_prv = s.len() == 111 && b"xtyzvu".contains(&b[0]) && s[1..].starts_with("prv");
            let bip38 = s.len() == 58 && s.starts_with("6P");
            let wif = (s.len() == 51 && b"59".contains(&b[0])) || (s.len() == 52 && b"KLc".contains(&b[0]));
            ((ext_prv || bip38 || wif) && is_base58(s)).then(|| "a private key string".to_string())
        }
        _ => None,
    }
}

/// The MCP passthrough: only agent-safe methods, and never a password (`startcoinjoin`'s is
/// blanked so the daemon uses the unlocked key).
pub fn agent_call(method: &str, params: &mut Value) -> Result<(), String> {
    let m = method.to_ascii_lowercase();
    if !AGENT_METHODS.contains(&m.as_str()) {
        return Err(format!("'{method}' is not available through the MCP (no passwords, no daemon shutdown); run it with `sabid rpc` on the daemon host"));
    }
    if m == "startcoinjoin" || m == "startcoinjoinsweep" {
        if let Some(first) = params.as_array_mut().and_then(|a| a.first_mut()) {
            *first = Value::String(String::new());
        }
        if let Some(o) = params.as_object_mut() {
            o.insert("password".into(), Value::String(String::new()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flags_secret_fields_and_private_key_strings() {
        assert!(looks_secret(&json!({"EncryptedSecret": "6PYK..."})).is_some());
        assert!(looks_secret(&json!({"wallet": {"keys": [{"ChainCode": "x"}]}})).is_some());
        assert!(looks_secret(&json!({"jsonRpcPassword": "x"})).is_some());
        assert!(looks_secret(&json!({"masterKey": "x"})).is_some());
        assert!(looks_secret(&json!({"seed": "x", "wif": "y"})).is_some());
        assert!(looks_secret(&json!({"masterKeyFingerprint": "8c000000", "seedHeight": 1})).is_none());
        assert!(looks_secret(&json!(["xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"])).is_some());
        assert!(looks_secret(&json!({"k": "6PRVWUbkzzgVpRZkRECALL7bhCq6ngRZaHazjbmskWKnVWX9hxyq2P1xfm"})).is_some());
        assert!(looks_secret(&json!({"k": "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"})).is_some());
        assert!(looks_secret(&json!({"publicKey": "xpub6CUGRU...", "balance": 1, "label": "xprv recovery stash", "masterKeyFingerprint": "00000000", "walletFile": "/w/tprv-backup.json"})).is_none());
    }

    #[test]
    fn mcp_allows_safe_methods_and_blanks_passwords() {
        let mut p = json!(["hunter2", true, true]);
        agent_call("startcoinjoin", &mut p).unwrap();
        assert_eq!(p, json!(["", true, true]));
        let mut sweep = json!(["hunter2", "OtherWallet"]);
        agent_call("startcoinjoinsweep", &mut sweep).unwrap();
        assert_eq!(sweep, json!(["", "OtherWallet"]));
        let mut o = json!({"password": "hunter2", "stopWhenAllMixed": false});
        agent_call("startcoinjoin", &mut o).unwrap();
        assert_eq!(o["password"], "");
        for refused in ["unlockwallet", "send", "build", "stop", "recoverwallet"] {
            assert!(agent_call(refused, &mut json!([])).is_err(), "{refused}");
        }
        assert!(agent_call("getwalletinfo", &mut json!([])).is_ok());
    }
}
