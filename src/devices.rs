//! The connected signing device, found the way Wasabi's hardware-wallet service does it:
//! a Coldcard over USB first, then a Trezor through the bridge; matched by fingerprint when asked.

use bitcoin::Network;
use std::sync::Arc;

pub enum Device {
    Coldcard(Arc<hw::ColdcardDevice>),
    Trezor(hw::TrezorDevice),
}

impl Device {
    pub fn vendor(&self) -> i64 {
        match self {
            Device::Trezor(_) => 1,
            Device::Coldcard(_) => 2,
        }
    }
    pub fn icon(&self) -> &'static str {
        match self {
            Device::Trezor(_) => "Trezor",
            Device::Coldcard(_) => "Coldcard",
        }
    }
}

/// `84'/0'/0'` -> `[84 | H, 0 | H, 0 | H]`.
fn indexes(path: &str) -> Result<Vec<u32>, String> {
    path.trim_start_matches("m/")
        .split('/')
        .map(|seg| {
            let hardened = seg.ends_with(['\'', 'h']);
            seg.trim_end_matches(['\'', 'h']).parse::<u32>().map(|n| if hardened { n | hw::trezor::messages::HARDENED } else { n }).map_err(|_| format!("bad key path {path}"))
        })
        .collect()
}

pub async fn find(fingerprint: Option<&str>) -> Result<(Device, String), String> {
    if let Ok(Ok(cc)) = tokio::task::spawn_blocking(hw::ColdcardDevice::open).await {
        let fp = cc.master_fingerprint.clone();
        if fingerprint.map(|f| f.eq_ignore_ascii_case(&fp)).unwrap_or(true) {
            return Ok((Device::Coldcard(Arc::new(cc)), fp));
        }
    }
    let t = hw::TrezorDevice::find(fingerprint).await.map_err(|e| format!("DeviceNotFound: {}", e.0))?;
    let fp = t.master_fingerprint().await.map_err(|e| e.0)?;
    Ok((Device::Trezor(t), fp))
}

/// A Coldcard key chain for one plain transaction: outside HSM mode the device asks the user to
/// confirm it on screen; in HSM mode its policy decides. No coinjoin policy is installed here.
pub async fn coldcard_signer(wallet: &std::sync::Arc<tokio::sync::Mutex<crate::daemon::LoadedWallet>>) -> Result<std::sync::Arc<dyn coinjoin::keychain::KeyChain>, String> {
    let (fp, keys, max_fee) = {
        let w = wallet.lock().await;
        let keys: std::collections::HashMap<bitcoin::ScriptBuf, hw::ColdcardKeyInfo> =
            w.km.keys.iter().filter(|k| k.kind != wallet::AccountKind::Other).map(|k| (k.script.clone(), hw::ColdcardKeyInfo { path: k.path.clone(), pubkey: k.pubkey.inner })).collect();
        (w.km.master_fingerprint(), keys, w.km.f64_field("CoinJoinDeviceMaxMiningFeeRate", 5.0))
    };
    let (dev, found) = find(Some(&fp)).await?;
    let Device::Coldcard(cc) = dev else { return Err(format!("The connected device ({found}) is not this wallet's Coldcard.")) };
    let kc = hw::ColdcardKeyChain::new(cc, &fp, keys, 1, coinjoin::FeeRate::from_sat_per_vb(max_fee), 0).map_err(|e| e.to_string())?;
    Ok(Arc::new(kc))
}

pub async fn account_xpub(dev: &Device, path: &str, network: Network) -> Result<String, String> {
    match dev {
        Device::Coldcard(cc) => {
            let (cc, p) = (cc.clone(), path.to_string());
            tokio::task::spawn_blocking(move || cc.xpub(&p)).await.map_err(|e| e.to_string())?.map_err(|e| format!("{} (a Coldcard in HSM mode does not share xpubs; reboot it to import)", e.0))
        }
        Device::Trezor(t) => t.account_xpub(&indexes(path)?, network).await.map_err(|e| e.0),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn paths_become_hardened_indexes() {
        let h = hw::trezor::messages::HARDENED;
        assert_eq!(super::indexes("84'/0'/0'").unwrap(), vec![84 | h, h, h]);
        assert_eq!(super::indexes("m/10025h/0h/0h/1h").unwrap(), vec![10025 | h, h, h, 1 | h]);
        assert!(super::indexes("x/1").is_err());
    }
}
