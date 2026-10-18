//! Wasabi's `Config.json` (`PersistentConfig`), read in place so sabid and the GUI/daemon agree.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct WasabiConfig {
    /// "Main", "TestNet", "TestNet4", "Signet" or "RegTest", as Wasabi writes it.
    pub network: String,
    pub coordinator_uri: String,
    pub use_tor: String,
    pub json_rpc_server_enabled: bool,
    pub json_rpc_user: String,
    pub json_rpc_password: String,
    pub json_rpc_server_prefixes: Vec<String>,
    pub bitcoin_rpc_end_point: String,
    pub bitcoin_rpc_credential_string: String,
    /// Money as Wasabi prints it, e.g. "0.00001" BTC
    pub dust_threshold: String,
    pub coordinator_identifier: String,
    pub max_coin_join_mining_fee_rate: f64,
    pub absolute_min_input_count: i32,
    pub config_version: i32,
}

impl Default for WasabiConfig {
    fn default() -> Self {
        Self {
            network: "Main".into(),
            coordinator_uri: "https://coinjoin.nl".into(),
            use_tor: "Enabled".into(),
            json_rpc_server_enabled: false,
            json_rpc_user: String::new(),
            json_rpc_password: String::new(),
            json_rpc_server_prefixes: vec!["http://127.0.0.1:37128/".into()],
            bitcoin_rpc_end_point: String::new(),
            bitcoin_rpc_credential_string: String::new(),
            dust_threshold: "0.00001".into(),
            coordinator_identifier: "CoinJoinCoordinatorIdentifier".into(),
            max_coin_join_mining_fee_rate: 5.0,
            absolute_min_input_count: 21,
            config_version: 4,
        }
    }
}

pub fn wasabi_data_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".walletwasabi").join("client")
}

impl WasabiConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read(path)?;
        let text = String::from_utf8_lossy(&raw);
        let text = text.trim_start_matches('\u{feff}');
        Ok(serde_json::from_str(text)?)
    }

    pub fn network(&self) -> bitcoin::Network {
        match self.network.as_str() {
            "TestNet" | "TestNet4" => bitcoin::Network::Testnet,
            "RegTest" => bitcoin::Network::Regtest,
            "Signet" => bitcoin::Network::Signet,
            _ => bitcoin::Network::Bitcoin,
        }
    }

    pub fn load_default() -> anyhow::Result<Self> {
        let p = wasabi_data_dir().join("Config.json");
        if p.exists() {
            Self::load(&p)
        } else {
            Ok(Self::default())
        }
    }
}
