mod coinjoin_manager;
mod config;
mod daemon;
mod mcp;
mod methods;
mod rpc;
mod secrets;
mod tor;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use wasabi_proto::{CoordinatorClient, Phase, ProxyConfig, RoundStateRequest};

#[derive(Parser)]
#[command(name = "sabid", version, about = "Rust Wasabi daemon: WabiSabi coinjoin client, JSON-RPC, CLI, MCP")]
struct Cli {
    /// Coordinator base URI (default: CoordinatorUri from Wasabi's Config.json)
    #[arg(long, global = true)]
    coordinator: Option<String>,
    /// SOCKS5 proxy host:port for Tor (default: probe 127.0.0.1:37150 and :9050, else start tor)
    #[arg(long, global = true)]
    socks: Option<String>,
    /// sabid data directory (stores, logs, own tor)
    #[arg(long, global = true, default_value_os_t = default_datadir())]
    datadir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

fn default_datadir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".sabid")
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the coordinator's rounds and verify their ids
    Status,
    /// Run the daemon: Tor, wallet sync, JSON-RPC server (Wasabi-compatible)
    Daemon {
        /// Wallet(s) to load at start (names of ~/.walletwasabi/client/Wallets/*.json)
        #[arg(long = "wallet")]
        wallets: Vec<String>,
        /// Listen address for JSON-RPC (default: first JsonRpcServerPrefixes entry or 127.0.0.1:37128)
        #[arg(long)]
        rpc_bind: Option<String>,
        /// Do not use Tor (clearnet; only for regtest/testing)
        #[arg(long)]
        no_tor: bool,
        /// Path to a tor binary to start when no SOCKS proxy answers
        #[arg(long)]
        tor_binary: Option<PathBuf>,
        /// Wallet directory (default: ~/.walletwasabi/client/Wallets, shared with Wasabi)
        #[arg(long)]
        wallet_dir: Option<PathBuf>,
    },
    /// Seed a wallet's transaction store from Wasabi's own confirmed-transaction store (no rescan)
    ImportWasabiTxs {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        wallet_dir: Option<PathBuf>,
    },
    /// List hardware wallets: Trezor bridge devices and a Coldcard on USB (with its HSM state)
    Devices,
    /// Model Context Protocol server on stdio for agents (thin client of a running daemon)
    Mcp {
        /// RPC URL of the daemon (default: from Config.json)
        #[arg(long)]
        url: Option<String>,
    },
    /// Decrypt a soft wallet's key with a password typed here and keep it in the daemon's memory
    /// for a while, so startcoinjoin (also from agents over MCP) needs no password
    Unlock {
        #[arg(long)]
        wallet: String,
        /// Seconds to stay unlocked
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// RPC URL (default: from Config.json)
        #[arg(long)]
        url: Option<String>,
    },
    /// Forget a wallet's decrypted key in the daemon
    Lock {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        url: Option<String>,
    },
    /// Call a JSON-RPC method on a running daemon (sabid or Wasabi)
    Rpc {
        method: String,
        /// Parameters as JSON array or object (default: [])
        params: Option<String>,
        #[arg(long)]
        wallet: Option<String>,
        /// RPC URL (default: from Config.json)
        #[arg(long)]
        url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into()))
        .init();
    let cli = Cli::parse();
    let mut cfg = config::WasabiConfig::load_default()?;
    if let Some(c) = &cli.coordinator {
        cfg.coordinator_uri = c.clone();
    }
    let coordinator = cfg.coordinator_uri.clone();

    match cli.cmd {
        Cmd::Status => {
            let proxy = cli.socks.clone().map(|socks5| ProxyConfig { socks5 });
            let client = CoordinatorClient::new(&coordinator, proxy.as_ref(), "status")?;
            let resp = client.get_status(&RoundStateRequest::default()).await?;
            println!("{coordinator}: {} round(s){}", resp.round_states.len(), if proxy.is_some() { " via tor" } else { " (clearnet)" });
            for r in &resp.round_states {
                let p = r.parameters();
                let phase = r.phase().map(|p| format!("{p:?}")).unwrap_or_else(|| format!("phase {}", r.phase));
                let inputs = r.coinjoin_state.inputs().count();
                let outputs = r.coinjoin_state.outputs().count();
                let remaining = r.input_registration_end().signed_duration_since(chrono::Utc::now());
                let id_ok = if r.is_round_id_matching() { "id ok" } else { "ID MISMATCH" };
                println!(
                    "- {} {}{} inputs={inputs} outputs={outputs} fee={} sat/vB min_in={} max_in={} max_sugg={} sat inreg_left={}s [{id_ok}]",
                    &r.id[..16],
                    phase,
                    if r.is_blame() { " (blame)" } else { "" },
                    p.fee_rate_sat_per_vb(),
                    p.min_input_count_by_round,
                    p.max_input_count_by_round,
                    p.max_suggested_amount,
                    remaining.num_seconds(),
                );
                println!(
                    "  timeouts: confirmation {}s, output registration {}s, signing {}s; coordination id '{}'; delay signing {}",
                    p.connection_confirmation_timeout.secs(),
                    p.output_registration_timeout.secs(),
                    p.transaction_signing_timeout.secs(),
                    p.coordination_identifier,
                    p.delay_transaction_signing
                );
                if r.phase() == Some(Phase::Ended) {
                    println!("  end state: {:?}", r.end_round_state());
                }
            }
        }
        Cmd::Daemon { wallets, rpc_bind, no_tor, tor_binary, wallet_dir } => {
            std::fs::create_dir_all(&cli.datadir)?;
            let tor_handle = if no_tor || cfg.use_tor.eq_ignore_ascii_case("Disabled") {
                None
            } else {
                Some(tor::ensure_tor(cli.socks.as_deref(), tor_binary.as_deref(), &cli.datadir).await?)
            };
            let socks = tor_handle.as_ref().map(|t| t.socks.clone());
            let d = daemon::Daemon::new(cfg.clone(), bitcoin::Network::Bitcoin, cli.datadir.clone(), socks, wallet_dir)?;
            for w in &wallets {
                match d.load_wallet(w).await {
                    Ok(_) => tracing::info!("wallet {w} loaded"),
                    Err(e) => tracing::error!("wallet {w}: {e}"),
                }
            }
            let bind = rpc_bind
                .or_else(|| cfg.json_rpc_server_prefixes.first().map(|p| p.trim_start_matches("http://").trim_end_matches('/').to_string()))
                .unwrap_or_else(|| "127.0.0.1:37128".to_string());
            let bind = bind.replace("localhost", "127.0.0.1");
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!("json-rpc listening on http://{bind}/ (auth {})", if cfg.json_rpc_user.is_empty() { "off" } else { "basic" });
            let app = rpc::router(d.clone());
            let sync = tokio::spawn(d.clone().run_sync_loop());
            let server = axum::serve(listener, app).with_graceful_shutdown({
                let d = d.clone();
                async move { d.shutdown.notified().await }
            });
            tokio::select! {
                r = server => { r?; }
                _ = tokio::signal::ctrl_c() => { d.shutdown.notify_waiters(); }
            }
            sync.abort();
            drop(tor_handle);
        }
        Cmd::ImportWasabiTxs { wallet, wallet_dir } => {
            let wdir = wallet_dir.unwrap_or_else(|| config::wasabi_data_dir().join("Wallets"));
            let km = wallet::KeyManager::load(&wdir.join(format!("{wallet}.json")))?;
            let net_dir = cli.datadir.join("Main");
            let store = wallet::WalletStore::open(&net_dir.join(format!("{wallet}.sqlite")))?;
            let tx_store = config::wasabi_data_dir().join("BitcoinStore/Main/ConfirmedTransactions/2/Transactions.sqlite");
            let (n, max_h) = wallet::import::from_wasabi_store(&tx_store, &km, &store)?;
            let filters = wallet::filters::FilterStore::open(Some(&config::wasabi_data_dir().join("BitcoinStore/Main/IndexStore/IndexStore.sqlite")), &net_dir.join("filters.sqlite"))?;
            let synced = km.file_height().unwrap_or(max_h).max(max_h);
            match filters.get(synced) {
                Some(row) => {
                    store.set_synced(synced, &row.block_hash)?;
                    println!("imported {n} transactions for {wallet}; synced height set to {synced}");
                }
                None => println!("imported {n} transactions for {wallet}; no filter for height {synced}, scan starts at the birth height"),
            }
        }
        Cmd::Devices => {
            match hw::TrezorDevice::enumerate().await {
                Ok(list) => {
                    for d in list {
                        println!("trezor  path={} model={} fw={} fingerprint={} error={}", d.path, d.model, d.firmware, d.fingerprint, d.error.unwrap_or_default());
                    }
                }
                Err(e) => println!("trezor bridge: {e}"),
            }
            match tokio::task::spawn_blocking(hw::ColdcardDevice::open).await? {
                Ok(dev) => {
                    println!("coldcard fingerprint={} xpub={}…", dev.master_fingerprint, &dev.master_xpub[..dev.master_xpub.len().min(12)]);
                    let dev = std::sync::Arc::new(dev);
                    let d2 = dev.clone();
                    let version = tokio::task::spawn_blocking(move || d2.version()).await?;
                    println!("coldcard version: {}", version.map(|v| v.replace('\n', " | ")).unwrap_or_else(|e| e.to_string()));
                    let d3 = dev.clone();
                    match tokio::task::spawn_blocking(move || d3.hsm_status()).await? {
                        Ok(s) => println!("coldcard hsm: active={} approval_wait={} policy_hash={} summary={}", s.active, s.approval_wait, s.policy_hash.unwrap_or_default(), s.summary.map(|x| x.replace('\n', " | ")).unwrap_or_default()),
                        Err(e) => println!("coldcard hsm: {e}"),
                    }
                }
                Err(e) => println!("coldcard: {e}"),
            }
        }
        Cmd::Mcp { url } => {
            let base = url.unwrap_or_else(|| cfg.json_rpc_server_prefixes.first().cloned().unwrap_or_else(|| "http://127.0.0.1:37128/".into()));
            let client = mcp::McpClient { base, user: cfg.json_rpc_user.clone(), password: cfg.json_rpc_password.clone() };
            client.serve_stdio().await?;
        }
        Cmd::Rpc { method, params, wallet, url } => {
            let params: serde_json::Value = match params {
                Some(p) => serde_json::from_str(&p)?,
                None => serde_json::json!([]),
            };
            println!("{}", serde_json::to_string_pretty(&rpc_call(&cfg, url, wallet.as_deref(), &method, params).await?)?);
        }
        Cmd::Unlock { wallet, ttl, url } => {
            use zeroize::Zeroize;
            let mut password = read_password(&format!("Password for wallet {wallet}: "))?;
            let r = rpc_result(&cfg, url, Some(&wallet), "unlockwallet", serde_json::json!([password, ttl])).await;
            password.zeroize();
            r?;
            println!("{wallet} unlocked for {ttl} s; startcoinjoin needs no password until then.");
        }
        Cmd::Lock { wallet, url } => {
            rpc_result(&cfg, url, Some(&wallet), "lockwallet", serde_json::json!([])).await?;
            println!("{wallet} locked; a running coinjoin ends after its round.");
        }
    }
    Ok(())
}

/// The `result` of a JSON-RPC call, or the daemon's error message as an error.
async fn rpc_result(cfg: &config::WasabiConfig, url: Option<String>, wallet: Option<&str>, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let v = rpc_call(cfg, url, wallet, method, params).await?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        anyhow::bail!("{}", e.get("message").and_then(|m| m.as_str()).unwrap_or("error"));
    }
    Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

/// One JSON-RPC call to a running daemon; the parsed reply (result or error object).
async fn rpc_call(cfg: &config::WasabiConfig, url: Option<String>, wallet: Option<&str>, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let base = url.unwrap_or_else(|| cfg.json_rpc_server_prefixes.first().cloned().unwrap_or_else(|| "http://127.0.0.1:37128/".into()));
    let target = match wallet {
        Some(w) => format!("{}/{}/", base.trim_end_matches('/'), w),
        None => base.clone(),
    };
    let body = serde_json::json!({"jsonrpc": "2.0", "id": "1", "method": method, "params": params});
    let mut req = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build()?.post(&target).header("content-type", "application/json").body(body.to_string());
    if !cfg.json_rpc_user.is_empty() {
        req = req.basic_auth(&cfg.json_rpc_user, Some(&cfg.json_rpc_password));
    }
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("daemon answered HTTP {status}: {text}"))
}

/// A line typed at the terminal with echo off (`stty`, nothing to link). Piped stdin is read as is;
/// a terminal without a working `stty` is refused rather than echoing the password.
fn read_password(prompt: &str) -> anyhow::Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    let echo_on = || {
        let _ = std::process::Command::new("stty").arg("echo").status();
    };
    let terminal = std::io::stdin().is_terminal();
    if terminal {
        if !std::process::Command::new("stty").arg("-echo").status().map(|s| s.success()).unwrap_or(false) {
            anyhow::bail!("cannot turn terminal echo off (no `stty`); not reading a password in the clear");
        }
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            echo_on();
            eprintln!();
            std::process::exit(130);
        });
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if terminal {
        echo_on();
        eprintln!();
    }
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}
