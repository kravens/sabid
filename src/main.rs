mod config;
mod daemon;
mod methods;
mod rpc;
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
    let cfg = config::WasabiConfig::load_default()?;
    let coordinator = cli.coordinator.clone().unwrap_or(cfg.coordinator_uri.clone());

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
        Cmd::Rpc { method, params, wallet, url } => {
            let base = url.unwrap_or_else(|| cfg.json_rpc_server_prefixes.first().cloned().unwrap_or_else(|| "http://127.0.0.1:37128/".into()));
            let target = match wallet {
                Some(w) => format!("{}/{}/", base.trim_end_matches('/'), w),
                None => base.clone(),
            };
            let params: serde_json::Value = match params {
                Some(p) => serde_json::from_str(&p)?,
                None => serde_json::json!([]),
            };
            let body = serde_json::json!({"jsonrpc": "2.0", "id": "1", "method": method, "params": params});
            let mut req = reqwest::Client::new().post(&target).header("content-type", "application/json").body(body.to_string());
            if !cfg.json_rpc_user.is_empty() {
                req = req.basic_auth(&cfg.json_rpc_user, Some(&cfg.json_rpc_password));
            }
            let text = req.send().await?.text().await?;
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
                Err(_) => println!("{text}"),
            }
        }
    }
    Ok(())
}
