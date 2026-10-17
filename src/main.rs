mod config;

use clap::{Parser, Subcommand};
use wasabi_proto::{CoordinatorClient, Phase, ProxyConfig, RoundStateRequest};

#[derive(Parser)]
#[command(name = "sabid", version, about = "Rust Wasabi daemon: WabiSabi coinjoin client, JSON-RPC, CLI, MCP")]
struct Cli {
    /// Coordinator base URI (default: CoordinatorUri from Wasabi's Config.json)
    #[arg(long, global = true)]
    coordinator: Option<String>,
    /// SOCKS5 proxy host:port for Tor (default: direct connection)
    #[arg(long, global = true)]
    socks: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the coordinator's rounds and verify their ids
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cli = Cli::parse();
    let cfg = config::WasabiConfig::load_default()?;
    let coordinator = cli.coordinator.clone().unwrap_or(cfg.coordinator_uri.clone());
    let proxy = cli.socks.clone().map(|socks5| ProxyConfig { socks5 });

    match cli.cmd {
        Cmd::Status => {
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
    }
    Ok(())
}
