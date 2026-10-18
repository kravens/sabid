//! `sabid bench`: numbers for the parts of a wallet daemon that cost time. Filter matching (the
//! CPU side of a sync), wallet loading (keys, store, coin/history view) and RPC latency against a
//! running daemon. Prints a Markdown table so results can be pasted into BENCHMARKS.md.

use std::path::Path;
use std::time::Instant;

fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|kb| kb.parse::<f64>().ok()))
        .map(|kb| kb / 1024.0)
        .unwrap_or(0.0)
}

/// Filter matching throughput with the wallet's scripts over `count` filters from `from`.
pub fn filters(wallet_file: &Path, filter_store: &wallet::filters::FilterStore, from: u32, count: usize, threads: usize) -> anyhow::Result<()> {
    let mut km = wallet::KeyManager::load(wallet_file)?;
    km.ensure_gap();
    let scripts = km.scripts();
    let mut height = from;
    let mut done = 0usize;
    let mut matches = 0usize;
    let mut read_secs = 0.0f64;
    let mut match_secs = 0.0f64;
    let mut slowest = 0.0f64;
    while done < count {
        let t = Instant::now();
        let rows = filter_store.range(height, 2000.min(count - done))?;
        read_secs += t.elapsed().as_secs_f64();
        if rows.is_empty() {
            break;
        }
        let t = Instant::now();
        let m = wallet::sync::match_filters_with(&scripts, &rows, threads)?;
        let secs = t.elapsed().as_secs_f64();
        match_secs += secs;
        slowest = slowest.max(secs);
        matches += m.len();
        done += rows.len();
        height = rows.last().map(|r| r.height + 1).unwrap_or(height);
    }
    println!(
        "| filters matched | {done} filters from {from}, {} scripts, {threads} thread(s) | {:.0} filters/s matching ({:.2} s), store read {:.2} s, {matches} matches, slowest batch {:.3} s |",
        scripts.len(),
        done as f64 / match_secs.max(1e-9),
        match_secs,
        read_secs,
        slowest
    );
    Ok(())
}

/// Wallet load: key file, transaction store, coin/history view.
pub fn load(wallet_file: &Path, store_file: &Path) -> anyhow::Result<()> {
    let t = Instant::now();
    let mut km = wallet::KeyManager::load(wallet_file)?;
    let t_keys = t.elapsed();
    let store = wallet::WalletStore::open(store_file)?;
    let txs = store.all_txs()?;
    let t_store = t.elapsed() - t_keys;
    let t2 = Instant::now();
    let (state, _) = wallet::store::WalletState::build(&txs, &mut km);
    let t_state = t2.elapsed();
    println!(
        "| wallet load | {} keys, {} transactions, {} coins | keys {:.0} ms, store {:.0} ms, coin view {:.0} ms, total {:.0} ms, RSS {:.0} MB |",
        km.keys.len(),
        txs.len(),
        state.coins.len(),
        t_keys.as_secs_f64() * 1e3,
        t_store.as_secs_f64() * 1e3,
        t_state.as_secs_f64() * 1e3,
        t.elapsed().as_secs_f64() * 1e3,
        rss_mb()
    );
    Ok(())
}

/// RPC latency of a running daemon (sabid or Wasabi): p50 / p95 over `n` calls per method.
pub async fn rpc(base: &str, user: &str, password: &str, wallet: &str, n: usize) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build()?;
    let call = |method: &'static str, wallet_scoped: bool| {
        let client = client.clone();
        let target = if wallet_scoped { format!("{}/{}/", base.trim_end_matches('/'), wallet) } else { base.to_string() };
        async move {
            let mut req = client.post(&target).header("content-type", "application/json").body(format!("{{\"jsonrpc\":\"2.0\",\"id\":\"b\",\"method\":\"{method}\",\"params\":[]}}"));
            if !user.is_empty() {
                req = req.basic_auth(user, Some(password));
            }
            let t = Instant::now();
            let text = req.send().await?.text().await?;
            anyhow::ensure!(text.contains("\"result\""), "{method}: {}", text.chars().take(120).collect::<String>());
            Ok::<f64, anyhow::Error>(t.elapsed().as_secs_f64() * 1e3)
        }
    };
    for (method, scoped) in [("getstatus", false), ("getwalletinfo", true), ("listunspentcoins", true), ("gethistory", true)] {
        let mut ms = Vec::with_capacity(n);
        for _ in 0..n {
            ms.push(call(method, scoped).await?);
        }
        ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |q: f64| ms[((ms.len() as f64 - 1.0) * q) as usize];
        println!("| rpc {method} | {n} calls | p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms |", p(0.5), p(0.95), ms[ms.len() - 1]);
    }
    Ok(())
}
