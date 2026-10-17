//! Tor: reuse a SOCKS proxy that already answers (Wasabi's 37150, system 9050), else spawn a
//! `tor` binary with Wasabi's settings (stream isolation by SOCKS auth).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const WASABI_SOCKS: &str = "127.0.0.1:37150";

/// SOCKS5 greeting; true when something speaks SOCKS5 there.
pub async fn probe_socks(addr: &str) -> bool {
    let Ok(Ok(mut s)) = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await else { return false };
    if s.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 2];
    matches!(tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut buf)).await, Ok(Ok(_)) if buf[0] == 0x05)
}

pub fn find_tor_binary(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.exists().then(|| p.to_path_buf());
    }
    let home = dirs::home_dir().unwrap_or_default();
    let candidates = [
        home.join("Documents/GitHub/wasabi-preview8/WalletWasabi/BundledApps/Binaries/linux-x64/Tor/tor"),
        home.join("Documents/GitHub/WalletWasabi/WalletWasabi/BundledApps/Binaries/linux-x64/Tor/tor"),
        PathBuf::from("/usr/bin/tor"),
        PathBuf::from("/usr/local/bin/tor"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

pub struct TorHandle {
    pub socks: String,
    child: Option<std::process::Child>,
}

impl Drop for TorHandle {
    fn drop(&mut self) {
        if let Some(c) = &mut self.child {
            let _ = c.kill();
        }
    }
}

/// Returns a usable SOCKS5 address (and the child when sabid started tor itself).
pub async fn ensure_tor(preferred: Option<&str>, tor_binary: Option<&Path>, datadir: &Path) -> anyhow::Result<TorHandle> {
    let mut candidates: Vec<String> = preferred.map(str::to_string).into_iter().collect();
    candidates.push(WASABI_SOCKS.to_string());
    candidates.push("127.0.0.1:9050".to_string());
    for c in &candidates {
        if probe_socks(c).await {
            tracing::info!("using existing tor socks at {c}");
            return Ok(TorHandle { socks: c.clone(), child: None });
        }
    }
    let bin = find_tor_binary(tor_binary).ok_or_else(|| anyhow::anyhow!("no SOCKS proxy answers and no tor binary found (use --socks or --tor-binary)"))?;
    let tor_dir = datadir.join("tor");
    std::fs::create_dir_all(&tor_dir)?;
    let socks = preferred.unwrap_or(WASABI_SOCKS).to_string();
    let log = tor_dir.join("tor.log");
    tracing::info!("starting tor {} on {socks}", bin.display());
    // Wasabi's bundled tor ships its own libevent/libssl next to the binary.
    let lib_dir = bin.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let ld = std::env::var("LD_LIBRARY_PATH").map(|v| format!("{}:{v}", lib_dir.display())).unwrap_or_else(|_| lib_dir.display().to_string());
    let stderr_log = std::fs::File::create(tor_dir.join("tor.stderr.log")).map(Stdio::from).unwrap_or_else(|_| Stdio::null());
    let child = Command::new(&bin)
        .env("LD_LIBRARY_PATH", ld)
        .args([
            "--SOCKSPort", &format!("{socks} ExtendedErrors KeepAliveIsolateSOCKSAuth"),
            "--SocksTimeout", "30",
            "--DataDirectory", &tor_dir.to_string_lossy(),
            "--Log", &format!("notice file {}", log.display()),
            "--TruncateLogFile", "1",
            "--NumEntryGuards", "3",
            "--NumPrimaryGuards", "3",
            "--ConfluxEnabled", "1",
            "--ConfluxClientUX", "throughput",
        ])
        .stdout(Stdio::null())
        .stderr(stderr_log)
        .spawn()?;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(180) {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if probe_socks(&socks).await {
            tracing::info!("tor socks up at {socks} (bootstrap continues in the background)");
            return Ok(TorHandle { socks, child: Some(child) });
        }
    }
    anyhow::bail!("tor did not open its SOCKS port within 3 minutes; see {}", log.display())
}
