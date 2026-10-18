//! sabid must not run beside Wasabi Wallet: both would register the same coins with the
//! coordinator, and Wasabi rewrites the stores sabid reads. Detection is by process, on Linux.

const DLLS: [&str; 3] = ["WalletWasabi.Fluent.Desktop.dll", "WalletWasabi.Fluent.dll", "WalletWasabi.Daemon.dll"];

/// A Wasabi GUI or daemon process: the native `wassabee`/`wassabeed` binaries, or `dotnet` running
/// their assemblies. A shell that merely mentions the name (`grep wassabee`) does not count.
pub fn is_wasabi_process(comm: &str, argv: &[String]) -> bool {
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
    let native = |s: &str| matches!(s, "wassabee" | "wassabeed");
    native(comm) || argv.first().map(|a| native(&base(a))).unwrap_or(false) || argv.iter().any(|a| DLLS.iter().any(|d| a.ends_with(d)))
}

/// Description of a running Wasabi process, if any.
pub fn wasabi_running() -> Option<String> {
    let me = std::process::id();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        if pid == me {
            continue;
        }
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        let argv: Vec<String> = std::fs::read(entry.path().join("cmdline")).unwrap_or_default().split(|b| *b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).to_string()).collect();
        if is_wasabi_process(comm.trim(), &argv) {
            return Some(format!("{} (pid {pid})", argv.first().cloned().unwrap_or_else(|| comm.trim().to_string())));
        }
    }
    None
}

pub const WARNING: &str = "Do not run sabid and Wasabi Wallet at the same time: both would register the same coins with the coordinator, and Wasabi rewrites the stores sabid reads. Close Wasabi, then start sabid.";

#[cfg(test)]
mod tests {
    use super::is_wasabi_process;
    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn recognises_wasabi_and_ignores_lookalikes() {
        assert!(is_wasabi_process("wassabee", &v(&["/tmp/.mount_x/usr/bin/wassabee"])));
        assert!(is_wasabi_process("wassabeed", &v(&["wassabeed", "daemon"])));
        assert!(is_wasabi_process("dotnet", &v(&["dotnet", "/opt/wasabi/WalletWasabi.Fluent.Desktop.dll"])));
        assert!(!is_wasabi_process("bash", &v(&["grep", "wassabee"])));
        assert!(!is_wasabi_process("dotnet", &v(&["dotnet", "WalletWasabi.Coordinator.dll"])));
        assert!(!is_wasabi_process("sabid", &v(&["sabid", "daemon", "--wallet", "wassabee"])));
    }
}
