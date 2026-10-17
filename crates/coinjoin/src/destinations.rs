//! `IDestinationProvider`: where coinjoin outputs go (the wallet's internal keys).

use crate::units::ScriptType;
use bitcoin::ScriptBuf;

pub trait DestinationProvider: Send + Sync {
    fn supported_script_types(&self) -> Vec<ScriptType>;
    /// `count` fresh internal (change-branch) scripts, taproot if preferred and available.
    fn next_destinations(&self, count: usize, prefer_taproot: bool) -> Vec<ScriptBuf>;
    /// Marks scripts used (`TrySetScriptStates(KeyState.Used)`) and persists.
    fn set_used(&self, scripts: &[ScriptBuf]);
}
