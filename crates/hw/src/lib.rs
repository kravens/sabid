//! Hardware wallet signers for sabid. Trezor first (Preview 8 parity): classic bridge HTTP API
//! (pytrezord / trezord), SLIP-25 coinjoin account, AuthorizeCoinJoin, SLIP-19 ownership proofs,
//! preauthorized SignTx with `coinjoin_request`.

pub mod proto;
pub mod trezor {
    pub mod bridge;
    pub mod device;
    pub mod keychain;
    pub mod messages;
}

pub use trezor::bridge::TrezorError;
pub use trezor::device::{DeviceInfo, TrezorDevice};
pub use trezor::keychain::TrezorKeyChain;
