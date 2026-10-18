//! Hardware wallet signers for sabid. Trezor first (Preview 8 parity): classic bridge HTTP API
//! (pytrezord / trezord), SLIP-25 coinjoin account, AuthorizeCoinJoin, SLIP-19 ownership proofs,
//! preauthorized SignTx with `coinjoin_request`.

pub mod coldcard {
    pub mod device;
    pub mod hid;
    pub mod keychain;
    pub mod policy;
    pub mod transport;
}
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
pub use coldcard::device::ColdcardDevice;
pub use coldcard::keychain::{ColdcardKeyChain, KeyInfo as ColdcardKeyInfo};
pub use coldcard::transport::ColdcardError;
