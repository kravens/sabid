//! WabiSabi anonymous-credential client, wire-compatible with Wasabi Wallet / NWabiSabi.
//!
//! * [`client`]: credential requests and response validation over libwabisabi (C, vendored).
//! * [`wire`]: the coordinator's JSON shapes and their byte-blob equivalents.
//! * [`round_hash`]: recomputation of round ids (Strobe transcript), to refuse tagged rounds.

pub mod client;
pub mod round_hash;
pub mod wire;

pub use client::{init, Credential, CredentialClient, CredentialIssuer, Error, IssuerParameters, RequestData, ValidationState};
