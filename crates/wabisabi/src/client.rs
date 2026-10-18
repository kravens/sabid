//! Safe client API over libwabisabi, mirroring `WabiSabi.Crypto.WabiSabiClient`.

use crate::wire::{CredentialsRequest, CredentialsResponse, WireError};
use rand::RngCore;
use std::os::raw::c_int;
use std::sync::Once;
use wabisabi_sys as sys;

static INIT: Once = Once::new();

pub fn init() {
    INIT.call_once(|| unsafe { sys::wabisabi_init() });
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("libwabisabi error {code} ({})", error_name(*code))]
    Native { code: i32 },
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("{0}")]
    Invalid(&'static str),
}

pub fn error_name(code: i32) -> &'static str {
    match code {
        0 => "ok",
        1 => "null pointer",
        2 => "invalid length",
        3 => "parse",
        4 => "invalid proof",
        5 => "invalid credential count",
        6 => "invalid bit commitment",
        7 => "serial duplicated",
        8 => "serial reused",
        9 => "negative balance",
        10 => "serial set full",
        11 => "buffer too small",
        12 => "alloc",
        13 => "invalid presentation count",
        14 => "issued count mismatch",
        15 => "credential duplicated",
        _ => "unknown",
    }
}

fn check(code: c_int) -> Result<(), Error> {
    if code == sys::WABISABI_OK {
        Ok(())
    } else {
        Err(Error::Native { code })
    }
}

pub const CREDENTIAL_NUMBER: usize = sys::CREDENTIAL_COUNT;

/// `[value:8 LE][randomness:32][mac_t:32][mac_V:33]`
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(pub [u8; sys::CREDENTIAL_SIZE]);

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credential(value={}, mac_t={})", self.value(), hex::encode(&self.0[40..48]))
    }
}

impl Credential {
    pub fn value(&self) -> i64 {
        i64::from_le_bytes(self.0[..8].try_into().unwrap())
    }
    pub fn mac_t(&self) -> &[u8] {
        &self.0[40..72]
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        b.try_into().ok().map(Credential)
    }
}

#[derive(Clone)]
pub struct ValidationState(pub [u8; sys::VALIDATION_SIZE]);

#[derive(Clone)]
pub struct IssuerParameters(pub [u8; sys::IPARAMS_SIZE]);

impl IssuerParameters {
    pub fn from_hex(cw: &str, i: &str) -> Result<Self, Error> {
        let cw = hex::decode(cw).map_err(WireError::from)?;
        let i = hex::decode(i).map_err(WireError::from)?;
        if cw.len() != sys::GE_SIZE || i.len() != sys::GE_SIZE {
            return Err(Error::Invalid("issuer parameters must be two 33-byte points"));
        }
        let mut out = [0u8; sys::IPARAMS_SIZE];
        out[..33].copy_from_slice(&cw);
        out[33..].copy_from_slice(&i);
        Ok(Self(out))
    }
}

/// Smallest `w` with `2^w >= v` (libwabisabi `ceil_log2_client`, equal to
/// C#'s `Math.Ceiling(Math.Log2(v))` on the values the protocol uses).
pub fn range_proof_width(max_amount: i64) -> usize {
    let mut w = 0;
    let mut n: i64 = 1;
    while n < max_amount {
        n <<= 1;
        w += 1;
    }
    w
}

/// One client per credential type (amount / vsize) per round, as in Wasabi.
#[derive(Clone)]
pub struct CredentialClient {
    iparams: IssuerParameters,
    max_amount: i64,
}

pub struct RequestData {
    pub request: CredentialsRequest,
    pub validation: ValidationState,
}

impl CredentialClient {
    pub fn new(iparams: IssuerParameters, range_proof_upper_bound: i64) -> Self {
        init();
        Self { iparams, max_amount: range_proof_upper_bound }
    }

    pub fn range_proof_width(&self) -> usize {
        range_proof_width(self.max_amount)
    }

    fn seed() -> [u8; sys::RAND_SIZE] {
        let mut s = [0u8; sys::RAND_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    }

    /// Null request: asks for two zero-value credentials, presents nothing.
    pub fn create_request_for_zero_amount(&self) -> Result<RequestData, Error> {
        self.create_request_for_zero_amount_seeded(Self::seed())
    }

    pub fn create_request_for_zero_amount_seeded(&self, seed: [u8; sys::RAND_SIZE]) -> Result<RequestData, Error> {
        let mut req = vec![0u8; sys::MAX_REQUEST_SIZE];
        let mut req_len: c_int = 0;
        let mut val = [0u8; sys::VALIDATION_SIZE];
        check(unsafe {
            sys::wabisabi_client_create_zero_request(
                seed.as_ptr(),
                req.as_mut_ptr(),
                req.len() as c_int,
                &mut req_len,
                val.as_mut_ptr(),
            )
        })?;
        let request = CredentialsRequest::zero_from_blob(&req[..req_len as usize])?;
        Ok(RequestData { request, validation: ValidationState(val) })
    }

    /// Presents `credentials` (must be exactly two, zero-valued ones pad) and requests `amounts`
    /// (padded with zeros to two; empty = presentation-only request, used for output registration).
    pub fn create_request(&self, amounts: &[i64], credentials: &[Credential]) -> Result<RequestData, Error> {
        self.create_request_seeded(amounts, credentials, Self::seed())
    }

    pub fn create_request_seeded(
        &self,
        amounts: &[i64],
        credentials: &[Credential],
        seed: [u8; sys::RAND_SIZE],
    ) -> Result<RequestData, Error> {
        if amounts.len() > CREDENTIAL_NUMBER {
            return Err(Error::Invalid("at most two credentials can be requested"));
        }
        if credentials.len() > CREDENTIAL_NUMBER {
            return Err(Error::Invalid("at most two credentials can be presented"));
        }
        let mut amounts_padded = amounts.to_vec();
        if !amounts_padded.is_empty() {
            amounts_padded.resize(CREDENTIAL_NUMBER, 0);
        }
        let creds: Vec<u8> = credentials.iter().flat_map(|c| c.0).collect();
        let mut req = vec![0u8; sys::MAX_REQUEST_SIZE];
        let mut req_len: c_int = 0;
        let mut val = [0u8; sys::VALIDATION_SIZE];
        let code = if amounts_padded.is_empty() {
            unsafe {
                sys::wabisabi_client_create_present_request(
                    self.iparams.0.as_ptr(),
                    self.max_amount,
                    creds.as_ptr(),
                    credentials.len() as c_int,
                    seed.as_ptr(),
                    req.as_mut_ptr(),
                    req.len() as c_int,
                    &mut req_len,
                    val.as_mut_ptr(),
                )
            }
        } else {
            unsafe {
                sys::wabisabi_client_create_real_request(
                    self.iparams.0.as_ptr(),
                    self.max_amount,
                    amounts_padded.as_ptr(),
                    amounts_padded.len() as c_int,
                    creds.as_ptr(),
                    credentials.len() as c_int,
                    seed.as_ptr(),
                    req.as_mut_ptr(),
                    req.len() as c_int,
                    &mut req_len,
                    val.as_mut_ptr(),
                )
            }
        };
        check(code)?;
        let request = CredentialsRequest::real_from_blob(&req[..req_len as usize], self.range_proof_width())?;
        Ok(RequestData { request, validation: ValidationState(val) })
    }

    /// Verifies the issuer's proofs and returns the two credentials that were requested.
    pub fn handle_response(&self, response: &CredentialsResponse, validation: &ValidationState) -> Result<Vec<Credential>, Error> {
        let blob = response.to_blob()?;
        let mut creds = vec![0u8; CREDENTIAL_NUMBER * sys::CREDENTIAL_SIZE];
        let mut n: c_int = 0;
        check(unsafe {
            sys::wabisabi_client_handle_response(
                self.iparams.0.as_ptr(),
                blob.as_ptr(),
                blob.len() as c_int,
                validation.0.as_ptr(),
                creds.as_mut_ptr(),
                creds.len() as c_int,
                &mut n,
            )
        })?;
        Ok(creds[..n as usize * sys::CREDENTIAL_SIZE]
            .chunks_exact(sys::CREDENTIAL_SIZE)
            .map(|c| Credential(c.try_into().unwrap()))
            .collect())
    }
}

/// Issuer side (coordinator). Used as a test oracle and by a future local coordinator.
pub struct CredentialIssuer {
    sk: [u8; sys::SK_SIZE],
    max_amount: i64,
    mstate: Vec<u8>,
}

impl CredentialIssuer {
    pub fn new(sk: [u8; sys::SK_SIZE], max_amount: i64) -> Self {
        init();
        Self { sk, max_amount, mstate: Vec::new() }
    }

    pub fn random(max_amount: i64) -> Self {
        let mut sk = [0u8; sys::SK_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut sk);
        // Keep every scalar below the group order: clearing the top byte is enough.
        for i in 0..5 {
            sk[i * 32] = 0;
        }
        Self::new(sk, max_amount)
    }

    pub fn parameters(&self) -> Result<IssuerParameters, Error> {
        let mut out = [0u8; sys::IPARAMS_SIZE];
        check(unsafe { sys::wabisabi_iparams_from_sk(self.sk.as_ptr(), out.as_mut_ptr()) })?;
        Ok(IssuerParameters(out))
    }

    pub fn balance(&self) -> i64 {
        self.mstate.get(..8).map(|b| i64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
    }

    fn handle(&mut self, blob: &[u8], zero: bool) -> Result<CredentialsResponse, Error> {
        let mut resp = vec![0u8; sys::MAX_REQUEST_SIZE];
        let mut resp_len: c_int = 0;
        let mut mstate = [0u8; sys::ISSUER_MSTATE_MAX_SIZE];
        let mut mstate_len: c_int = 0;
        let seed = CredentialClient::seed();
        let f = if zero { sys::wabisabi_issuer_handle_zero } else { sys::wabisabi_issuer_handle_real };
        let mstate_in = if self.mstate.is_empty() { std::ptr::null() } else { self.mstate.as_ptr() };
        check(unsafe {
            f(
                self.sk.as_ptr(),
                self.max_amount,
                mstate_in,
                self.mstate.len() as c_int,
                blob.as_ptr(),
                blob.len() as c_int,
                seed.as_ptr(),
                resp.as_mut_ptr(),
                resp.len() as c_int,
                &mut resp_len,
                mstate.as_mut_ptr(),
                mstate.len() as c_int,
                &mut mstate_len,
            )
        })?;
        self.mstate = mstate[..mstate_len as usize].to_vec();
        Ok(CredentialsResponse::from_blob(&resp[..resp_len as usize])?)
    }

    pub fn handle_zero_request(&mut self, req: &CredentialsRequest) -> Result<CredentialsResponse, Error> {
        self.handle(&req.zero_to_blob()?, true)
    }

    pub fn handle_real_request(&mut self, req: &CredentialsRequest) -> Result<CredentialsResponse, Error> {
        self.handle(&req.real_to_blob()?, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_matches_dotnet_ceil_log2() {
        assert_eq!(range_proof_width(2_100_000_000), 31);
        assert_eq!(range_proof_width(255), 8);
        assert_eq!(range_proof_width(256), 8);
        assert_eq!(range_proof_width(257), 9);
        assert_eq!(range_proof_width(1), 0);
    }

    /// zero -> issue -> real (present zeros, request amounts) -> issue -> presentation-only,
    /// through the JSON shapes the coordinator sees, against the C issuer.
    #[test]
    fn full_credential_roundtrip_through_json() {
        let max = 2_100_000_000i64;
        let mut issuer = CredentialIssuer::random(max);
        let client = CredentialClient::new(issuer.parameters().unwrap(), max);

        let zero = client.create_request_for_zero_amount().unwrap();
        let zero_json = serde_json::to_string(&zero.request).unwrap();
        assert!(zero_json.contains("\"Delta\":0"));
        let zero_req: CredentialsRequest = serde_json::from_str(&zero_json).unwrap();
        let resp = issuer.handle_zero_request(&zero_req).unwrap();
        let resp: CredentialsResponse = serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        let zeros = client.handle_response(&resp, &zero.validation).unwrap();
        assert_eq!(zeros.len(), 2);
        assert!(zeros.iter().all(|c| c.value() == 0));

        // Real: present the two zero credentials, request 100_000 + 0 (delta = 100_000).
        let real = client.create_request(&[100_000], &zeros).unwrap();
        assert_eq!(real.request.delta, 100_000);
        assert_eq!(real.request.presented.len(), 2);
        assert_eq!(real.request.requested.len(), 2);
        assert_eq!(real.request.requested[0].bit_commitments.len(), 31);
        assert_eq!(real.request.proofs.len(), 5);
        let real_req: CredentialsRequest =
            serde_json::from_str(&serde_json::to_string(&real.request).unwrap()).unwrap();
        let resp = issuer.handle_real_request(&real_req).unwrap();
        let creds = client.handle_response(&resp, &real.validation).unwrap();
        let mut values: Vec<i64> = creds.iter().map(|c| c.value()).collect();
        values.sort();
        assert_eq!(values, vec![0, 100_000]);
        assert_eq!(issuer.balance(), 100_000);

        // Reissue: split 100_000 into 60_000 + 40_000 (delta 0).
        let split = client.create_request(&[60_000, 40_000], &creds).unwrap();
        assert_eq!(split.request.delta, 0);
        let resp = issuer.handle_real_request(&split.request).unwrap();
        let creds2 = client.handle_response(&resp, &split.validation).unwrap();
        let mut values: Vec<i64> = creds2.iter().map(|c| c.value()).collect();
        values.sort();
        assert_eq!(values, vec![40_000, 60_000]);

        // Presentation-only (output registration): spend both, request nothing (delta -100_000).
        let present = client.create_request(&[], &creds2).unwrap();
        // No requested slots: the validation state carries zeros there, never an unset point
        // (serializing one made secp256k1 abort the daemon in a live round).
        assert!(present.validation.0[207..].iter().all(|b| *b == 0));
        assert_eq!(present.request.delta, -100_000);
        assert_eq!(present.request.requested.len(), 0);
        assert_eq!(present.request.presented.len(), 2);
        assert_eq!(present.request.proofs.len(), 3);
        let resp = issuer.handle_real_request(&present.request).unwrap();
        assert_eq!(resp.issued_credentials.len(), 0);
        assert_eq!(issuer.balance(), 0);
    }

    #[test]
    fn tampered_response_is_rejected() {
        let max = 255;
        let mut issuer = CredentialIssuer::random(max);
        let client = CredentialClient::new(issuer.parameters().unwrap(), max);
        let zero = client.create_request_for_zero_amount().unwrap();
        let mut resp = issuer.handle_zero_request(&zero.request).unwrap();
        resp.issued_credentials.swap(0, 1);
        assert!(client.handle_response(&resp, &zero.validation).is_err());
    }
}

