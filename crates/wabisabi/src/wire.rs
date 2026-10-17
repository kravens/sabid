//! Coordinator JSON shapes for credential requests/responses (`Serialization/WabiSabi.cs`) and
//! the mapping to libwabisabi's byte blobs (`wabisabi_ffi.h` header comment).
//!
//! Group elements are 33-byte compressed points, scalars 32-byte big-endian; the coordinator
//! writes them as upper-case hex.

use serde::{Deserialize, Serialize};
use wabisabi_sys::{GE_SIZE, MAC_SIZE, PRESENTATION_SIZE, SCALAR_SIZE, VALUE_SIZE};

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("truncated blob at offset {0}")]
    Truncated(usize),
    #[error("bad hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("element has {0} bytes, expected {1}")]
    BadLength(usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    #[serde(rename = "PublicNonces")]
    pub public_nonces: Vec<String>,
    #[serde(rename = "Responses")]
    pub responses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuanceRequest {
    #[serde(rename = "Ma")]
    pub ma: String,
    #[serde(rename = "BitCommitments")]
    pub bit_commitments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialPresentation {
    #[serde(rename = "Ca")]
    pub ca: String,
    #[serde(rename = "Cx0")]
    pub cx0: String,
    #[serde(rename = "Cx1")]
    pub cx1: String,
    #[serde(rename = "CV")]
    pub cv: String,
    #[serde(rename = "S")]
    pub s: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mac {
    #[serde(rename = "T")]
    pub t: String,
    #[serde(rename = "V")]
    pub v: String,
}

/// Both the zero and the real request share one JSON shape (`ICredentialsRequest`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialsRequest {
    #[serde(rename = "Delta")]
    pub delta: i64,
    #[serde(rename = "Presented")]
    pub presented: Vec<CredentialPresentation>,
    #[serde(rename = "Requested")]
    pub requested: Vec<IssuanceRequest>,
    #[serde(rename = "Proofs")]
    pub proofs: Vec<Proof>,
}

pub type ZeroCredentialsRequest = CredentialsRequest;
pub type RealCredentialsRequest = CredentialsRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialsResponse {
    #[serde(rename = "issuedCredentials")]
    pub issued_credentials: Vec<Mac>,
    #[serde(rename = "proofs")]
    pub proofs: Vec<Proof>,
}

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.off + n;
        let s = self.buf.get(self.off..end).ok_or(WireError::Truncated(self.off))?;
        self.off = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<usize, WireError> {
        Ok(self.take(1)?[0] as usize)
    }
    fn i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn hex(&mut self, n: usize) -> Result<String, WireError> {
        Ok(hex::encode_upper(self.take(n)?))
    }
    fn proof(&mut self) -> Result<Proof, WireError> {
        let n_nonces = self.u8()?;
        let n_responses = self.u8()?;
        let mut public_nonces = Vec::with_capacity(n_nonces);
        for _ in 0..n_nonces {
            public_nonces.push(self.hex(GE_SIZE)?);
        }
        let mut responses = Vec::with_capacity(n_responses);
        for _ in 0..n_responses {
            responses.push(self.hex(SCALAR_SIZE)?);
        }
        Ok(Proof { public_nonces, responses })
    }
    fn done(&self) -> Result<(), WireError> {
        if self.off == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::Truncated(self.off))
        }
    }
}

fn push_hex(out: &mut Vec<u8>, h: &str, expected: usize) -> Result<(), WireError> {
    let b = hex::decode(h)?;
    if b.len() != expected {
        return Err(WireError::BadLength(b.len(), expected));
    }
    out.extend_from_slice(&b);
    Ok(())
}

fn push_proof(out: &mut Vec<u8>, p: &Proof) -> Result<(), WireError> {
    out.push(p.public_nonces.len() as u8);
    out.push(p.responses.len() as u8);
    for n in &p.public_nonces {
        push_hex(out, n, GE_SIZE)?;
    }
    for r in &p.responses {
        push_hex(out, r, SCALAR_SIZE)?;
    }
    Ok(())
}

impl CredentialsRequest {
    /// `ZeroRequest : [Ma_0][Ma_1][proof_0][proof_1]`
    pub fn zero_from_blob(blob: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader { buf: blob, off: 0 };
        let mut requested = Vec::with_capacity(2);
        for _ in 0..2 {
            requested.push(IssuanceRequest { ma: r.hex(GE_SIZE)?, bit_commitments: vec![] });
        }
        let proofs = vec![r.proof()?, r.proof()?];
        r.done()?;
        Ok(Self { delta: 0, presented: vec![], requested, proofs })
    }

    /// `RealRequest : [delta:8][n_presented:1][pres...][n_requested:1][Ma + width bits ...][n_proofs:1][proofs...]`
    pub fn real_from_blob(blob: &[u8], width: usize) -> Result<Self, WireError> {
        let mut r = Reader { buf: blob, off: 0 };
        let delta = r.i64()?;
        let n_presented = r.u8()?;
        let mut presented = Vec::with_capacity(n_presented);
        for _ in 0..n_presented {
            presented.push(CredentialPresentation {
                ca: r.hex(GE_SIZE)?,
                cx0: r.hex(GE_SIZE)?,
                cx1: r.hex(GE_SIZE)?,
                cv: r.hex(GE_SIZE)?,
                s: r.hex(GE_SIZE)?,
            });
        }
        let n_requested = r.u8()?;
        let mut requested = Vec::with_capacity(n_requested);
        for _ in 0..n_requested {
            let ma = r.hex(GE_SIZE)?;
            let mut bit_commitments = Vec::with_capacity(width);
            for _ in 0..width {
                bit_commitments.push(r.hex(GE_SIZE)?);
            }
            requested.push(IssuanceRequest { ma, bit_commitments });
        }
        let n_proofs = r.u8()?;
        let mut proofs = Vec::with_capacity(n_proofs);
        for _ in 0..n_proofs {
            proofs.push(r.proof()?);
        }
        r.done()?;
        Ok(Self { delta, presented, requested, proofs })
    }

    /// Inverse of [`Self::real_from_blob`] (used by the issuer side / tests).
    pub fn real_to_blob(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.delta.to_le_bytes());
        out.push(self.presented.len() as u8);
        for p in &self.presented {
            for e in [&p.ca, &p.cx0, &p.cx1, &p.cv, &p.s] {
                push_hex(&mut out, e, GE_SIZE)?;
            }
        }
        out.push(self.requested.len() as u8);
        for q in &self.requested {
            push_hex(&mut out, &q.ma, GE_SIZE)?;
            for b in &q.bit_commitments {
                push_hex(&mut out, b, GE_SIZE)?;
            }
        }
        out.push(self.proofs.len() as u8);
        for p in &self.proofs {
            push_proof(&mut out, p)?;
        }
        Ok(out)
    }

    pub fn zero_to_blob(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        for q in &self.requested {
            push_hex(&mut out, &q.ma, GE_SIZE)?;
        }
        for p in &self.proofs {
            push_proof(&mut out, p)?;
        }
        Ok(out)
    }
}

impl CredentialsResponse {
    /// `Response : [n_issued:1][mac_0]...[proof_0]...` with `mac = [t:32][V:33]`
    pub fn to_blob(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        out.push(self.issued_credentials.len() as u8);
        for m in &self.issued_credentials {
            push_hex(&mut out, &m.t, SCALAR_SIZE)?;
            push_hex(&mut out, &m.v, GE_SIZE)?;
        }
        for p in &self.proofs {
            push_proof(&mut out, p)?;
        }
        Ok(out)
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader { buf: blob, off: 0 };
        let n = r.u8()?;
        let mut issued_credentials = Vec::with_capacity(n);
        for _ in 0..n {
            issued_credentials.push(Mac { t: r.hex(SCALAR_SIZE)?, v: r.hex(GE_SIZE)? });
        }
        let mut proofs = Vec::with_capacity(n);
        for _ in 0..n {
            proofs.push(r.proof()?);
        }
        r.done()?;
        Ok(Self { issued_credentials, proofs })
    }
}

/// Sizes the C side uses, re-exported for callers that slice credential blobs.
pub const CREDENTIAL_BYTES: usize = VALUE_SIZE + SCALAR_SIZE + MAC_SIZE;
pub const PRESENTATION_BYTES: usize = PRESENTATION_SIZE;
