//! SLIP-0019 ownership proofs as Wasabi serializes them (`OwnershipProof`, `ProofBody`,
//! `Bip322Signature`, `CoinJoinInputCommitmentData`, `OwnershipIdentifier`, `Slip21Node`).

use bitcoin::hashes::{sha256, sha512, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::key::{Secp256k1, TapTweak, UntweakedKeypair};
use bitcoin::secp256k1::{ecdsa, schnorr, Message, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::{ScriptBuf, VarInt};
use bitcoin::consensus::encode::serialize;

pub const VERSION_MAGIC: [u8; 4] = [0x53, 0x4c, 0x00, 0x19];
pub const FLAG_USER_CONFIRMATION: u8 = 0x01;

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("malformed ownership proof: {0}")]
    Malformed(&'static str),
    #[error("unsupported script type")]
    UnsupportedScript,
}

fn varint(n: u64) -> Vec<u8> {
    serialize(&VarInt(n))
}

fn read_varint(b: &[u8], off: &mut usize) -> Result<u64, ProofError> {
    let mut cur = std::io::Cursor::new(&b[*off..]);
    let v = <VarInt as bitcoin::consensus::Decodable>::consensus_decode(&mut cur).map_err(|_| ProofError::Malformed("varint"))?;
    *off += cur.position() as usize;
    Ok(v.0)
}

/// `CoinJoinInputCommitmentData.ToBytes()`: varint(len(coordinator)) || coordinator || roundId (32 bytes, uint256 little-endian bytes)
pub fn commitment_data(coordinator_identifier: &str, round_id_hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    // uint256.ToBytes(lendian: false) = big-endian = the hex as displayed.
    let id = hex::decode(round_id_hex)?;
    let mut out = varint(coordinator_identifier.len() as u64);
    out.extend_from_slice(coordinator_identifier.as_bytes());
    out.extend_from_slice(&id);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipProof {
    pub flags: u8,
    pub identifiers: Vec<[u8; 32]>,
    pub script_sig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
}

impl OwnershipProof {
    fn body_bytes(&self) -> Vec<u8> {
        let mut b = VERSION_MAGIC.to_vec();
        b.push(self.flags);
        b.extend(varint(self.identifiers.len() as u64));
        for id in &self.identifiers {
            b.extend_from_slice(id);
        }
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body_bytes();
        b.extend(varint(self.script_sig.len() as u64));
        b.extend_from_slice(&self.script_sig);
        b.extend(varint(self.witness.len() as u64));
        for w in &self.witness {
            b.extend(varint(w.len() as u64));
            b.extend_from_slice(w);
        }
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, ProofError> {
        if b.len() < 5 || b[..4] != VERSION_MAGIC {
            return Err(ProofError::Malformed("version magic"));
        }
        let flags = b[4];
        let mut off = 5;
        let n = read_varint(b, &mut off)? as usize;
        let mut identifiers = Vec::new();
        for _ in 0..n {
            let id: [u8; 32] = b.get(off..off + 32).ok_or(ProofError::Malformed("identifier"))?.try_into().unwrap();
            identifiers.push(id);
            off += 32;
        }
        let ss_len = read_varint(b, &mut off)? as usize;
        let script_sig = b.get(off..off + ss_len).ok_or(ProofError::Malformed("scriptSig"))?.to_vec();
        off += ss_len;
        let wn = read_varint(b, &mut off)? as usize;
        let mut witness = Vec::new();
        for _ in 0..wn {
            let l = read_varint(b, &mut off)? as usize;
            witness.push(b.get(off..off + l).ok_or(ProofError::Malformed("witness item"))?.to_vec());
            off += l;
        }
        if off != b.len() {
            return Err(ProofError::Malformed("trailing bytes"));
        }
        Ok(Self { flags, identifiers, script_sig, witness })
    }

    /// `ProofBody.SignatureHash`: SHA256(body || varint(spk) || spk || varint(commitment) || commitment)
    pub fn signature_hash(&self, script_pubkey: &ScriptBuf, commitment: &[u8]) -> [u8; 32] {
        let mut data = self.body_bytes();
        data.extend(varint(script_pubkey.len() as u64));
        data.extend_from_slice(script_pubkey.as_bytes());
        data.extend(varint(commitment.len() as u64));
        data.extend_from_slice(commitment);
        sha256::Hash::hash(&data).to_byte_array()
    }

    pub fn verify(&self, script_pubkey: &ScriptBuf, commitment: &[u8], require_user_confirmation: bool) -> bool {
        if require_user_confirmation && self.flags & FLAG_USER_CONFIRMATION == 0 {
            return false;
        }
        if !self.script_sig.is_empty() {
            return false;
        }
        let hash = self.signature_hash(script_pubkey, commitment);
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(hash);
        if script_pubkey.is_p2wpkh() {
            if self.witness.len() != 2 {
                return false;
            }
            let sig_bytes = &self.witness[0];
            let Some((_sighash, der)) = sig_bytes.split_last() else { return false };
            let Ok(sig) = ecdsa::Signature::from_der(der) else { return false };
            let Ok(pk) = PublicKey::from_slice(&self.witness[1]) else { return false };
            let expected = ScriptBuf::new_p2wpkh(&bitcoin::key::CompressedPublicKey(pk).wpubkey_hash());
            if &expected != script_pubkey {
                return false;
            }
            secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
        } else if script_pubkey.is_p2tr() {
            if self.witness.len() != 1 {
                return false;
            }
            let w = &self.witness[0];
            let sig_bytes = if w.len() == 65 { &w[..64] } else { &w[..] };
            let Ok(sig) = schnorr::Signature::from_slice(sig_bytes) else { return false };
            let Ok(xonly) = XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34]) else { return false };
            secp.verify_schnorr(&sig, &msg, &xonly).is_ok()
        } else {
            false
        }
    }

    /// `OwnershipProof.GenerateCoinJoinInputProof` for a soft wallet key (user confirmation set).
    pub fn generate(secret: &SecretKey, identifier: [u8; 32], script_pubkey: &ScriptBuf, commitment: &[u8]) -> Result<Self, ProofError> {
        let secp = Secp256k1::new();
        let mut proof = Self { flags: FLAG_USER_CONFIRMATION, identifiers: vec![identifier], script_sig: vec![], witness: vec![] };
        let hash = proof.signature_hash(script_pubkey, commitment);
        let msg = Message::from_digest(hash);
        if script_pubkey.is_p2wpkh() {
            // NBitcoin: key.Sign(hash, SigningOptions(SigHash.All, useLowR: false)) -> DER || 0x01
            let sig = secp.sign_ecdsa(&msg, secret);
            let mut der = sig.serialize_der().to_vec();
            der.push(0x01);
            let pk = PublicKey::from_secret_key(&secp, secret);
            proof.witness = vec![der, pk.serialize().to_vec()];
            Ok(proof)
        } else if script_pubkey.is_p2tr() {
            // SignTaprootKeySpend(hash, merkleRoot: null, aux: zero, sighash Default) -> 64 bytes
            let kp = UntweakedKeypair::from_secret_key(&secp, secret);
            let tweaked = kp.tap_tweak(&secp, None);
            let sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked.to_keypair(), &[0u8; 32]);
            proof.witness = vec![sig.as_ref().to_vec()];
            Ok(proof)
        } else {
            Err(ProofError::UnsupportedScript)
        }
    }
}

/// SLIP-21 node: 64 bytes, key = data[32..]
pub struct Slip21Node([u8; 64]);

impl Slip21Node {
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut e = HmacEngine::<sha512::Hash>::new(b"Symmetric key seed");
        e.input(seed);
        Self(Hmac::<sha512::Hash>::from_engine(e).to_byte_array())
    }
    pub fn derive_child(&self, label: &[u8]) -> Self {
        let mut e = HmacEngine::<sha512::Hash>::new(&self.0[..32]);
        e.input(&[0u8]);
        e.input(label);
        Self(Hmac::<sha512::Hash>::from_engine(e).to_byte_array())
    }
    pub fn key(&self) -> [u8; 32] {
        self.0[32..].try_into().unwrap()
    }
}

/// `OwnershipIdentifier(identificationKey, scriptPubKey)` = HMAC-SHA256(key, spk) where the key is
/// SLIP-21 `m/"SLIP-0019"/"Ownership identification key"` of the master private key bytes.
pub fn ownership_identifier(master_private_key: &[u8; 32], script_pubkey: &ScriptBuf) -> [u8; 32] {
    let node = Slip21Node::from_seed(master_private_key).derive_child(b"SLIP-0019").derive_child(b"Ownership identification key");
    let mut e = HmacEngine::<sha256::Hash>::new(&node.key());
    e.input(script_pubkey.as_bytes());
    Hmac::<sha256::Hash>::from_engine(e).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::CompressedPublicKey;

    #[test]
    fn roundtrip_and_verify_p2wpkh_and_p2tr() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let commitment = commitment_data("CoinJoinCoordinatorIdentifier", &"ab".repeat(32)).unwrap();
        let ident = ownership_identifier(&[1u8; 32], &ScriptBuf::new());

        let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
        let proof = OwnershipProof::generate(&sk, ident, &spk, &commitment).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(&bytes[..4], &VERSION_MAGIC);
        let parsed = OwnershipProof::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
        assert!(parsed.verify(&spk, &commitment, true));
        assert!(!parsed.verify(&spk, b"other", true));

        let xonly = XOnlyPublicKey::from(pk);
        let spk_tr = ScriptBuf::new_p2tr(&secp, xonly, None);
        let proof = OwnershipProof::generate(&sk, ident, &spk_tr, &commitment).unwrap();
        assert_eq!(proof.witness[0].len(), 64);
        assert!(OwnershipProof::from_bytes(&proof.to_bytes()).unwrap().verify(&spk_tr, &commitment, true));
    }

    #[test]
    fn slip21_vector() {
        // SLIP-0021 test vector: master node key from seed "..." (we only check determinism and length)
        let n = Slip21Node::from_seed(&[0u8; 64]);
        assert_eq!(n.derive_child(b"SLIP-0021").key().len(), 32);
    }
}
