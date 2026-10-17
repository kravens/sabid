//! NBitcoin `Script.ToString()` asm form <-> rust-bitcoin `ScriptBuf`, and the OutPoint hex form.
//! Only what the coinjoin protocol carries: witness v0/v1 outputs (`"0 <hex>"`, `"1 <hex>"`).

use bitcoin::blockdata::opcodes::all as op;
use bitcoin::hashes::Hash;
use bitcoin::script::{Builder, Instruction, PushBytesBuf, ScriptBuf};
use bitcoin::{OutPoint, Txid};

#[derive(Debug, thiserror::Error)]
#[error("unsupported script asm: {0}")]
pub struct ScriptAsmError(String);

pub fn script_from_asm(asm: &str) -> Result<ScriptBuf, ScriptAsmError> {
    let mut b = Builder::new();
    for tok in asm.split_whitespace() {
        b = match tok {
            "0" | "OP_0" => b.push_opcode(op::OP_PUSHBYTES_0),
            "OP_RETURN" => b.push_opcode(op::OP_RETURN),
            t if t.parse::<u8>().map(|n| (1..=16).contains(&n)).unwrap_or(false) => {
                b.push_int(t.parse::<i64>().unwrap())
            }
            t if t.starts_with("OP_") => return Err(ScriptAsmError(asm.to_string())),
            t => {
                let bytes = hex::decode(t).map_err(|_| ScriptAsmError(asm.to_string()))?;
                let pb = PushBytesBuf::try_from(bytes).map_err(|_| ScriptAsmError(asm.to_string()))?;
                b.push_slice(pb)
            }
        };
    }
    Ok(b.into_script())
}

pub fn script_to_asm(script: &ScriptBuf) -> String {
    let mut parts = Vec::new();
    for ins in script.instructions() {
        match ins {
            Ok(Instruction::PushBytes(pb)) => {
                if pb.is_empty() {
                    parts.push("0".to_string());
                } else {
                    parts.push(hex::encode(pb.as_bytes()));
                }
            }
            Ok(Instruction::Op(o)) => {
                let n = o.to_u8();
                let s = if n == op::OP_PUSHBYTES_0.to_u8() {
                    "0".to_string()
                } else if (op::OP_PUSHNUM_1.to_u8()..=op::OP_PUSHNUM_16.to_u8()).contains(&n) {
                    (n - op::OP_PUSHNUM_1.to_u8() + 1).to_string()
                } else {
                    format!("{o:?}")
                };
                parts.push(s);
            }
            Err(_) => parts.push("<invalid>".to_string()),
        }
    }
    parts.join(" ")
}

/// NBitcoin `OutPoint.ToBytes()`: txid little-endian (as in the raw tx) + vout u32 LE.
pub fn outpoint_to_hex(op: &OutPoint) -> String {
    let mut v = op.txid.to_byte_array().to_vec();
    v.extend_from_slice(&op.vout.to_le_bytes());
    hex::encode_upper(v)
}

pub fn outpoint_from_hex(s: &str) -> Option<OutPoint> {
    let b = hex::decode(s).ok()?;
    if b.len() != 36 {
        return None;
    }
    let txid = Txid::from_slice(&b[..32]).ok()?;
    let vout = u32::from_le_bytes(b[32..36].try_into().ok()?);
    Some(OutPoint { txid, vout })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asm_roundtrip_witness() {
        for asm in ["0 751e76e8199196d454941c45d1b3a323f1433bd6", "1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"] {
            let s = script_from_asm(asm).unwrap();
            assert!(s.is_p2wpkh() || s.is_p2tr());
            assert_eq!(script_to_asm(&s), asm);
        }
    }

    #[test]
    fn outpoint_hex_roundtrip() {
        let op = OutPoint { txid: Txid::from_slice(&[7u8; 32]).unwrap(), vout: 258 };
        let h = outpoint_to_hex(&op);
        assert_eq!(&h[64..], "02010000");
        assert_eq!(outpoint_from_hex(&h), Some(op));
    }
}
