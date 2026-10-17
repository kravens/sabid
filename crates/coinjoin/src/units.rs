//! Script types, virtual sizes and fee arithmetic exactly as Wasabi/NBitcoin compute them
//! (the coordinator does the same arithmetic, so a satoshi off means a rejected request).

use bitcoin::ScriptBuf;

/// NBitcoin `ScriptType` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ScriptType {
    Witness = 0,
    P2PKH = 1,
    P2SH = 2,
    P2PK = 3,
    P2WPKH = 4,
    P2WSH = 5,
    MultiSig = 6,
    Taproot = 7,
}

impl ScriptType {
    pub fn from_u8(n: u8) -> Option<ScriptType> {
        use ScriptType::*;
        Some(match n {
            0 => Witness,
            1 => P2PKH,
            2 => P2SH,
            3 => P2PK,
            4 => P2WPKH,
            5 => P2WSH,
            6 => MultiSig,
            7 => Taproot,
            _ => return None,
        })
    }

    pub fn of_script(s: &ScriptBuf) -> Option<ScriptType> {
        if s.is_p2wpkh() {
            Some(ScriptType::P2WPKH)
        } else if s.is_p2tr() {
            Some(ScriptType::Taproot)
        } else if s.is_p2wsh() {
            Some(ScriptType::P2WSH)
        } else if s.is_p2pkh() {
            Some(ScriptType::P2PKH)
        } else if s.is_p2sh() {
            Some(ScriptType::P2SH)
        } else {
            None
        }
    }

    /// Wasabi `Constants.*InputVirtualSize`
    pub fn input_vsize(self) -> i64 {
        match self {
            ScriptType::P2WPKH => 69,
            ScriptType::Taproot => 58,
            ScriptType::P2PKH => 148,
            ScriptType::P2SH => 91,
            ScriptType::P2WSH => 105,
            _ => 69,
        }
    }

    /// Wasabi `Constants.*OutputVirtualSize` (= serialized TxOut size)
    pub fn output_vsize(self) -> i64 {
        match self {
            ScriptType::P2WPKH => 31,
            ScriptType::Taproot => 43,
            ScriptType::P2PKH => 34,
            ScriptType::P2SH => 32,
            ScriptType::P2WSH => 43,
            _ => 31,
        }
    }
}

pub fn script_output_vsize(s: &ScriptBuf) -> i64 {
    // NBitcoin: new TxOut(0, script).GetSerializedSize() = 8 + varint(len) + len
    let len = s.len() as i64;
    8 + if len < 0xfd { 1 } else { 3 } + len
}

pub fn script_input_vsize(s: &ScriptBuf) -> i64 {
    ScriptType::of_script(s).map(|t| t.input_vsize()).unwrap_or(69)
}

/// NBitcoin `FeeRate`: satoshis per 1000 vbytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate {
    pub fee_per_k: i64,
}

impl FeeRate {
    pub const fn from_fee_per_k(fee_per_k: i64) -> Self {
        Self { fee_per_k }
    }

    /// `new FeeRate(decimal satoshiPerByte)` = satoshiPerByte * 1000 (truncated to satoshis)
    pub fn from_sat_per_vb(sat_per_vb: f64) -> Self {
        Self { fee_per_k: (sat_per_vb * 1000.0).floor() as i64 }
    }

    pub fn sat_per_vb(&self) -> f64 {
        self.fee_per_k as f64 / 1000.0
    }

    /// NBitcoin `GetFee`: truncating division, never zero.
    pub fn get_fee(&self, vsize: i64) -> i64 {
        let fee = self.fee_per_k * vsize / 1000;
        if fee == 0 {
            1
        } else {
            fee
        }
    }

    /// Wasabi `GetFeeWithZero`
    pub fn get_fee_with_zero(&self, vsize: i64) -> i64 {
        if self.fee_per_k == 0 {
            0
        } else {
            self.get_fee(vsize)
        }
    }
}

/// Wasabi `EffectiveValue`: amount minus the fee to spend it.
pub fn effective_value(amount: i64, script_type: ScriptType, fee_rate: FeeRate) -> i64 {
    amount - fee_rate.get_fee(script_type.input_vsize())
}

/// Wasabi `EffectiveCost` of a TxOut: value plus the fee to create it.
pub fn effective_cost(value: i64, script: &ScriptBuf, fee_rate: FeeRate) -> i64 {
    value + fee_rate.get_fee(script_output_vsize(script))
}

/// `VirtualSizeHelpers.VirtualSize`
pub fn virtual_size(non_segwit_bytes: i64, segwit_bytes: i64) -> i64 {
    let weight = 4 * non_segwit_bytes + segwit_bytes;
    (weight + 3) / 4
}

/// `MultipartyTransactionParameters.SharedOverhead` for 255 inputs/outputs.
pub fn shared_overhead() -> i64 {
    virtual_size(4 + 4 + 3 + 3, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_math_matches_nbitcoin() {
        let f = FeeRate::from_fee_per_k(500);
        assert_eq!(f.get_fee(69), 34);
        assert_eq!(f.get_fee(1), 1);
        assert_eq!(FeeRate::from_fee_per_k(0).get_fee(100), 1);
        assert_eq!(FeeRate::from_fee_per_k(0).get_fee_with_zero(100), 0);
        assert_eq!(shared_overhead(), 15);
        assert_eq!(FeeRate::from_sat_per_vb(1.3).fee_per_k, 1300);
    }
}
