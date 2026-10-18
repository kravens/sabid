//! Plain transactions (Wasabi `build` / `send` / `broadcast`): the coins given are the inputs,
//! the payments the outputs, change goes to the wallet's next internal key, fee at a rate, RBF on.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use coinjoin::keychain::{KeyChain, UnsignedCoinJoin};
use coinjoin::units::{script_input_vsize, script_output_vsize};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use wallet::store::Coin;

pub struct Payment {
    pub script: ScriptBuf,
    pub amount: u64,
    pub subtract_fee: bool,
}

pub struct Built {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub fee: u64,
    /// The change script when the transaction has a change output.
    pub change: Option<ScriptBuf>,
}

/// nVersion, nLockTime, input and output counts, segwit marker: the part no input or output pays for.
const OVERHEAD_VBYTES: i64 = 11;
pub const MIN_FEE_RATE: f64 = 1.0;
pub const MAX_FEE_RATE: f64 = 2000.0;

pub fn build(coins: &[Coin], payments: &[Payment], fee_rate_sat_vb: f64, change: ScriptBuf, dust: u64) -> Result<Built, String> {
    if coins.is_empty() {
        return Err("No coins to spend.".into());
    }
    if payments.is_empty() {
        return Err("No payments.".into());
    }
    if !(MIN_FEE_RATE..=MAX_FEE_RATE).contains(&fee_rate_sat_vb) {
        return Err(format!("Fee rate {fee_rate_sat_vb} sat/vB is out of range ({MIN_FEE_RATE}..{MAX_FEE_RATE})."));
    }
    let total_in: u64 = coins.iter().map(|c| c.amount).sum();
    let total_out: u64 = payments.iter().map(|p| p.amount).sum();
    let fee_for = |with_change: bool| -> u64 {
        let vsize = OVERHEAD_VBYTES
            + coins.iter().map(|c| script_input_vsize(&c.script)).sum::<i64>()
            + payments.iter().map(|p| script_output_vsize(&p.script)).sum::<i64>()
            + if with_change { script_output_vsize(&change) } else { 0 };
        (fee_rate_sat_vb * vsize as f64).ceil() as u64
    };
    let mut outputs: Vec<(ScriptBuf, u64)> = payments.iter().map(|p| (p.script.clone(), p.amount)).collect();
    let subtracting: Vec<usize> = payments.iter().enumerate().filter(|(_, p)| p.subtract_fee).map(|(i, _)| i).collect();
    let mut change_out: Option<u64> = None;
    if subtracting.is_empty() {
        // The fee comes out of what is left; a remainder below dust is left to the miners.
        let fee_no_change = fee_for(false);
        if total_in < total_out + fee_no_change {
            return Err(format!("Not enough funds: {total_in} sat for {total_out} sat plus {fee_no_change} sat fee."));
        }
        let rest = total_in.saturating_sub(total_out + fee_for(true));
        if rest >= dust {
            change_out = Some(rest);
        }
    } else {
        // The flagged payments pay the fee; what the inputs hold beyond the payments is change.
        if total_in < total_out {
            return Err(format!("Not enough funds: {total_in} sat for {total_out} sat."));
        }
        let leftover = total_in - total_out;
        let fee = if leftover >= dust {
            change_out = Some(leftover);
            fee_for(true)
        } else {
            fee_for(false)
        };
        let n = subtracting.len() as u64;
        for (k, i) in subtracting.iter().enumerate() {
            let share = fee / n + if (k as u64) < fee % n { 1 } else { 0 };
            outputs[*i].1 = outputs[*i].1.checked_sub(share).ok_or("A payment is smaller than its share of the fee.")?;
        }
    }
    if let Some(small) = outputs.iter().find(|(_, a)| *a < dust) {
        return Err(format!("A payment of {} sat is below the dust threshold of {dust} sat.", small.1));
    }
    if let Some(c) = change_out {
        outputs.push((change.clone(), c));
    }
    outputs.shuffle(&mut rand::thread_rng());
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: coins.iter().map(|c| TxIn { previous_output: c.outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }).collect(),
        output: outputs.iter().map(|(s, a)| TxOut { value: Amount::from_sat(*a), script_pubkey: s.clone() }).collect(),
    };
    let prevouts = coins.iter().map(|c| TxOut { value: Amount::from_sat(c.amount), script_pubkey: c.script.clone() }).collect();
    let fee = total_in - outputs.iter().map(|(_, a)| a).sum::<u64>();
    Ok(Built { tx, prevouts, fee, change: change_out.map(|_| change) })
}

pub fn sign(key_chain: &dyn KeyChain, built: &Built) -> Result<Transaction, String> {
    let unsigned = UnsignedCoinJoin { tx: built.tx.clone(), prevouts: built.prevouts.clone(), ownership_proofs: HashMap::new() };
    let mut tx = built.tx.clone();
    for input in &mut tx.input {
        input.witness = key_chain.sign(&unsigned, &input.previous_output).map_err(|e| e.to_string())?;
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};

    fn coin(i: u32, amount: u64) -> Coin {
        let mut spk = vec![0u8, 20];
        spk.extend_from_slice(&[i as u8; 20]);
        Coin {
            outpoint: OutPoint { txid: Txid::all_zeros(), vout: i },
            amount,
            script: ScriptBuf::from_bytes(spk),
            key_path: String::new(),
            label: String::new(),
            height: 1,
            spender: None,
            anonymity_set: 1.0,
            excluded_from_coinjoin: false,
            is_own_coinjoin_output: false,
        }
    }
    fn spk(b: u8) -> ScriptBuf {
        let mut v = vec![0u8, 20];
        v.extend_from_slice(&[b; 20]);
        ScriptBuf::from_bytes(v)
    }

    #[test]
    fn change_and_fee_at_the_rate() {
        let b = build(&[coin(0, 100_000), coin(1, 50_000)], &[Payment { script: spk(9), amount: 60_000, subtract_fee: false }], 10.0, spk(7), 1000).unwrap();
        let vsize = OVERHEAD_VBYTES + 2 * script_input_vsize(&spk(0)) + 2 * script_output_vsize(&spk(9));
        assert_eq!(b.fee, (10.0 * vsize as f64).ceil() as u64);
        assert_eq!(b.tx.output.len(), 2);
        assert_eq!(b.tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>(), 150_000 - b.fee);
        assert!(b.change.is_some());
        assert!(b.tx.input.iter().all(|i| i.sequence == Sequence::ENABLE_RBF_NO_LOCKTIME));
    }

    #[test]
    fn subtract_fee_reduces_the_payment_and_keeps_the_rest_as_change() {
        let b = build(&[coin(0, 100_000)], &[Payment { script: spk(9), amount: 70_000, subtract_fee: true }], 2.0, spk(7), 1000).unwrap();
        let pay = b.tx.output.iter().find(|o| o.script_pubkey == spk(9)).unwrap().value.to_sat();
        let change = b.tx.output.iter().find(|o| o.script_pubkey == spk(7)).unwrap().value.to_sat();
        assert_eq!(change, 30_000);
        assert_eq!(70_000 - pay, b.fee);
        assert_eq!(b.fee, (2.0 * (OVERHEAD_VBYTES + script_input_vsize(&spk(0)) + 2 * script_output_vsize(&spk(9))) as f64).ceil() as u64);
    }

    #[test]
    fn dust_change_is_left_as_fee_and_shortfalls_fail() {
        let b = build(&[coin(0, 100_000)], &[Payment { script: spk(9), amount: 99_500, subtract_fee: false }], 1.0, spk(7), 1000).unwrap();
        assert!(b.change.is_none(), "the remainder is below dust");
        assert_eq!(b.fee, 500);
        assert!(build(&[coin(0, 1_000)], &[Payment { script: spk(9), amount: 990, subtract_fee: false }], 1.0, spk(7), 500).is_err());
        assert!(build(&[coin(0, 100_000)], &[Payment { script: spk(9), amount: 100, subtract_fee: false }], 1.0, spk(7), 1000).is_err(), "dust payment");
        assert!(build(&[coin(0, 100_000)], &[Payment { script: spk(9), amount: 1000, subtract_fee: false }], 5000.0, spk(7), 1000).is_err(), "absurd fee rate");
    }
}
