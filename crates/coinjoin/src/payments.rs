//! Payments made inside coinjoin rounds (Wasabi `PaymentBatch`): pending payments wait, the best
//! set that fits a round's registered amount goes in as outputs, and they end finished or back to
//! pending with the round. In memory, like Wasabi.

use crate::units::{effective_cost, script_output_vsize, FeeRate, ScriptType};
use bitcoin::{ScriptBuf, Txid};
use rand::RngCore;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentState {
    Pending,
    InProgress { round_id: String },
    Signed { txid: Txid },
    Finished { txid: Txid },
}

#[derive(Debug, Clone)]
pub struct Payment {
    pub id: String,
    pub script: ScriptBuf,
    pub amount: i64,
    /// Oldest first; the last entry is the current state.
    pub states: Vec<PaymentState>,
}

impl Payment {
    pub fn state(&self) -> &PaymentState {
        self.states.last().expect("a payment always has a state")
    }
}

/// Wasabi caps a round at four payments.
const MAX_PAYMENTS_PER_ROUND: usize = 4;
/// Enough pending payments to choose from without enumerating thousands of sets.
const MAX_CANDIDATES: usize = 12;

#[derive(Default)]
pub struct PaymentBatch {
    payments: Mutex<Vec<Payment>>,
}

impl PaymentBatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a pending payment; the id has the shape of Wasabi's GUID.
    pub fn add(&self, script: ScriptBuf, amount: i64) -> String {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        let h = hex::encode(b);
        let id = format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]);
        self.payments.lock().unwrap().push(Payment { id: id.clone(), script, amount, states: vec![PaymentState::Pending] });
        id
    }

    pub fn abort(&self, id: &str) -> Result<(), String> {
        let mut ps = self.payments.lock().unwrap();
        let i = ps.iter().position(|p| p.id == id).ok_or("Payment was not found.")?;
        if *ps[i].state() != PaymentState::Pending {
            return Err("Payment could not be canceled because it is not pending.".into());
        }
        ps.remove(i);
        Ok(())
    }

    pub fn list(&self) -> Vec<Payment> {
        self.payments.lock().unwrap().clone()
    }

    pub fn any_pending(&self) -> bool {
        self.payments.lock().unwrap().iter().any(|p| *p.state() == PaymentState::Pending)
    }

    /// `GetBestPaymentSet`: the most payments (up to four) whose cost fits what the round
    /// registered, leaving room for at least one more output unless the match is exact.
    pub fn best_set(&self, available_amount: i64, available_vsize: i64, allowed_types: &[ScriptType], amount_min: i64, amount_max: i64, fee_rate: FeeRate) -> Vec<Payment> {
        let candidates: Vec<Payment> = self
            .payments
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p.state() == PaymentState::Pending)
            .filter(|p| ScriptType::of_script(&p.script).map(|t| allowed_types.contains(&t)).unwrap_or(false))
            .filter(|p| (amount_min..=amount_max).contains(&p.amount))
            .take(MAX_CANDIDATES)
            .cloned()
            .collect();
        let n = candidates.len();
        let mut best: Vec<usize> = Vec::new();
        for mask in 1u32..(1u32 << n) {
            let count = mask.count_ones() as usize;
            if count > MAX_PAYMENTS_PER_ROUND || count <= best.len() {
                continue;
            }
            let chosen: Vec<usize> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            let total: i64 = chosen.iter().map(|&i| effective_cost(candidates[i].amount, &candidates[i].script, fee_rate)).sum();
            let vsize: i64 = chosen.iter().map(|&i| script_output_vsize(&candidates[i].script)).sum();
            let fits = total <= available_amount && if total == available_amount { vsize <= available_vsize } else { vsize + ScriptType::Taproot.output_vsize().max(ScriptType::P2WPKH.output_vsize()) <= available_vsize };
            if fits {
                best = chosen;
            }
        }
        best.into_iter().map(|i| candidates[i].clone()).collect()
    }

    fn move_where(&self, pick: impl Fn(&Payment) -> bool, next: impl Fn(&Payment) -> PaymentState) {
        for p in self.payments.lock().unwrap().iter_mut() {
            if pick(p) {
                let s = next(p);
                p.states.push(s);
            }
        }
    }

    pub fn move_in_progress(&self, ids: &[String], round_id: &str) {
        self.move_where(|p| ids.contains(&p.id) && *p.state() == PaymentState::Pending, |_| PaymentState::InProgress { round_id: round_id.to_string() });
    }

    pub fn move_signed(&self, txid: Txid) {
        self.move_where(|p| matches!(p.state(), PaymentState::InProgress { .. }), |_| PaymentState::Signed { txid });
    }

    /// The round failed: in-progress and signed-but-unknown payments wait for the next one.
    pub fn move_pending(&self) {
        self.move_where(|p| matches!(p.state(), PaymentState::InProgress { .. } | PaymentState::Signed { .. }), |_| PaymentState::Pending);
    }

    pub fn move_finished(&self, txid: Txid) {
        self.move_where(|p| matches!(p.state(), PaymentState::InProgress { .. } | PaymentState::Signed { .. }), |_| PaymentState::Finished { txid });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn p2wpkh(b: u8) -> ScriptBuf {
        let mut v = vec![0u8, 20];
        v.extend_from_slice(&[b; 20]);
        ScriptBuf::from_bytes(v)
    }

    #[test]
    fn picks_the_most_payments_that_fit_and_tracks_their_states() {
        let b = PaymentBatch::new();
        let a = b.add(p2wpkh(1), 100_000);
        let c = b.add(p2wpkh(2), 200_000);
        let big = b.add(p2wpkh(3), 10_000_000);
        let fee = FeeRate::from_sat_per_vb(2.0);
        let types = [ScriptType::P2WPKH, ScriptType::Taproot];
        let set = b.best_set(400_000, 1000, &types, 5_000, 100_000_000, fee);
        let ids: Vec<&str> = set.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&a.as_str()) && ids.contains(&c.as_str()) && !ids.contains(&big.as_str()));
        assert!(b.best_set(400_000, 40, &types, 5_000, 100_000_000, fee).is_empty(), "no vsize for a payment plus one more output");
        assert!(b.best_set(50_000, 1000, &types, 5_000, 100_000_000, fee).is_empty(), "nothing fits 50k");
        b.move_in_progress(&[a.clone()], "round");
        assert!(b.abort(&a).is_err(), "in progress cannot be cancelled");
        assert!(b.abort(&c).is_ok());
        assert!(b.any_pending(), "the big one still waits");
        b.move_signed(Txid::all_zeros());
        b.move_finished(Txid::all_zeros());
        let a_now = b.list().into_iter().find(|p| p.id == a).unwrap();
        assert!(matches!(a_now.state(), PaymentState::Finished { .. }));
        assert_eq!(a_now.states.len(), 4);
        b.move_in_progress(&[big.clone()], "r2");
        b.move_pending();
        assert_eq!(*b.list().into_iter().find(|p| p.id == big).unwrap().state(), PaymentState::Pending);
    }
}
