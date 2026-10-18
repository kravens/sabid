//! Port of Wasabi's `CoinJoinCoinSelector` (+ `UtxoSelectionParameters`, randomness generator).

use crate::decomposer::create_denominations;
use crate::units::{effective_value, FeeRate, ScriptType};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const MAX_INPUTS_REGISTRABLE_BY_WALLET: usize = 10;
pub const MAX_WEIGHTED_ANON_LOSS: f64 = 3.0;
pub const SEMI_PRIVATE_THRESHOLD: i32 = 2;
pub const MAXIMUM_NUMBER_OF_BITCOINS_SATS: i64 = 2_099_999_997_690_000;

#[derive(Debug, Clone)]
pub struct CjCoin {
    pub outpoint: OutPoint,
    pub amount: i64,
    pub script: ScriptBuf,
    pub script_type: ScriptType,
    pub anonymity_set: f64,
}

impl CjCoin {
    pub fn txid(&self) -> Txid {
        self.outpoint.txid
    }
    pub fn effective_value(&self, fee_rate: FeeRate) -> i64 {
        effective_value(self.amount, self.script_type, fee_rate)
    }
    pub fn is_private(&self, target: i32) -> bool {
        self.anonymity_set >= target as f64
    }
    pub fn is_semi_private(&self, target: i32, semi: i32) -> bool {
        self.anonymity_set >= semi as f64 && self.anonymity_set < target as f64
    }
    pub fn is_red(&self, semi: i32) -> bool {
        self.anonymity_set < semi as f64
    }
}

#[derive(Debug, Clone)]
pub struct UtxoSelectionParameters {
    pub allowed_input_amounts: (i64, i64),
    pub min_allowed_output_amount: i64,
    pub mining_fee_rate: FeeRate,
    pub allowed_input_script_types: Vec<ScriptType>,
}

/// `RoundParametersExtensions.CalculateMinReasonableOutputAmount`
pub fn min_reasonable_output_amount(allowed_output_types: &[ScriptType], supported: &[ScriptType], fee_rate: FeeRate, allowed_output_min: i64) -> i64 {
    let max_pair = allowed_output_types.iter().filter(|t| supported.contains(t)).map(|t| t.input_vsize() + t.output_vsize()).max().unwrap_or(0);
    fee_rate.get_fee(max_pair).max(allowed_output_min)
}

impl UtxoSelectionParameters {
    /// `UtxoSelectionParameters.FromRoundParameters`
    pub fn from_round<R: Rng>(
        allowed_input_amounts: (i64, i64),
        allowed_output_amounts: (i64, i64),
        allowed_input_types: Vec<ScriptType>,
        allowed_output_types: &[ScriptType],
        mining_fee_rate: FeeRate,
        supported: &[ScriptType],
        rng: &mut R,
    ) -> Option<Self> {
        let out_types: Vec<ScriptType> = allowed_output_types.iter().copied().filter(|t| supported.contains(t)).collect();
        let max_vsize_type = *out_types.iter().max_by_key(|t| t.input_vsize() + t.output_vsize())?;
        let min_reasonable = min_reasonable_output_amount(allowed_output_types, supported, mining_fee_rate, allowed_output_amounts.0);
        let smallest = create_denominations(min_reasonable, allowed_output_amounts.1, mining_fee_rate, &[max_vsize_type], rng).iter().map(|o| o.effective_cost()).min()?;
        Some(Self { allowed_input_amounts, min_allowed_output_amount: smallest, mining_fee_rate, allowed_input_script_types: allowed_input_types })
    }
}

pub struct CoinJoinCoinSelector {
    pub consolidation_mode: bool,
    pub anon_score_target: i32,
    pub semi_private_threshold: i32,
    pub are_payments_pending: bool,
}

fn random_element<'a, T, R: Rng>(items: impl IntoIterator<Item = &'a T>, rng: &mut R) -> Option<&'a T> {
    // Wasabi `RandomElement`: reservoir sampling, uniform.
    let mut current = None;
    let mut count = 0u32;
    for e in items {
        count += 1;
        if rng.gen_range(0..count) == 0 {
            current = Some(e);
        }
    }
    current
}

fn biased_random_element<'a, T, R: Rng>(items: &'a [T], bias_percent: u32, rng: &mut R) -> Option<&'a T> {
    for e in items {
        if rng.gen_range(0..100) < bias_percent {
            return Some(e);
        }
    }
    items.first()
}

fn input_target<R: Rng>(rng: &mut R) -> usize {
    // Prefer the maximum, each lower count with halving probability.
    for i in (1..=MAX_INPUTS_REGISTRABLE_BY_WALLET).rev() {
        if rng.gen_range(0..10) < 5 {
            return i;
        }
    }
    MAX_INPUTS_REGISTRABLE_BY_WALLET
}

fn random_biased_same_tx_allowance<R: Rng>(percent: u32, rng: &mut R) -> usize {
    for num in 0..=100 {
        if rng.gen_range(0..100) < percent {
            return num;
        }
    }
    0
}

fn anon_loss(coins: &[CjCoin]) -> f64 {
    let min = coins.iter().map(|c| c.anonymity_set).fold(f64::INFINITY, f64::min);
    let total: f64 = coins.iter().map(|c| c.amount as f64).sum();
    coins.iter().map(|c| (c.anonymity_set - min) * c.amount as f64).sum::<f64>() / total
}

fn reps(group: &[CjCoin]) -> usize {
    let mut by_tx: HashMap<Txid, usize> = HashMap::new();
    for c in group {
        *by_tx.entry(c.txid()).or_default() += 1;
    }
    by_tx.values().map(|n| n - 1).sum()
}

fn group_key(group: &[CjCoin]) -> Vec<OutPoint> {
    let mut k: Vec<OutPoint> = group.iter().map(|c| c.outpoint).collect();
    k.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
    k
}

/// Lexicographic k-combinations with an early-stop callback (returns false to stop).
fn for_each_combination<T: Clone>(items: &[T], k: usize, mut f: impl FnMut(Vec<T>) -> bool) {
    if k > items.len() {
        return;
    }
    if k == 0 {
        f(Vec::new());
        return;
    }
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        if !f(idx.iter().map(|&i| items[i].clone()).collect()) {
            return;
        }
        let mut i = k;
        loop {
            if i == 0 {
                return;
            }
            i -= 1;
            if idx[i] != i + items.len() - k {
                break;
            }
            if i == 0 {
                return;
            }
        }
        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

impl CoinJoinCoinSelector {
    pub fn new(consolidation_mode: bool, anon_score_target: i32, non_private_coin_isolation: bool, are_payments_pending: bool) -> Self {
        Self { consolidation_mode, anon_score_target, semi_private_threshold: if non_private_coin_isolation { SEMI_PRIVATE_THRESHOLD } else { 0 }, are_payments_pending }
    }

    fn anon_score_tx_source_biased_shuffle<R: Rng>(&self, coins: &[CjCoin], rng: &mut R) -> Vec<CjCoin> {
        let mut ordered: Vec<CjCoin> = Vec::new();
        for _ in 0..coins.len() {
            let mut remaining: Vec<&CjCoin> = coins.iter().filter(|c| !ordered.iter().any(|o| o.outpoint == c.outpoint)).collect();
            remaining.sort_by(|a, b| a.anonymity_set.partial_cmp(&b.anonymity_set).unwrap_or(std::cmp::Ordering::Equal));
            let mut alternating: Vec<CjCoin> = Vec::new();
            let mut skipped: Vec<CjCoin> = Vec::new();
            for c in remaining {
                if alternating.iter().any(|x| x.txid() == c.txid()) || ordered.iter().any(|x| x.txid() == c.txid()) {
                    skipped.push(c.clone());
                } else {
                    alternating.push(c.clone());
                }
            }
            alternating.extend(skipped);
            let coin = biased_random_element(&alternating, 50, rng).expect("non-empty").clone();
            ordered.push(coin);
        }
        ordered
    }

    /// `SelectCoinsForRound`
    pub fn select_coins_for_round<R: Rng>(&self, coins: &[CjCoin], p: &UtxoSelectionParameters, liquidity_clue: i64, rng: &mut R) -> Vec<CjCoin> {
        let liquidity_clue = if liquidity_clue > 0 { liquidity_clue } else { MAXIMUM_NUMBER_OF_BITCOINS_SATS };
        let filtered: Vec<CjCoin> = coins
            .iter()
            .filter(|x| x.amount >= p.allowed_input_amounts.0 && x.amount <= p.allowed_input_amounts.1)
            .filter(|x| p.allowed_input_script_types.contains(&x.script_type))
            .filter(|x| x.effective_value(p.mining_fee_rate) > 0)
            .cloned()
            .collect();
        if filtered.is_empty() {
            tracing::debug!("No suitable coins for this round.");
            return vec![];
        }
        let effective_target = if self.are_payments_pending && filtered.iter().all(|x| x.is_private(self.anon_score_target)) { i32::MAX } else { self.anon_score_target };
        let private: Vec<CjCoin> = filtered.iter().filter(|x| x.is_private(effective_target)).cloned().collect();
        let semi: Vec<CjCoin> = filtered.iter().filter(|x| x.is_semi_private(effective_target, self.semi_private_threshold)).cloned().collect();
        let red: Vec<CjCoin> = filtered.iter().filter(|x| x.is_red(self.semi_private_threshold)).cloned().collect();
        if semi.len() + red.len() == 0 {
            tracing::debug!("No suitable coins for this round.");
            return vec![];
        }
        let mut allowed_non_private = semi.clone();
        if let Some(r) = random_element(red.iter(), rng) {
            allowed_non_private.push(r.clone());
        }
        let input_count = (private.len() + allowed_non_private.len()).min(if self.consolidation_mode { MAX_INPUTS_REGISTRABLE_BY_WALLET } else { input_target(rng) });
        let bias_shuffled_private = self.anon_score_tx_source_biased_shuffle(&private, rng);
        let smaller: Vec<CjCoin> = bias_shuffled_private.iter().filter(|x| x.amount <= liquidity_clue).cloned().collect();
        let larger: Vec<CjCoin> = bias_shuffled_private.iter().filter(|x| x.amount > liquidity_clue).cloned().collect();
        let allowed_private: Vec<CjCoin> = smaller.into_iter().chain(larger).take(input_count.saturating_sub(1)).collect();
        let allowed: Vec<CjCoin> = allowed_non_private.iter().cloned().chain(allowed_private).collect();
        let ordered_allowed = self.anon_score_tx_source_biased_shuffle(&allowed, rng);
        let mut largest_non_private = allowed_non_private.clone();
        largest_non_private.sort_by(|a, b| b.amount.cmp(&a.amount));
        largest_non_private.truncate(3);

        let mut groups: HashMap<Vec<OutPoint>, Vec<CjCoin>> = HashMap::new();
        let try_add = |groups: &mut HashMap<Vec<OutPoint>, Vec<CjCoin>>, group: Vec<CjCoin>| {
            let eff: i64 = group.iter().map(|x| x.effective_value(p.mining_fee_rate)).sum();
            if eff >= p.min_allowed_output_amount {
                groups.entry(group_key(&group)).or_insert(group);
            }
        };
        let sw1 = Instant::now();
        for coin in &largest_non_private {
            let others: Vec<CjCoin> = ordered_allowed.iter().filter(|x| x.outpoint != coin.outpoint).cloned().collect();
            let mut base: Vec<CjCoin> = others.iter().take(input_count.saturating_sub(1)).cloned().collect();
            base.push(coin.clone());
            try_add(&mut groups, base);
            let sw2 = Instant::now();
            for_each_combination(&others, input_count.saturating_sub(1), |mut g| {
                g.push(coin.clone());
                try_add(&mut groups, g);
                sw2.elapsed() <= Duration::from_secs(1)
            });
            if sw1.elapsed() > Duration::from_secs(10) {
                break;
            }
        }
        if groups.is_empty() {
            tracing::debug!("Couldn't create any combinations, ending.");
            return vec![];
        }
        let best_rep = groups.values().map(|g| reps(g)).min().unwrap();
        let best_rep_groups: Vec<&Vec<CjCoin>> = groups.values().filter(|g| reps(g) == best_rep).collect();
        let remaining_largest: Vec<CjCoin> = largest_non_private
            .iter()
            .filter(|x| best_rep_groups.iter().any(|g| g.iter().any(|y| y.outpoint == x.outpoint)))
            .cloned()
            .collect();
        let mut selected_non_private = random_element(remaining_largest.iter(), rng).cloned();
        let mut by_amount = remaining_largest.clone();
        by_amount.sort_by(|a, b| b.amount.cmp(&a.amount));
        for coin in &by_amount {
            if rng.gen_range(0..100) < 50 {
                selected_non_private = Some(coin.clone());
                break;
            }
        }
        let Some(selected) = selected_non_private else {
            tracing::debug!("Couldn't select largest non-private coin, ending.");
            return vec![];
        };
        let containing: Vec<&Vec<CjCoin>> = best_rep_groups.iter().copied().filter(|g| g.iter().any(|y| y.outpoint == selected.outpoint)).collect();
        let Some(final_candidate) = random_element(containing.iter().copied(), rng) else {
            tracing::debug!("Couldn't select final selection candidate, ending.");
            return vec![];
        };
        let same_tx_allowance = random_biased_same_tx_allowance(67, rng);
        let mut winner: Vec<CjCoin> = vec![selected.clone()];
        let mut rest: Vec<CjCoin> = final_candidate.iter().filter(|x| x.outpoint != selected.outpoint).cloned().collect();
        rest.sort_by(|a, b| a.anonymity_set.partial_cmp(&b.anonymity_set).unwrap_or(std::cmp::Ordering::Equal).then(b.amount.cmp(&a.amount)));
        for coin in rest {
            if winner.iter().any(|x| x.txid() == coin.txid()) {
                let distinct: HashSet<Txid> = winner.iter().map(|x| x.txid()).collect();
                let same_tx_used = winner.len() - distinct.len();
                if same_tx_used < same_tx_allowance {
                    winner.push(coin);
                }
            } else {
                winner.push(coin);
            }
        }
        let mut winner_loss = anon_loss(&winner);
        while winner.iter().map(|x| x.amount).sum::<i64>() > liquidity_clue && winner_loss > MAX_WEIGHTED_ANON_LOSS {
            let mut best_reduced = winner.clone();
            let mut best_loss = winner_loss;
            let mut changed = false;
            for coin in winner.iter().filter(|x| x.outpoint != selected.outpoint) {
                let reduced: Vec<CjCoin> = winner.iter().filter(|x| x.outpoint != coin.outpoint).cloned().collect();
                let loss = anon_loss(&reduced);
                if loss <= best_loss {
                    best_loss = loss;
                    best_reduced = reduced;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
            winner = best_reduced;
            winner_loss = best_loss;
        }
        if winner.len() < MAX_INPUTS_REGISTRABLE_BY_WALLET {
            let winner_scripts: HashSet<ScriptBuf> = winner.iter().map(|x| x.script.clone()).collect();
            let mut same_address: Vec<CjCoin> = filtered
                .iter()
                .filter(|x| !winner.iter().any(|w| w.outpoint == x.outpoint) && winner_scripts.contains(&x.script))
                .cloned()
                .collect();
            let mut counts: HashMap<ScriptBuf, usize> = HashMap::new();
            for c in &same_address {
                *counts.entry(c.script.clone()).or_default() += 1;
            }
            same_address.sort_by(|a, b| counts[&b.script].cmp(&counts[&a.script]));
            let take = MAX_INPUTS_REGISTRABLE_BY_WALLET - winner.len();
            let added = same_address.into_iter().take(take).collect::<Vec<_>>();
            if !added.is_empty() {
                tracing::info!("{} coins were added to the selection because they are on the same addresses of some selected coins.", added.len());
            }
            winner.extend(added);
        }
        winner.shuffle(rng);
        winner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn coin(i: u8, amount: i64, anon: f64) -> CjCoin {
        let txid = Txid::from_slice(&[i; 32]).unwrap();
        CjCoin { outpoint: OutPoint { txid, vout: 0 }, amount, script: ScriptBuf::new(), script_type: ScriptType::P2WPKH, anonymity_set: anon }
    }

    #[test]
    fn selects_non_private_coins_and_never_only_private() {
        let mut rng = rand::thread_rng();
        let params = UtxoSelectionParameters {
            allowed_input_amounts: (5000, 2_100_000_000),
            min_allowed_output_amount: 5000,
            mining_fee_rate: FeeRate::from_fee_per_k(1300),
            allowed_input_script_types: vec![ScriptType::P2WPKH, ScriptType::Taproot],
        };
        let coins: Vec<CjCoin> = (1..=12).map(|i| coin(i, 100_000 * i as i64, if i % 3 == 0 { 20.0 } else { 1.0 })).collect();
        let sel = CoinJoinCoinSelector::new(false, 10, true, false);
        let w = sel.select_coins_for_round(&coins, &params, 0, &mut rng);
        assert!(!w.is_empty() && w.len() <= MAX_INPUTS_REGISTRABLE_BY_WALLET);
        assert!(w.iter().any(|c| c.anonymity_set < 10.0));
        let only_private: Vec<CjCoin> = coins.iter().filter(|c| c.anonymity_set >= 10.0).cloned().collect();
        assert!(sel.select_coins_for_round(&only_private, &params, 0, &mut rng).is_empty());
    }

    #[test]
    fn combinations_are_complete() {
        let mut n = 0;
        for_each_combination(&[1, 2, 3, 4, 5], 3, |_| {
            n += 1;
            true
        });
        assert_eq!(n, 10);
    }
}
