//! Port of Wasabi's `DenominationBuilder`, `Decomposer` and `AmountDecomposer` (the "Sake" simulation).

use crate::units::{FeeRate, ScriptType};
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Output {
    pub amount: i64,
    pub script_type: ScriptType,
    pub fee: i64,
    pub input_fee: i64,
}

impl Output {
    fn new(amount: i64, script_type: ScriptType, fee_rate: FeeRate, is_effective_cost: bool) -> Self {
        let fee = fee_rate.get_fee(script_type.output_vsize());
        let input_fee = fee_rate.get_fee(script_type.input_vsize());
        Self { amount: if is_effective_cost { amount - fee } else { amount }, script_type, fee, input_fee }
    }
    pub fn from_denomination(amount: i64, script_type: ScriptType, fee_rate: FeeRate) -> Self {
        Self::new(amount, script_type, fee_rate, false)
    }
    pub fn from_amount(amount: i64, script_type: ScriptType, fee_rate: FeeRate) -> Self {
        Self::new(amount, script_type, fee_rate, true)
    }
    pub fn effective_amount(&self) -> i64 {
        self.amount - self.fee
    }
    pub fn effective_cost(&self) -> i64 {
        self.amount + self.fee
    }
}

/// `DenominationBuilder.CreateDenominationAmounts`
pub fn denomination_amounts(min_allowed: i64, max_allowed: i64) -> Vec<i64> {
    let mut set: HashSet<i64> = HashSet::new();
    let mut times = |times: i64, base: f64| {
        let mut i = 0;
        loop {
            let v = (times as f64) * base.powi(i);
            if v > max_allowed as f64 || i > 60 {
                break;
            }
            if v >= min_allowed as f64 {
                set.insert(v as i64);
            }
            i += 1;
        }
    };
    times(1, 2.0);
    times(1, 3.0);
    times(2, 3.0);
    times(1, 10.0);
    times(2, 10.0);
    times(5, 10.0);
    let mut v: Vec<i64> = set.into_iter().collect();
    v.sort_unstable();
    v
}

/// `DenominationBuilder.CreateDenominations`: one random allowed script type per denomination,
/// ordered by effective amount descending.
pub fn create_denominations<R: Rng>(min_allowed: i64, max_allowed: i64, fee_rate: FeeRate, allowed_types: &[ScriptType], rng: &mut R) -> Vec<Output> {
    let mut outs: Vec<Output> = denomination_amounts(min_allowed, max_allowed)
        .into_iter()
        .map(|d| Output::from_denomination(d, *allowed_types.choose(rng).expect("allowed types"), fee_rate))
        .collect();
    outs.sort_by(|a, b| b.effective_amount().cmp(&a.effective_amount()));
    outs
}

/// `Decomposer.Decompose`: changeless combinations of `denoms` (sorted descending) summing to
/// within `tolerance` below `target`, at most `max_count` parts, at most 10,000 results.
pub fn decompose(target: i64, tolerance: i64, max_count: usize, denoms: &[i64]) -> Vec<Vec<i64>> {
    assert!(target > 0 && tolerance > 0 && tolerance < target);
    let mut out = Vec::new();
    combos(Vec::new(), 0, target, tolerance, max_count, denoms, &mut out);
    out
}

fn combos(head: Vec<i64>, sum: i64, target: i64, tolerance: i64, k: usize, denoms: &[i64], out: &mut Vec<Vec<i64>>) {
    if out.len() >= 10_000 {
        return;
    }
    let remaining = target - sum;
    if k == 0 || remaining < tolerance {
        out.push(head);
        return;
    }
    let start = denoms.iter().position(|d| *d <= remaining).unwrap_or(denoms.len());
    let new_denoms = &denoms[start..];
    for (i, d) in new_denoms.iter().enumerate() {
        if (k as i64) * d < remaining - tolerance {
            break;
        }
        let mut sub = Vec::new();
        let mut h = head.clone();
        h.push(*d);
        combos(h, sum + d, target, tolerance, k - 1, &new_denoms[i..], &mut sub);
        // TakeUntil(sum == target): keep results up to and including the first exact hit.
        for s in sub {
            let exact = s.iter().sum::<i64>() == target;
            out.push(s);
            if exact || out.len() >= 10_000 {
                break;
            }
        }
        if out.len() >= 10_000 {
            return;
        }
    }
}

pub struct AmountDecomposer {
    pub fee_rate: FeeRate,
    pub available_vsize: i64,
    pub allowed_output_types: Vec<ScriptType>,
    pub min_allowed_output_amount: i64,
    pub max_allowed_output_amount: i64,
    pub denominations: Vec<Output>,
    pub change_script_type: ScriptType,
}

type Candidate = (Vec<Output>, i64);

impl AmountDecomposer {
    pub fn new<R: Rng>(fee_rate: FeeRate, min_allowed_output_amount: i64, max_allowed_output_amount: i64, available_vsize: i64, allowed_output_types: Vec<ScriptType>, rng: &mut R) -> Self {
        let denominations = create_denominations(min_allowed_output_amount, max_allowed_output_amount, fee_rate, &allowed_output_types, rng);
        let change_script_type = *allowed_output_types.choose(rng).expect("allowed types");
        Self { fee_rate, available_vsize, allowed_output_types, min_allowed_output_amount, max_allowed_output_amount, denominations, change_script_type }
    }

    pub fn change_fee(&self) -> i64 {
        self.fee_rate.get_fee(self.change_script_type.output_vsize())
    }

    fn filtered_denominations(&self, all_input_effective_values: &[i64]) -> Vec<Output> {
        let histogram = self.denomination_frequencies(all_input_effective_values);
        let mut pre: Vec<Output> = histogram.into_iter().filter(|(_, c)| *c > 1).map(|(o, _)| o).collect();
        pre.sort_by(|a, b| b.effective_cost().cmp(&a.effective_cost()));
        let increment = 0.5 / pre.len().max(1) as f64;
        let mut denoms: Vec<Output> = Vec::new();
        let mut current_length = pre.len();
        for denom in pre {
            let filter_severity = 1.0 + (current_length as f64 * increment);
            if denoms.is_empty() || denom.amount <= (denoms.last().unwrap().amount as f64 / filter_severity) as i64 {
                denoms.push(denom);
            }
            current_length -= 1;
        }
        denoms
    }

    fn denomination_frequencies(&self, input_effective_values: &[i64]) -> HashMap<Output, i64> {
        let mut sorted = input_effective_values.to_vec();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let second_largest = sorted.get(1).copied().unwrap_or(0);
        let mut denoms_for_breakdown: Vec<&Output> = self.denominations.iter().filter(|x| x.effective_cost() <= second_largest).collect();
        denoms_for_breakdown.sort_by(|a, b| b.effective_amount().cmp(&a.effective_amount()));
        let mut freq: HashMap<Output, i64> = HashMap::new();
        for input in input_effective_values {
            for d in self.break_down(*input, &denoms_for_breakdown) {
                *freq.entry(d).or_default() += 1;
            }
        }
        freq
    }

    fn break_down(&self, coin_input_effective_value: i64, denominations: &[&Output]) -> Vec<Output> {
        let mut remaining = coin_input_effective_value;
        let mut denoms = Vec::new();
        for denom in denominations {
            if denom.amount < self.min_allowed_output_amount || remaining < self.min_allowed_output_amount + self.change_fee() {
                break;
            }
            while denom.effective_cost() <= remaining {
                denoms.push((*denom).clone());
                remaining -= denom.effective_cost();
            }
        }
        if remaining >= self.min_allowed_output_amount + self.change_fee() {
            denoms.push(Output::from_amount(remaining, self.change_script_type, self.fee_rate));
        }
        denoms
    }

    fn cost(outputs: &[Output]) -> i64 {
        outputs.iter().map(|o| o.fee).sum::<i64>() + outputs.iter().map(|o| o.input_fee).sum::<i64>()
    }

    fn key(outputs: &[Output]) -> Vec<i64> {
        let mut v: Vec<(i64, i64)> = outputs.iter().map(|o| (o.effective_cost(), o.amount)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, a)| a).collect()
    }

    pub fn decompose<R: Rng>(&self, my_input_sum: i64, all_input_effective_values: &[i64], is_performing_a_payment: bool, rng: &mut R) -> anyhow::Result<Vec<Output>> {
        let denoms = self.filtered_denominations(all_input_effective_values);
        let smallest_script = ScriptType::P2WPKH.output_vsize().min(ScriptType::Taproot.output_vsize());
        let max_outputs = ((self.available_vsize / smallest_script) as usize).min(10);
        if denoms.is_empty() {
            anyhow::bail!("No valid output denominations found. This can occur when an insufficient number of coins are registered to participate in the coinjoin.");
        }
        if !is_performing_a_payment && denoms.iter().map(|x| x.effective_cost()).min().unwrap() > my_input_sum {
            anyhow::bail!("Not enough coins registered to participate in the coinjoin.");
        }
        let mut candidates: HashMap<Vec<i64>, Candidate> = HashMap::new();
        let naive = self.naive_decomposition(&denoms, my_input_sum, max_outputs);
        candidates.insert(Self::key(&naive.0), naive);
        for c in self.pre_decompositions(&denoms, my_input_sum, max_outputs, rng) {
            candidates.entry(Self::key(&c.0)).or_insert(c);
        }
        for c in self.changeless_decompositions(&denoms, my_input_sum, max_outputs) {
            candidates.entry(Self::key(&c.0)).or_insert(c);
        }
        let denom_set: HashSet<Output> = denoms.iter().cloned().collect();
        let mut pre: Vec<Candidate> = candidates.into_values().collect();
        let changeless: Vec<Candidate> = pre.iter().filter(|c| c.0.iter().all(|o| denom_set.contains(o))).cloned().collect();
        let change_avoided = !changeless.is_empty();
        if change_avoided {
            pre = changeless;
        }
        pre.shuffle(rng);
        let find_change = |d: &[Output]| -> i64 { d.iter().filter(|o| !denom_set.contains(o)).map(|o| o.amount).sum() };
        let mixed = |d: &[Output]| -> i32 {
            if d.iter().any(|o| o.script_type == ScriptType::Taproot) && d.iter().any(|o| o.script_type == ScriptType::P2WPKH) {
                0
            } else {
                1
            }
        };
        pre.sort_by(|a, b| find_change(&a.0).cmp(&find_change(&b.0)).then(a.1.cmp(&b.1)).then(mixed(&a.0).cmp(&mixed(&b.0))));
        let finals: Vec<Candidate> = if change_avoided {
            let best_cost = pre[0].1;
            let tolerance = (best_cost as f64 * 1.2) as i64;
            pre.iter().filter(|c| c.1 <= tolerance).cloned().collect()
        } else {
            let best_change = find_change(&pre[0].0);
            let tolerance = ((my_input_sum as f64) * 0.1).max(best_change as f64 * 1.2).max(100_000.0) as i64;
            pre.iter().filter(|c| find_change(&c.0) <= tolerance).cloned().collect()
        };
        let largest_set: Vec<Output> = {
            let mut seen = HashSet::new();
            finals.iter().filter_map(|c| c.0.first().cloned()).filter(|o| seen.insert(o.clone())).collect()
        };
        let Some(largest) = largest_set.choose(rng).cloned() else { anyhow::bail!("no decomposition fits the available vsize") };
        let matching: Vec<&Candidate> = finals.iter().filter(|c| c.0.first() == Some(&largest)).collect();
        let Some(final_candidate) = matching.choose(rng).map(|c| c.0.clone()) else { anyhow::bail!("no decomposition fits the available vsize") };
        let total_output: i64 = final_candidate.iter().map(|x| x.effective_cost()).sum();
        if total_output > my_input_sum {
            anyhow::bail!("The decomposer is creating money. Aborting.");
        }
        if total_output + self.min_allowed_output_amount + self.change_fee() < my_input_sum {
            anyhow::bail!("The decomposer is losing money. Aborting.");
        }
        let total_vsize: i64 = final_candidate.iter().map(|d| d.script_type.output_vsize()).sum();
        if total_vsize > self.available_vsize {
            anyhow::bail!("The decomposer created more outputs than it can. Aborting.");
        }
        Ok(final_candidate)
    }

    fn changeless_decompositions(&self, denoms: &[Output], my_input_sum: i64, max_outputs: usize) -> Vec<Candidate> {
        let mut out = Vec::new();
        let mut std: Vec<i64> = denoms.iter().map(|d| d.effective_cost()).filter(|x| *x <= my_input_sum).collect();
        std.sort_unstable_by(|a, b| b.cmp(a));
        if max_outputs > 1 {
            for decomposition in decompose(my_input_sum, self.min_allowed_output_amount + self.change_fee(), max_outputs.min(8), &std) {
                let mut finals = Vec::new();
                for cost in decomposition {
                    finals.push(denoms.iter().find(|d| d.effective_cost() == cost).expect("denomination").clone());
                }
                let total_vsize: i64 = finals.iter().map(|d| d.script_type.output_vsize()).sum();
                if total_vsize > self.available_vsize {
                    continue;
                }
                let deficit = my_input_sum - finals.iter().map(|d| d.effective_cost()).sum::<i64>() + Self::cost(&finals);
                out.push((finals, deficit));
            }
        }
        out
    }

    fn pre_decompositions<R: Rng>(&self, denoms: &[Output], my_input_sum: i64, max_outputs: usize, rng: &mut R) -> Vec<Candidate> {
        let mut out: HashMap<Vec<i64>, Candidate> = HashMap::new();
        for _ in 0..10_000 {
            let mut remaining_vsize = self.available_vsize;
            let mut remaining = my_input_sum;
            let mut current: Vec<Output> = Vec::new();
            loop {
                let pool: Vec<&Output> = denoms.iter().filter(|x| x.effective_cost() <= remaining && x.effective_cost() >= remaining / 3).collect();
                let denom = pool.choose(rng).copied().or_else(|| denoms.iter().find(|x| x.effective_cost() <= remaining));
                let Some(denom) = denom else { break };
                let need_change = remaining >= denom.effective_cost() + self.min_allowed_output_amount + self.change_fee();
                if (!need_change && remaining_vsize < denom.script_type.output_vsize())
                    || (need_change && remaining_vsize < denom.script_type.output_vsize() + self.change_script_type.output_vsize())
                {
                    break;
                }
                current.push(denom.clone());
                remaining -= denom.effective_cost();
                remaining_vsize -= denom.script_type.output_vsize();
                if current.len() + 1 >= max_outputs {
                    break;
                }
            }
            let mut loss = 0;
            if remaining >= self.min_allowed_output_amount + self.change_fee() {
                current.push(Output::from_amount(remaining, self.change_script_type, self.fee_rate));
            } else {
                loss = remaining;
            }
            let cost = loss + Self::cost(&current);
            out.entry(Self::key(&current)).or_insert((current, cost));
        }
        out.into_values().collect()
    }

    fn naive_decomposition(&self, denoms: &[Output], my_input_sum: i64, max_outputs: usize) -> Candidate {
        let mut remaining_vsize = self.available_vsize;
        let mut remaining = my_input_sum;
        let mut naive: Vec<Output> = Vec::new();
        'outer: for denom in denoms.iter().filter(|x| x.amount <= my_input_sum) {
            while denom.effective_cost() <= remaining {
                let need_change = remaining >= denom.effective_cost() + self.min_allowed_output_amount + self.change_fee();
                if (!need_change && remaining_vsize < denom.script_type.output_vsize())
                    || (need_change && remaining_vsize < denom.script_type.output_vsize() + self.change_script_type.output_vsize())
                {
                    break 'outer;
                }
                naive.push(denom.clone());
                remaining -= denom.effective_cost();
                remaining_vsize -= denom.script_type.output_vsize();
                if naive.len() + 1 >= max_outputs {
                    break 'outer;
                }
            }
        }
        let mut loss = 0;
        if remaining >= self.min_allowed_output_amount + self.change_fee() {
            naive.push(Output::from_amount(remaining, self.change_script_type, self.fee_rate));
        } else {
            loss = remaining;
        }
        if naive.is_empty() {
            naive.push(Output::from_amount(remaining, self.change_script_type, self.fee_rate));
        }
        let cost = loss + Self::cost(&naive);
        (naive, cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_denominations_cover_wasabi_list() {
        let d = denomination_amounts(5000, 137438953472);
        for std in [5000i64, 6561, 8192, 10000, 13122, 16384, 19683, 20000, 100000, 1000000, 2097152, 4782969, 100000000, 137438953472] {
            assert!(d.contains(&std), "{std} missing");
        }
    }

    #[test]
    fn decomposer_splits_without_losing_money() {
        let mut rng = rand::thread_rng();
        let fee = FeeRate::from_fee_per_k(1300);
        let dec = AmountDecomposer::new(fee, 5000, 2_100_000_000, 255, vec![ScriptType::P2WPKH, ScriptType::Taproot], &mut rng);
        let others: Vec<i64> = (0..40).map(|i| 50_000 + i * 97_000).collect();
        let mine = 1_234_567;
        let mut all = others.clone();
        all.push(mine);
        let outs = dec.decompose(mine, &all, false, &mut rng).unwrap();
        let total: i64 = outs.iter().map(|o| o.effective_cost()).sum();
        assert!(total <= mine && total + 5000 + dec.change_fee() >= mine, "total {total} mine {mine}");
        assert!(outs.len() <= 8);
    }
}
