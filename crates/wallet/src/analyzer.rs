//! Port of Wasabi's `BlockchainAnalyzer`: anonymity scores per key (script), updated transaction
//! by transaction in blockchain order. Clusters (labels) are not ported.

use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use std::collections::{HashMap, HashSet};

/// `HdPubKey.DefaultHighAnonymitySet` sentinel: "not calculated yet".
pub const DEFAULT_HIGH: f64 = i32::MAX as f64;
const MAX_SATS: i64 = 2_099_999_997_690_000;

pub const STD_DENOMS: [i64; 79] = [
    5000, 6561, 8192, 10000, 13122, 16384, 19683, 20000, 32768, 39366, 50000, 59049, 65536, 100000, 118098, 131072, 177147, 200000, 262144, 354294, 500000, 524288, 531441, 1000000, 1048576, 1062882, 1594323,
    2000000, 2097152, 3188646, 4194304, 4782969, 5000000, 8388608, 9565938, 10000000, 14348907, 16777216, 20000000, 28697814, 33554432, 43046721, 50000000, 67108864, 86093442, 100000000, 129140163, 134217728,
    200000000, 258280326, 268435456, 387420489, 500000000, 536870912, 774840978, 1000000000, 1073741824, 1162261467, 2000000000, 2147483648, 2324522934, 3486784401, 4294967296, 5000000000, 6973568802,
    8589934592, 10000000000, 10460353203, 17179869184, 20000000000, 20920706406, 31381059609, 34359738368, 50000000000, 62762119218, 68719476736, 94143178827, 100000000000, 137438953472,
];

#[derive(Debug, Clone)]
pub struct CoinRef {
    pub outpoint: OutPoint,
    pub script: ScriptBuf,
    pub amount: i64,
}

#[derive(Debug, Clone)]
struct Virtual {
    script: ScriptBuf,
    amount: i64,
    coins: Vec<CoinRef>,
}

#[derive(Debug, Clone)]
struct ForeignVirtual {
    amount: i64,
    outpoints: Vec<OutPoint>,
}

#[derive(Debug, Clone)]
struct TxInfo {
    input_prevouts: Vec<OutPoint>,
    wallet_inputs: Vec<CoinRef>,
    wallet_virtual_inputs: Vec<Virtual>,
    wallet_virtual_outputs: Vec<Virtual>,
    foreign_virtual_outputs: Vec<ForeignVirtual>,
}

#[derive(Debug, Default)]
struct KeyAnon {
    anonset: Option<f64>,
    historical: HashMap<Txid, f64>,
}

#[derive(Debug, Default)]
pub struct Analyzer {
    keys: HashMap<ScriptBuf, KeyAnon>,
    txs: HashMap<Txid, TxInfo>,
}

#[derive(Debug, Clone, Copy)]
struct StartingAnonScores {
    minimum: (f64, f64),
    big_input_minimum: (f64, f64),
    weighted_average: (f64, f64),
}

fn weighted_average<I: Iterator<Item = (f64, i64)> + Clone>(items: I) -> f64 {
    let num: f64 = items.clone().map(|(v, w)| v * w as f64).sum();
    let den: f64 = {
        let s: i64 = items.map(|(_, w)| w).sum();
        if s == 0 { 1.0 } else { s as f64 }
    };
    num / den
}

fn min_or_default<I: Iterator<Item = f64>>(items: I) -> f64 {
    items.fold(None, |m: Option<f64>, v| Some(m.map(|x| x.min(v)).unwrap_or(v))).unwrap_or(0.0)
}

fn group_virtual(coins: &[CoinRef]) -> Vec<Virtual> {
    let mut out: Vec<Virtual> = Vec::new();
    for c in coins {
        if let Some(v) = out.iter_mut().find(|v| v.script == c.script) {
            v.amount += c.amount;
            v.coins.push(c.clone());
        } else {
            out.push(Virtual { script: c.script.clone(), amount: c.amount, coins: vec![c.clone()] });
        }
    }
    out
}

impl Analyzer {
    fn anon(&self, script: &ScriptBuf) -> f64 {
        self.keys.get(script).and_then(|k| k.anonset).unwrap_or(DEFAULT_HIGH)
    }

    /// Current anonymity score of a key, as reported for its coins (sentinel never leaks).
    pub fn anonymity_set(&self, script: &ScriptBuf) -> f64 {
        let a = self.anon(script);
        if a >= DEFAULT_HIGH { 1.0 } else { a }
    }

    fn set(&mut self, script: &ScriptBuf, value: f64, txid: Option<Txid>) {
        let k = self.keys.entry(script.clone()).or_default();
        k.anonset = Some(value);
        if let Some(t) = txid {
            k.historical.insert(t, value);
        }
    }

    fn intersect(anonsets: &[f64]) -> f64 {
        if anonsets.is_empty() {
            return 1.0;
        }
        let smallest = anonsets.iter().cloned().fold(f64::INFINITY, f64::min);
        let penalty = 2f64.powi(anonsets.len() as i32 - 1);
        (smallest / penalty.max(1.0)).max(1.0)
    }

    /// `BlockchainAnalyzer.Analyze`: `wallet_inputs` are our coins spent by `tx`, `wallet_outputs` our outputs.
    pub fn analyze(&mut self, tx: &Transaction, wallet_inputs: Vec<CoinRef>, wallet_outputs: Vec<CoinRef>) {
        let txid = tx.compute_txid();
        let our_output_indices: HashSet<u32> = wallet_outputs.iter().map(|c| c.outpoint.vout).collect();
        let mut foreign_virtual_outputs: Vec<ForeignVirtual> = Vec::new();
        {
            let mut by_script: Vec<(ScriptBuf, ForeignVirtual)> = Vec::new();
            for (i, o) in tx.output.iter().enumerate() {
                if our_output_indices.contains(&(i as u32)) {
                    continue;
                }
                let op = OutPoint { txid, vout: i as u32 };
                if let Some((_, fv)) = by_script.iter_mut().find(|(s, _)| *s == o.script_pubkey) {
                    fv.amount += o.value.to_sat() as i64;
                    fv.outpoints.push(op);
                } else {
                    by_script.push((o.script_pubkey.clone(), ForeignVirtual { amount: o.value.to_sat() as i64, outpoints: vec![op] }));
                }
            }
            foreign_virtual_outputs.extend(by_script.into_iter().map(|(_, f)| f));
        }
        let info = TxInfo {
            input_prevouts: tx.input.iter().map(|i| i.previous_output).collect(),
            wallet_virtual_inputs: group_virtual(&wallet_inputs),
            wallet_virtual_outputs: group_virtual(&wallet_outputs),
            wallet_inputs: wallet_inputs.clone(),
            foreign_virtual_outputs,
        };
        let own_input_count = wallet_inputs.len();
        let foreign_input_count = tx.input.len() - own_input_count;
        let foreign_output_count = tx.output.len() - wallet_outputs.len();
        let output_values: Vec<i64> = tx.output.iter().map(|o| o.value.to_sat() as i64).collect();
        let is_wasabi2_cj = tx.output.len() >= 2
            && tx.input.len() >= 21
            && (output_values.iter().filter(|v| STD_DENOMS.contains(v)).count() as f64) > output_values.len() as f64 * 0.8
            && output_values.windows(2).all(|w| w[0] >= w[1]);

        if own_input_count == 0 {
            for c in &wallet_outputs {
                self.set(&c.script, 1.0, Some(txid));
            }
        } else if foreign_input_count == 0 && foreign_output_count > 0 {
            for c in &wallet_inputs {
                self.set(&c.script, 1.0, None);
            }
            for c in &wallet_outputs {
                self.set(&c.script, 1.0, Some(txid));
            }
        } else {
            let starting_output_anonset;
            if foreign_input_count == 0 {
                let keys: Vec<ScriptBuf> = info.wallet_virtual_inputs.iter().map(|v| v.script.clone()).collect();
                let anonsets: Vec<f64> = keys.iter().map(|k| self.anon(k)).collect();
                let starting = Self::intersect(&anonsets);
                for k in &keys {
                    self.set(k, starting, None);
                }
                for c in &wallet_outputs {
                    let cur = self.anon(&c.script);
                    if (cur - DEFAULT_HIGH).abs() < 0.000001 {
                        self.set(&c.script, starting, Some(txid));
                    } else {
                        self.set(&c.script, Self::intersect(&[starting, cur]), Some(txid));
                    }
                }
                starting_output_anonset = starting;
            } else {
                let scores = self.coinjoin_inputs(&info);
                self.coinjoin_outputs(txid, &info, foreign_input_count, is_wasabi2_cj, scores);
                starting_output_anonset = scores.weighted_average.0;
            }
            // AdjustWalletInputs
            if !wallet_outputs.is_empty() {
                let smallest = wallet_outputs.iter().map(|c| self.anon(&c.script)).fold(f64::INFINITY, f64::min);
                if smallest < starting_output_anonset {
                    let keys: Vec<ScriptBuf> = info.wallet_virtual_inputs.iter().map(|v| v.script.clone()).collect();
                    for k in keys {
                        self.set(&k, smallest, None);
                    }
                }
            }
        }
        // ResetUncalculatedAnonScores
        for c in &wallet_outputs {
            if self.anon(&c.script) >= DEFAULT_HIGH {
                self.set(&c.script, 1.0, Some(txid));
            }
        }
        self.txs.insert(txid, info);
    }

    fn coinjoin_inputs(&self, info: &TxInfo) -> StartingAnonScores {
        let relevant: HashSet<OutPoint> = info.input_prevouts.iter().copied().collect();
        let vis = &info.wallet_virtual_inputs;
        let min_sanction = |vi: &Virtual| vi.coins.iter().map(|c| self.input_sanction(c, &relevant, true)).fold(f64::NEG_INFINITY, f64::max);
        let avg_sanction = |vi: &Virtual| vi.coins.iter().map(|c| self.input_sanction(c, &relevant, false)).fold(f64::NEG_INFINITY, f64::max);
        let unmixed = (min_or_default(vis.iter().map(|v| self.anon(&v.script))), min_or_default(vis.iter().map(|v| self.anon(&v.script) + min_sanction(v))));
        let mixed = (
            weighted_average(vis.iter().map(|v| (self.anon(&v.script), v.amount))),
            weighted_average(vis.iter().map(|v| (self.anon(&v.script) + avg_sanction(v), v.amount))),
        );
        // Half mixed: our inputs at the head of the (amount-ordered) input list.
        let mut large_keys: HashSet<ScriptBuf> = HashSet::new();
        for prevout in &info.input_prevouts {
            match info.wallet_inputs.iter().find(|c| c.outpoint == *prevout) {
                Some(c) => {
                    large_keys.insert(c.script.clone());
                }
                None => break,
            }
        }
        let larger: Vec<&Virtual> = vis.iter().filter(|v| large_keys.contains(&v.script)).collect();
        let half = min_or_default(larger.iter().map(|v| self.anon(&v.script)));
        let half_s = min_or_default(larger.iter().map(|v| self.anon(&v.script) + min_sanction(v)));
        StartingAnonScores { minimum: unmixed, big_input_minimum: (half.min(mixed.0), half_s.min(mixed.1)), weighted_average: mixed }
    }

    /// `ComputeInputSanction` (recursion depth 3, worst-case branch aggregation).
    fn input_sanction(&self, coin: &CoinRef, relevant: &HashSet<OutPoint>, use_min: bool) -> f64 {
        fn rec(a: &Analyzer, coin: &CoinRef, relevant: &HashSet<OutPoint>, use_min: bool, depth: u32, memo: &mut HashMap<OutPoint, f64>) -> f64 {
            if depth > 3 {
                return 0.0;
            }
            if let Some(v) = memo.get(&coin.outpoint) {
                return *v;
            }
            let Some(t) = a.txs.get(&coin.outpoint.txid) else { return 0.0 };
            let mut sanction = -a.contribution(t, &coin.outpoint, relevant);
            let branches: Vec<(f64, i64)> = t.wallet_inputs.iter().map(|c| (rec(a, c, relevant, use_min, depth + 1, memo), c.amount)).collect();
            sanction += if use_min { min_or_default(branches.iter().map(|b| b.0)) } else { weighted_average(branches.iter().copied()) };
            memo.insert(coin.outpoint, sanction);
            sanction
        }
        let mut memo = HashMap::new();
        rec(self, coin, relevant, use_min, 1, &mut memo)
    }

    /// `ComputeAnonymityContribution`: equal-valued relevant foreign outputs per equal-valued wallet output.
    fn contribution(&self, t: &TxInfo, outpoint: &OutPoint, relevant: &HashSet<OutPoint>) -> f64 {
        let Some(vo) = t.wallet_virtual_outputs.iter().find(|v| v.coins.iter().any(|c| c.outpoint == *outpoint)) else { return 0.0 };
        let amount = vo.amount;
        let equal_wallet = t.wallet_virtual_outputs.iter().filter(|v| v.amount == amount).count().max(1);
        let equal_foreign = t.foreign_virtual_outputs.iter().filter(|f| f.outpoints.iter().any(|o| relevant.contains(o))).filter(|f| f.amount == amount).count();
        equal_foreign as f64 / equal_wallet as f64
    }

    fn coinjoin_outputs(&mut self, txid: Txid, info: &TxInfo, foreign_input_count: usize, is_wasabi2_cj: bool, scores: StartingAnonScores) {
        let mut max_wa: Option<i64> = None;
        let all_foreign: HashSet<OutPoint> = info.foreign_virtual_outputs.iter().flat_map(|f| f.outpoints.iter().copied()).collect();
        let input_keys: HashSet<ScriptBuf> = info.wallet_virtual_inputs.iter().map(|v| v.script.clone()).collect();
        for vo in &info.wallet_virtual_outputs {
            let starting = if info.foreign_virtual_outputs.iter().all(|f| f.amount != vo.amount) {
                if is_wasabi2_cj && STD_DENOMS.contains(&vo.amount) {
                    if max_wa.is_none() {
                        max_wa = Some(self.largest_equal_foreign_output_amount(info).unwrap_or(MAX_SATS));
                    }
                    if vo.amount <= max_wa.unwrap() { scores.weighted_average } else { scores.big_input_minimum }
                } else {
                    scores.minimum
                }
            } else {
                scores.weighted_average
            };
            let gain = self.contribution(info, &vo.coins[0].outpoint, &all_foreign).min(foreign_input_count as f64);
            let anonset = (starting.1 + gain).max(gain + 1.0).max(starting.0);
            for c in &vo.coins {
                let cur = self.anon(&c.script);
                if (cur - DEFAULT_HIGH).abs() < 0.00001 {
                    self.set(&c.script, anonset, Some(txid));
                } else if input_keys.contains(&c.script) {
                    self.set(&c.script, starting.1, Some(txid));
                } else if self.keys.get(&c.script).map(|k| k.historical.contains_key(&txid)).unwrap_or(false) {
                    if self.keys[&c.script].historical.len() == 1 {
                        self.set(&c.script, anonset, Some(txid));
                    }
                } else {
                    self.set(&c.script, Self::intersect(&[anonset, cur]), Some(txid));
                }
            }
        }
    }

    fn largest_equal_foreign_output_amount(&self, info: &TxInfo) -> Option<i64> {
        let mut counts: HashMap<i64, usize> = HashMap::new();
        for f in &info.foreign_virtual_outputs {
            *counts.entry(f.amount).or_default() += 1;
        }
        counts.into_iter().filter(|(_, n)| *n > 1).map(|(a, _)| a).max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn spk(n: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([n; 20]))
    }

    fn tx(inputs: Vec<OutPoint>, outputs: Vec<(u8, i64)>) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: inputs.into_iter().map(|o| TxIn { previous_output: o, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }).collect(),
            output: outputs.into_iter().map(|(s, v)| TxOut { value: Amount::from_sat(v as u64), script_pubkey: spk(s) }).collect(),
        }
    }

    #[test]
    fn receive_then_coinjoin_gains_anonymity() {
        let mut a = Analyzer::default();
        // Receive 100_000 sat to key 1.
        let t0 = tx(vec![OutPoint { txid: Txid::from_slice(&[9; 32]).unwrap(), vout: 0 }], vec![(1, 100_000)]);
        let t0id = t0.compute_txid();
        a.analyze(&t0, vec![], vec![CoinRef { outpoint: OutPoint { txid: t0id, vout: 0 }, script: spk(1), amount: 100_000 }]);
        assert_eq!(a.anonymity_set(&spk(1)), 1.0);
        // Coinjoin: 25 inputs (ours first), 30 outputs; ours: one 50_000 denom among 9 foreign 50_000s.
        let mut inputs = vec![OutPoint { txid: t0id, vout: 0 }];
        for i in 0..24u8 {
            inputs.push(OutPoint { txid: Txid::from_slice(&[i + 10; 32]).unwrap(), vout: 0 });
        }
        let mut outputs = vec![(2, 50_000)];
        for i in 0..9u8 {
            outputs.push((100 + i, 50_000));
        }
        for i in 0..20u8 {
            outputs.push((150 + i, 20_000));
        }
        outputs.sort_by(|x, y| y.1.cmp(&x.1));
        let t1 = tx(inputs, outputs);
        let t1id = t1.compute_txid();
        let our_vout = t1.output.iter().position(|o| o.script_pubkey == spk(2)).unwrap() as u32;
        a.analyze(
            &t1,
            vec![CoinRef { outpoint: OutPoint { txid: t0id, vout: 0 }, script: spk(1), amount: 100_000 }],
            vec![CoinRef { outpoint: OutPoint { txid: t1id, vout: our_vout }, script: spk(2), amount: 50_000 }],
        );
        let score = a.anonymity_set(&spk(2));
        assert!(score >= 10.0 && score <= 11.0, "score {score}");
    }
}
