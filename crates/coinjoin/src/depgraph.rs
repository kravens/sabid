//! Port of Wasabi's `DependencyGraph` / `CredentialEdgeSet`: plans which credentials each
//! request (connection confirmation, reissuance, output registration) presents and requests so
//! that amounts and vsizes balance with at most K=2 credentials per request.

use std::cmp::Ordering;

pub const K: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    Amount = 0,
    Vsize = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Input,
    Output,
    Reissuance,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub kind: NodeKind,
    pub amount: i64,
    pub vsize: i64,
    pub max_in_degree: usize,
    pub max_out_degree: usize,
    pub max_zero_only_out_degree: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub id: usize,
    pub from: usize,
    pub to: usize,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct EdgeSet {
    pub kind: CredentialType,
    pub max_credential_value: i64,
    pub edges: Vec<Edge>,
    in_edges: Vec<Vec<usize>>,
    out_edges: Vec<Vec<usize>>,
    edge_balances: Vec<i64>,
}

#[derive(Debug, thiserror::Error)]
#[error("dependency graph: {0}")]
pub struct GraphError(String);

type R<T> = Result<T, GraphError>;

impl EdgeSet {
    fn new(kind: CredentialType, max_credential_value: i64) -> Self {
        Self { kind, max_credential_value, edges: vec![], in_edges: vec![], out_edges: vec![], edge_balances: vec![] }
    }
    fn add_node(&mut self) {
        self.in_edges.push(vec![]);
        self.out_edges.push(vec![]);
        self.edge_balances.push(0);
    }
    pub fn balance(&self, nodes: &[Node], n: usize) -> i64 {
        let base = match self.kind {
            CredentialType::Amount => nodes[n].amount,
            CredentialType::Vsize => nodes[n].vsize,
        };
        base + self.edge_balances[n]
    }
    pub fn in_degree(&self, n: usize) -> usize {
        self.in_edges[n].len()
    }
    pub fn out_degree(&self, n: usize) -> usize {
        self.out_edges[n].iter().filter(|e| self.edges[**e].value != 0).count()
    }
    pub fn zero_only_out_degree(&self, n: usize) -> usize {
        self.out_edges[n].iter().filter(|e| self.edges[**e].value == 0).count()
    }
    pub fn remaining_in_degree(&self, nodes: &[Node], n: usize) -> usize {
        nodes[n].max_in_degree - self.in_degree(n)
    }
    pub fn remaining_out_degree(&self, nodes: &[Node], n: usize) -> usize {
        nodes[n].max_out_degree - self.out_degree(n)
    }
    pub fn remaining_zero_only_out_degree(&self, nodes: &[Node], n: usize) -> usize {
        nodes[n].max_zero_only_out_degree - self.zero_only_out_degree(n)
    }
    pub fn available_zero_out_degree(&self, nodes: &[Node], n: usize) -> i64 {
        self.remaining_zero_only_out_degree(nodes, n) as i64 + (self.remaining_out_degree(nodes, n) as i64 - if self.balance(nodes, n) > 0 { 1 } else { 0 })
    }
    /// In-edges of a node, by value descending (the order credentials are presented in).
    pub fn in_edges(&self, n: usize) -> Vec<Edge> {
        let mut v: Vec<Edge> = self.in_edges[n].iter().map(|e| self.edges[*e]).collect();
        v.sort_by(|a, b| b.value.cmp(&a.value));
        v
    }
    pub fn out_edges(&self, n: usize) -> Vec<Edge> {
        let mut v: Vec<Edge> = self.out_edges[n].iter().map(|e| self.edges[*e]).collect();
        v.sort_by(|a, b| b.value.cmp(&a.value));
        v
    }

    fn add_edge(&mut self, nodes: &[Node], from: usize, to: usize, value: i64) -> R<()> {
        if self.remaining_in_degree(nodes, to) == 0 {
            return Err(GraphError("Can't add more than k in edges per node.".into()));
        }
        if value > 0 {
            if self.remaining_out_degree(nodes, from) == 0 {
                return Err(GraphError("Can't add more than k non-zero out edges per node.".into()));
            }
            if self.remaining_out_degree(nodes, from) == 1 {
                if self.balance(nodes, from) - value > 0 {
                    return Err(GraphError(format!("Can't add final out edge without discharging positive value (edge value {value} but node balance is {}).", self.balance(nodes, from))));
                }
                if self.remaining_in_degree(nodes, from) == 0 && self.balance(nodes, from) - value != 0 {
                    return Err(GraphError("Can't add final in edge without discharging negative value completely.".into()));
                }
            }
        } else if self.available_zero_out_degree(nodes, from) == 0 {
            return Err(GraphError("Can't add more than 2k zero/non-zero out edge per node.".into()));
        }
        if self.remaining_in_degree(nodes, to) == 1 {
            if self.balance(nodes, to) + value < 0 {
                return Err(GraphError("Can't add final in edge without discharging negative value.".into()));
            }
            if self.remaining_out_degree(nodes, to) == 0 && self.balance(nodes, to) + value != 0 {
                return Err(GraphError("Can't add final in edge without discharging negative value completely.".into()));
            }
        }
        if self.remaining_out_degree(nodes, to) == 0 && self.balance(nodes, to) + value > 0 {
            return Err(GraphError("Can't add edge with excess value to node with no remaining out degree.".into()));
        }
        let id = self.edges.len();
        self.edges.push(Edge { id, from, to, value });
        self.in_edges[to].push(id);
        self.out_edges[from].push(id);
        self.edge_balances[from] -= value;
        self.edge_balances[to] += value;
        Ok(())
    }

    fn add_zero_edges(&mut self, nodes: &[Node], src: usize, dst: usize) -> R<()> {
        while self.remaining_in_degree(nodes, dst) > 0 {
            self.add_edge(nodes, src, dst, 0)?;
        }
        Ok(())
    }

    fn drain_reissuance_one(&mut self, nodes: &[Node], reissuance: usize, node: usize) -> R<()> {
        let value = self.balance(nodes, node);
        if (self.balance(nodes, reissuance) + value).abs() > self.max_credential_value {
            return Ok(());
        }
        if value > 0 {
            return self.add_edge(nodes, node, reissuance, value);
        }
        if value < 0 {
            self.add_edge(nodes, reissuance, node, -value)?;
            return self.add_zero_edges(nodes, reissuance, node);
        }
        if self.in_degree(reissuance) == 0 {
            return self.add_zero_edges(nodes, reissuance, node);
        }
        Ok(())
    }

    fn drain_reissuance(&mut self, nodes: &[Node], reissuance: usize, from: &[usize]) -> R<()> {
        for n in from {
            self.drain_reissuance_one(nodes, reissuance, *n)?;
        }
        Ok(())
    }

    fn drain_terminal_one(&mut self, nodes: &[Node], node: usize, discharge: usize) -> R<()> {
        let value = self.balance(nodes, discharge);
        if value < 0 {
            return self.add_edge(nodes, node, discharge, self.balance(nodes, node).min(-value));
        }
        if value > 0 {
            let edge_value = (-self.balance(nodes, node)).min(value);
            if edge_value == value || self.remaining_out_degree(nodes, discharge) > 1 {
                return self.add_edge(nodes, discharge, node, edge_value);
            }
        }
        Ok(())
    }

    fn drain_terminal(&mut self, nodes: &[Node], node: usize, others: &[usize]) -> R<()> {
        for o in others {
            self.drain_terminal_one(nodes, node, *o)?;
        }
        Ok(())
    }

    fn drain_zero_credentials(&mut self, nodes: &[Node], src: usize, dst: usize) -> R<()> {
        while !(self.balance(nodes, dst) != 0 || self.available_zero_out_degree(nodes, src) == 0 || self.remaining_in_degree(nodes, dst) == 0) {
            self.add_edge(nodes, src, dst, 0)?;
        }
        Ok(())
    }

    /// `MatchNodesToDischarge`: (largest magnitude node, smaller nodes, fan-in)
    fn match_nodes_to_discharge(&self, nodes: &[Node], with_out: &[usize], with_in: &[usize]) -> (usize, Vec<usize>, bool) {
        let mut sources = with_out.to_vec();
        sources.sort_by(|&a, &b| {
            self.balance(nodes, b)
                .cmp(&self.balance(nodes, a))
                .then(self.remaining_out_degree(nodes, b).cmp(&self.remaining_out_degree(nodes, a)))
                .then(self.available_zero_out_degree(nodes, b).cmp(&self.available_zero_out_degree(nodes, a)))
        });
        let mut sinks = with_in.to_vec();
        sinks.sort_by(|&a, &b| self.balance(nodes, a).cmp(&self.balance(nodes, b)).then(self.remaining_in_degree(nodes, b).cmp(&self.remaining_in_degree(nodes, a))));
        let balance_sign = |p: usize, n: usize| -> Ordering {
            let ps: i64 = sources.iter().take(p).map(|&v| self.balance(nodes, v)).sum();
            let ns: i64 = sinks.iter().take(n).map(|&v| -self.balance(nodes, v)).sum();
            ps.cmp(&ns)
        };
        let mut prev = balance_sign(1, 1);
        let (mut p, mut n) = (1usize, 1usize);
        let (mut avail_p, mut avail_n) = (sources.len(), sinks.len());
        loop {
            let sign = balance_sign(p, n);
            if sign == prev && sign == Ordering::Less && avail_p > 0 {
                p += 1;
                avail_p -= 1;
                prev = sign;
                continue;
            }
            if sign == prev && sign == Ordering::Greater && avail_n > 0 {
                n += 1;
                avail_n -= 1;
                prev = sign;
                continue;
            }
            let fan_in = prev == Ordering::Less;
            return if fan_in {
                let mut small: Vec<usize> = sources.iter().take(p).copied().collect();
                small.reverse();
                (sinks[0], small, true)
            } else {
                (sources[0], sinks.iter().take(n).copied().collect(), false)
            };
        }
    }
}

#[derive(Debug, Clone)]
pub struct DependencyGraph {
    pub nodes: Vec<Node>,
    pub edge_sets: [EdgeSet; 2],
}

impl DependencyGraph {
    /// `ResolveCredentialDependencies(effectiveValues, outputs, feeRate, availableVsizes, ...)`
    /// with inputs as `(effective value, vsize credential)` and outputs as `(effective cost, output vsize)`.
    pub fn resolve(inputs: &[(i64, i64)], outputs: &[(i64, i64)], max_amount_credential: i64, max_vsize_credential: i64) -> R<Self> {
        if inputs.iter().chain(outputs).any(|(a, v)| *a < 0 || *v < 0) {
            return Err(GraphError("All values must be positive.".into()));
        }
        if inputs.iter().map(|x| x.0).sum::<i64>() < outputs.iter().map(|x| x.0).sum::<i64>()
            || inputs.iter().map(|x| x.1).sum::<i64>() < outputs.iter().map(|x| x.1).sum::<i64>()
        {
            return Err(GraphError("Overall balance must not be negative.".into()));
        }
        let mut g = Self { nodes: vec![], edge_sets: [EdgeSet::new(CredentialType::Amount, max_amount_credential), EdgeSet::new(CredentialType::Vsize, max_vsize_credential)] };
        for (a, v) in inputs {
            g.add_node(Node { kind: NodeKind::Input, amount: *a, vsize: *v, max_in_degree: 0, max_out_degree: K, max_zero_only_out_degree: K * (K - 1) });
        }
        for (a, v) in outputs {
            g.add_node(Node { kind: NodeKind::Output, amount: -a, vsize: -v, max_in_degree: K, max_out_degree: 0, max_zero_only_out_degree: 0 });
        }
        g.resolve_negative_balance_nodes(CredentialType::Amount)?;
        g.resolve_negative_balance_nodes(CredentialType::Vsize)?;
        g.resolve_zero_credentials(CredentialType::Amount)?;
        g.resolve_zero_credentials(CredentialType::Vsize)?;
        Ok(g)
    }

    fn add_node(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        for es in &mut self.edge_sets {
            es.add_node();
        }
        self.nodes.len() - 1
    }

    pub fn inputs(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|&i| self.nodes[i].kind == NodeKind::Input).collect()
    }
    pub fn outputs(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|&i| self.nodes[i].kind == NodeKind::Output).collect()
    }
    pub fn reissuances(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|&i| self.nodes[i].kind == NodeKind::Reissuance).collect()
    }
    pub fn es(&self, ct: CredentialType) -> &EdgeSet {
        &self.edge_sets[ct as usize]
    }
    pub fn in_edges(&self, node: usize, ct: CredentialType) -> Vec<Edge> {
        self.es(ct).in_edges(node)
    }
    pub fn out_edges(&self, node: usize, ct: CredentialType) -> Vec<Edge> {
        self.es(ct).out_edges(node)
    }

    fn resolve_negative_balance_nodes(&mut self, ct: CredentialType) -> R<()> {
        loop {
            self.resolve_uniform_input_special_cases(ct)?;
            let es = &self.edge_sets[ct as usize];
            let positive: Vec<usize> = (0..self.nodes.len()).filter(|&v| es.balance(&self.nodes, v) > 0).collect();
            let negative: Vec<usize> = (0..self.nodes.len()).filter(|&v| es.balance(&self.nodes, v) < 0).collect();
            if negative.is_empty() {
                return Ok(());
            }
            let (mut largest, mut small, fan_in) = es.match_nodes_to_discharge(&self.nodes, &positive, &negative);
            let mut max_count = if fan_in { es.remaining_in_degree(&self.nodes, largest) } else { es.remaining_out_degree(&self.nodes, largest) };
            let small_sum: i64 = small.iter().map(|&v| es.balance(&self.nodes, v)).sum();
            match es.balance(&self.nodes, largest).abs().cmp(&small_sum.abs()) {
                Ordering::Greater => {
                    if max_count > 1 {
                        max_count -= 1;
                    } else {
                        largest = self.aggregate_into_reissuance_node(&[largest], ct)?;
                    }
                }
                Ordering::Less => {
                    let es = &self.edge_sets[ct as usize];
                    let degree = |v: usize| if fan_in { es.remaining_out_degree(&self.nodes, v) } else { es.remaining_in_degree(&self.nodes, v) };
                    small.sort_by_key(|&v| degree(v));
                    if small.len() <= max_count && degree(*small.last().unwrap()) == 1 {
                        max_count = max_count.min(small.len() - 1);
                    }
                }
                Ordering::Equal => {}
            }
            let small = self.reduce_nodes(small, max_count, ct)?;
            self.edge_sets[ct as usize].drain_terminal(&self.nodes, largest, &small)?;
        }
    }

    fn resolve_uniform_input_special_cases(&mut self, ct: CredentialType) -> R<()> {
        let es = &self.edge_sets[ct as usize];
        let mut negative: Vec<usize> = (0..self.nodes.len()).filter(|&v| es.balance(&self.nodes, v) < 0).collect();
        negative.sort_by_key(|&v| es.balance(&self.nodes, v));
        if negative.is_empty() {
            return Ok(());
        }
        let mut unconstrained: Vec<usize> = (0..self.nodes.len()).filter(|&v| es.balance(&self.nodes, v) > 0 && es.remaining_out_degree(&self.nodes, v) > 1).collect();
        unconstrained.sort_by(|&a, &b| es.balance(&self.nodes, b).cmp(&es.balance(&self.nodes, a)));
        let distinct: std::collections::HashSet<i64> = unconstrained.iter().map(|&v| es.balance(&self.nodes, v)).collect();
        if distinct.len() == 1 {
            let u0 = es.balance(&self.nodes, unconstrained[0]);
            let n0 = es.balance(&self.nodes, negative[0]);
            if (unconstrained.len() as i64) * u0 > -(negative.len() as i64) * n0 && negative.len() > unconstrained.len() {
                negative = self.reduce_nodes(negative, unconstrained.len(), ct)?;
            }
        }
        let es = &self.edge_sets[ct as usize];
        if negative.len() <= unconstrained.len() && unconstrained.iter().zip(&negative).all(|(&p, &n)| es.balance(&self.nodes, p) + es.balance(&self.nodes, n) >= 0) {
            let pairs: Vec<(usize, usize)> = unconstrained.iter().copied().zip(negative.iter().copied()).collect();
            for (p, n) in pairs {
                self.edge_sets[ct as usize].drain_terminal(&self.nodes, p, &[n])?;
            }
        }
        Ok(())
    }

    fn reduce_nodes(&mut self, mut nodes: Vec<usize>, max_count: usize, ct: CredentialType) -> R<Vec<usize>> {
        if max_count == 0 && !nodes.is_empty() {
            return Err(GraphError("cannot reduce nodes to zero (would loop forever)".into()));
        }
        while nodes.len() > max_count {
            let take = K.min(nodes.len());
            let head: Vec<usize> = nodes.drain(..take).collect();
            let r = self.aggregate_into_reissuance_node(&head, ct)?;
            nodes.push(r);
        }
        Ok(nodes)
    }

    fn aggregate_into_reissuance_node(&mut self, from: &[usize], ct: CredentialType) -> R<usize> {
        let r = self.add_node(Node { kind: NodeKind::Reissuance, amount: 0, vsize: 0, max_in_degree: K, max_out_degree: K, max_zero_only_out_degree: K * (K - 1) });
        self.drain_reissuance(r, from, ct)?;
        if ct as usize > 0 {
            for &v in from {
                self.edge_sets[0].drain_zero_credentials(&self.nodes, r, v)?;
            }
        }
        Ok(r)
    }

    fn drain_reissuance(&mut self, r: usize, from: &[usize], ct: CredentialType) -> R<()> {
        self.edge_sets[ct as usize].drain_reissuance(&self.nodes, r, from)?;
        if (ct as usize) + 1 < self.edge_sets.len() {
            self.edge_sets[ct as usize + 1].drain_reissuance(&self.nodes, r, from)?;
        }
        Ok(())
    }

    fn zero_pass(&mut self, ct: CredentialType, terminal: bool) -> R<bool> {
        let es = &self.edge_sets[ct as usize];
        let mut unresolved: Vec<usize> = (0..self.nodes.len())
            .filter(|&v| es.remaining_in_degree(&self.nodes, v) > 0 && (terminal || es.available_zero_out_degree(&self.nodes, v) > 0))
            .collect();
        unresolved.sort_by(|&a, &b| es.available_zero_out_degree(&self.nodes, b).cmp(&es.available_zero_out_degree(&self.nodes, a)));
        if unresolved.is_empty() {
            return Ok(false);
        }
        let mut providers: Vec<usize> = Vec::new();
        for v in 0..self.nodes.len() {
            if es.remaining_in_degree(&self.nodes, v) == 0 {
                for _ in 0..es.available_zero_out_degree(&self.nodes, v).max(0) {
                    providers.push(v);
                }
            }
        }
        let mut targets: Vec<usize> = Vec::new();
        for &v in &unresolved {
            for _ in 0..es.remaining_in_degree(&self.nodes, v) {
                targets.push(v);
            }
        }
        let pairs: Vec<(usize, usize)> = providers.into_iter().zip(targets).collect();
        if pairs.is_empty() {
            return Err(GraphError("no zero credential providers left".into()));
        }
        for (from, to) in pairs {
            self.edge_sets[ct as usize].add_edge(&self.nodes, from, to, 0)?;
        }
        Ok(true)
    }

    fn resolve_zero_credentials(&mut self, ct: CredentialType) -> R<()> {
        while self.zero_pass(ct, false)? {}
        while self.zero_pass(ct, true)? {}
        Ok(())
    }

    /// Debug view in graphviz dot format (as Wasabi's `AsGraphviz`).
    pub fn as_graphviz(&self) -> String {
        let mut s = String::from("digraph {\n");
        for (i, n) in self.nodes.iter().enumerate() {
            let label = if n.amount == 0 && n.vsize == 0 { String::new() } else { format!("{}s {}b", n.amount, n.vsize) };
            s += &format!("  {i} [label=\"{label}\"];\n");
        }
        for (ci, es) in self.edge_sets.iter().enumerate() {
            let (color, unit) = if ci == 0 { ("blue", "s") } else { ("red", "b") };
            s += &format!("  {{\n    edge [color={color}, fontcolor={color}];\n");
            let mut edges = es.edges.clone();
            edges.sort_by(|a, b| b.value.cmp(&a.value).then(a.from.cmp(&b.from)).then(a.to.cmp(&b.to)));
            for e in edges {
                s += &format!("    {} -> {} [label=\"{}{unit}\"{}];\n", e.from, e.to, e.value, if e.value == 0 { ", style=dashed" } else { "" });
            }
            s += "  }\n";
        }
        s + "}\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_valid(g: &DependencyGraph) {
        for (ci, es) in g.edge_sets.iter().enumerate() {
            let ct = if ci == 0 { CredentialType::Amount } else { CredentialType::Vsize };
            for v in 0..g.nodes.len() {
                assert_eq!(es.remaining_in_degree(&g.nodes, v), 0, "{:?} node {v} in-degree not maxed\n{}", ct, g.as_graphviz());
                assert!(es.balance(&g.nodes, v) >= 0, "{:?} node {v} negative balance\n{}", ct, g.as_graphviz());
                if g.nodes[v].kind == NodeKind::Output {
                    assert_eq!(es.balance(&g.nodes, v), 0, "{:?} output {v} not discharged", ct);
                }
                assert!(es.in_degree(v) <= g.nodes[v].max_in_degree);
                assert!(es.out_degree(v) <= g.nodes[v].max_out_degree);
            }
        }
    }

    #[test]
    fn simple_one_in_two_out() {
        let g = DependencyGraph::resolve(&[(10_000, 255)], &[(4_000, 31), (5_000, 43)], 2_100_000_000, 255).unwrap();
        check_valid(&g);
    }

    #[test]
    fn many_inputs_many_outputs() {
        let inputs: Vec<(i64, i64)> = (1..=7).map(|i| (100_000 * i, 255 - 69)).collect();
        let outputs: Vec<(i64, i64)> = vec![(1_000_000, 31), (500_000, 43), (300_000, 31), (200_000, 43), (100_000, 31), (50_000, 31), (40_000, 43), (30_000, 31)];
        let g = DependencyGraph::resolve(&inputs, &outputs, 2_100_000_000, 255).unwrap();
        check_valid(&g);
        assert!(!g.reissuances().is_empty());
    }

    #[test]
    fn exact_match() {
        let g = DependencyGraph::resolve(&[(1000, 100), (2000, 100)], &[(3000, 50)], 2_100_000_000, 255).unwrap();
        check_valid(&g);
    }
}
