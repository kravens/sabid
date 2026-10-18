//! Port of Wasabi's `RoundStateUpdater` / `RoundStateProvider`: polls `/status` with checkpoints,
//! merges incremental events, refuses rounds whose id or input proofs do not check out, and
//! lets round participants await a round phase or predicate.

use crate::ownership::{commitment_data, OwnershipProof};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use wasabi_proto::{CoinjoinState, CoordinatorClient, Phase, RoundEvent, RoundState, RoundStateCheckpoint, RoundStateRequest};

pub const QUERY_FREQUENCY: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum AwaitError {
    #[error("Round {0} is not running anymore.")]
    RoundNotFound(String),
    #[error("round {round_id}: expected phase {expected:?} but it is in {actual:?}")]
    UnexpectedPhase { round_id: String, expected: Phase, actual: Phase, state: Box<RoundState> },
    #[error("timed out waiting for a round")]
    Timeout,
    #[error("round state updater stopped")]
    Stopped,
}

pub struct RoundStateUpdater {
    client: CoordinatorClient,
    rounds: Mutex<Vec<RoundState>>,
    changed: Notify,
    waiters: AtomicUsize,
    updates: AtomicUsize,
    pub last_error: Mutex<Option<String>>,
}

impl RoundStateUpdater {
    pub fn new(client: CoordinatorClient) -> Arc<Self> {
        Arc::new(Self { client, rounds: Mutex::new(Vec::new()), changed: Notify::new(), waiters: AtomicUsize::new(0), updates: AtomicUsize::new(0), last_error: Mutex::new(None) })
    }

    pub async fn rounds(&self) -> Vec<RoundState> {
        self.rounds.lock().await.clone()
    }

    pub async fn get(&self, round_id: &str) -> Option<RoundState> {
        self.rounds.lock().await.iter().find(|r| r.id == round_id).cloned()
    }

    /// `UpdateRoundsStateAsync`
    pub async fn update_once(&self) -> anyhow::Result<()> {
        let checkpoints: Vec<RoundStateCheckpoint> = self
            .rounds
            .lock()
            .await
            .iter()
            .map(|r| RoundStateCheckpoint { round_id: r.id.clone(), state_id: r.coinjoin_state.events().len() as i32 })
            .collect();
        let resp = tokio::time::timeout(Duration::from_secs(30), self.client.get_status(&RoundStateRequest { round_checkpoints: checkpoints })).await??;
        let mut rounds = self.rounds.lock().await;
        let mut updated: Vec<RoundState> = Vec::new();
        let mut fresh: Vec<RoundState> = Vec::new();
        for mut rs in resp.round_states {
            if rs.coinjoin_state.parameters().is_none() {
                tracing::warn!("round {} has no RoundCreated event; ignoring it", &rs.id[..rs.id.len().min(8)]);
                continue;
            }
            if let Some(old) = rounds.iter().find(|r| r.id == rs.id) {
                verify_input_proofs(&rs, &old.parameters().coordination_identifier)?;
                let mut events = old.coinjoin_state.events().to_vec();
                events.extend(rs.coinjoin_state.events().iter().cloned());
                rs.coinjoin_state = match rs.coinjoin_state {
                    CoinjoinState::ConstructionState { .. } => CoinjoinState::ConstructionState { events },
                    CoinjoinState::SigningState { witnesses, is_fully_signed, .. } => CoinjoinState::SigningState { events, witnesses, is_fully_signed },
                };
                updated.push(rs);
            } else {
                if !rs.is_round_id_matching() {
                    anyhow::bail!("Coordinator is cheating by creating rounds that do not match the parameters.");
                }
                verify_input_proofs(&rs, &rs.parameters().coordination_identifier)?;
                fresh.push(rs);
            }
        }
        // Keep the coordinator's order: new rounds first, then the updated ones (round preference).
        fresh.extend(updated);
        *rounds = fresh;
        drop(rounds);
        self.updates.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Polls while someone is waiting (Wasabi only queries when awaiters exist).
    pub async fn run(self: Arc<Self>, stop: Arc<Notify>) {
        loop {
            if self.waiters.load(Ordering::SeqCst) > 0 {
                match self.update_once().await {
                    Ok(()) => *self.last_error.lock().await = None,
                    Err(e) => {
                        tracing::warn!("round status: {e}");
                        *self.last_error.lock().await = Some(e.to_string());
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(QUERY_FREQUENCY) => {}
                    _ = stop.notified() => return,
                }
            } else {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = stop.notified() => return,
                }
            }
        }
    }

    /// `CreateRoundAwaiterAsync(roundId, phase)` / `(predicate)`: resolves on the first update
    /// where the round is in `phase` (and satisfies `pred`); fails when the round is gone or past it.
    pub async fn wait_for(&self, round_id: Option<&str>, phase: Option<Phase>, pred: impl Fn(&RoundState) -> bool, timeout: Duration) -> Result<RoundState, AwaitError> {
        self.waiters.fetch_add(1, Ordering::SeqCst);
        let r = tokio::time::timeout(timeout, self.wait_inner(round_id, phase, pred)).await.unwrap_or(Err(AwaitError::Timeout));
        self.waiters.fetch_sub(1, Ordering::SeqCst);
        r
    }

    async fn wait_inner(&self, round_id: Option<&str>, phase: Option<Phase>, pred: impl Fn(&RoundState) -> bool) -> Result<RoundState, AwaitError> {
        let mut seen_update = self.updates.load(Ordering::SeqCst);
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let current = self.updates.load(Ordering::SeqCst);
            if current != seen_update || seen_update > 0 {
                seen_update = current;
                let rounds = self.rounds.lock().await;
                if let Some(id) = round_id {
                    if !rounds.iter().any(|r| r.id == id) {
                        return Err(AwaitError::RoundNotFound(id.to_string()));
                    }
                }
                for rs in rounds.iter() {
                    if let Some(id) = round_id {
                        if rs.id != id {
                            continue;
                        }
                    }
                    if let Some(expected) = phase {
                        let actual = rs.phase().unwrap_or(Phase::Ended);
                        if (actual as i32) > (expected as i32) {
                            return Err(AwaitError::UnexpectedPhase { round_id: round_id.unwrap_or("").to_string(), expected, actual, state: Box::new(rs.clone()) });
                        }
                        if actual != expected {
                            continue;
                        }
                    }
                    if pred(rs) {
                        return Ok(rs.clone());
                    }
                }
            }
            notified.await;
        }
    }
}

/// `MultipartyTransactionState.VerifyOwnershipProofs`: every newly added input must carry a proof
/// bound to this round and coordinator, or the coordinator is replaying inputs across rounds.
fn verify_input_proofs(rs: &RoundState, coordinator_identifier: &str) -> anyhow::Result<()> {
    let commitment = commitment_data(coordinator_identifier, &rs.id)?;
    for e in rs.coinjoin_state.events() {
        if let RoundEvent::InputAdded { coin, ownership_proof } = e {
            let proof = OwnershipProof::from_bytes(&hex::decode(ownership_proof)?)?;
            let spk = wasabi_proto::script::script_from_asm(&coin.tx_out.script_pub_key)?;
            if !proof.verify(&spk, &commitment, true) {
                anyhow::bail!("The coordinator is cheating by adding inputs to rounds that were created to be registered in different rounds.");
            }
        }
    }
    Ok(())
}
