//! Port of Wasabi's `CoinJoinClient` + `DependencyGraphTaskScheduler`: one wallet's participation
//! in a round (and its blame rounds), from round selection to posting signatures.

use crate::arena::{AliceClient, ArenaClient, ArenaError, BobClient};
use crate::decomposer::{AmountDecomposer, Output};
use crate::depgraph::{CredentialType, DependencyGraph};
use crate::destinations::DestinationProvider;
use crate::keychain::{KeyChain, UnsignedCoinJoin};
use crate::round_state::{AwaitError, RoundStateUpdater, QUERY_FREQUENCY};
use crate::selector::{min_reasonable_output_amount, CjCoin, CoinJoinCoinSelector, UtxoSelectionParameters};
use crate::units::{effective_cost, script_input_vsize, script_output_vsize, FeeRate, ScriptType};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use futures_util::future::{join_all, try_join_all};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex};
use tokio_util::sync::CancellationToken;
use wabisabi::Credential;
use wasabi_proto::{ApiError, CoordinatorClient, EndRoundState, Phase, RoundState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinjoinError {
    NoCoinsEligibleToMix,
    AutoConjoinDisabled,
    UserInSendWorkflow,
    NotEnoughUnprivateBalance,
    AllCoinsPrivate,
    UserWasntInRound,
    NoConfirmedCoinsEligibleToMix,
    CoinsRejected,
    OnlyImmatureCoinsAvailable,
    OnlyExcludedCoinsAvailable,
    MiningFeeRateTooHigh,
    MinInputCountTooLow,
    CoordinatorLiedAboutInputs,
    NotEnoughConfirmedUnprivateBalance,
    DeviceAuthorizationFailed,
    DeviceRefusedToSign,
    DeviceNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum CjError {
    #[error("{error:?}: {msg}")]
    Client { error: CoinjoinError, msg: String },
    #[error("cancelled")]
    Cancelled,
    #[error(transparent)]
    Await(#[from] AwaitError),
    #[error(transparent)]
    Arena(#[from] ArenaError),
    #[error("round ending unknown: {msg}")]
    UnknownRoundEnding { coins: Vec<CjCoin>, output_scripts: Vec<ScriptBuf>, msg: String },
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for CjError {
    fn from(e: anyhow::Error) -> Self {
        CjError::Other(e.to_string())
    }
}

impl CjError {
    fn client(error: CoinjoinError, msg: impl ToString) -> Self {
        CjError::Client { error, msg: msg.to_string() }
    }
    fn api_code(&self) -> Option<&str> {
        match self {
            CjError::Arena(ArenaError::Api(e)) => e.error_code(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoinJoinConfig {
    pub coordinator_identifier: String,
    pub max_mining_fee_rate_sat_vb: f64,
    pub absolute_min_input_count: i32,
    pub allow_solo_coinjoining: bool,
}

#[derive(Debug, Clone)]
pub enum Progress {
    WaitingForRound,
    EnteringInputRegistration { round_id: String, end: chrono::DateTime<chrono::FixedOffset> },
    EnteringCriticalPhase,
    EnteringConnectionConfirmation { round_id: String },
    EnteringOutputRegistration { round_id: String },
    EnteringSigning { round_id: String },
    TransactionSigned { txid: Txid, inputs: Vec<OutPoint> },
    LeavingCriticalPhase,
    RoundEnded { round_id: String, end_state: EndRoundState },
    CoinBanned { outpoint: OutPoint, until: chrono::DateTime<chrono::FixedOffset> },
    WaitingForBlameRound,
}

#[derive(Debug, Clone)]
pub struct CoinjoinCosts {
    pub mining_fee: i64,
    pub wasted_dust: i64,
}

#[derive(Debug, Clone)]
pub struct ForeignCoin {
    pub outpoint: OutPoint,
    pub script: ScriptBuf,
    pub amount: i64,
}

pub enum CoinJoinResult {
    Success { coins: Vec<CjCoin>, output_scripts: Vec<ScriptBuf>, unsigned_tx: Transaction, costs: CoinjoinCosts },
    Failed,
}

enum RoundOutcome {
    Success { coins: Vec<CjCoin>, output_scripts: Vec<ScriptBuf>, unsigned_tx: Transaction, costs: CoinjoinCosts },
    Failed,
    Disrupted { my_signed: Vec<CjCoin>, all_round_coins: Vec<ForeignCoin>, max_suggested_amount: i64 },
}

#[derive(Clone)]
enum Restrictions {
    Unrestricted,
    Blame { previous_round_signed_coins: Vec<ForeignCoin>, suggested_amount: i64 },
}

pub type ClientFactory = Arc<dyn Fn(&str) -> Result<CoordinatorClient, ApiError> + Send + Sync>;
pub type InputVerifier = Arc<dyn Fn(Vec<ForeignCoin>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

pub struct CoinJoinClient {
    pub make_client: ClientFactory,
    pub key_chain: Arc<dyn KeyChain>,
    pub destinations: Arc<dyn DestinationProvider>,
    pub updater: Arc<RoundStateUpdater>,
    pub selector: CoinJoinCoinSelector,
    pub config: CoinJoinConfig,
    pub liquidity_clue: Arc<Mutex<Option<i64>>>,
    pub input_verifier: Option<InputVerifier>,
    pub do_not_register_in_last_minute: Duration,
    pub min_anon_score_for_payments: i32,
    /// Payments to embed in rounds (`PaymentAwareOutputProvider`); none for device wallets.
    pub payments: Option<Arc<crate::payments::PaymentBatch>>,
    pub progress: mpsc::UnboundedSender<Progress>,
    pub coins_in_critical_phase: Mutex<Vec<CjCoin>>,
    pub coins_banned: Mutex<HashSet<OutPoint>>,
}

const MINIMUM_OUTPUT_AMOUNT_SANITY: i64 = 10_000;
const EXTRA_PHASE_TIMEOUT_MARGIN: Duration = Duration::from_secs(120);
const EXTRA_ROUND_TIMEOUT_MARGIN: Duration = Duration::from_secs(600);
const MAXIMUM_REQUEST_DELAY: Duration = Duration::from_secs(10);
const MAX_WAITING_TIME_FOR_ROUND: Duration = Duration::from_secs(600);

/// `TimeSpan.SamplePoisson`: `n` instants in `[start, start + min(end - start, max_delay))`.
pub fn scheduled_instants(n: usize, start: Instant, end: Instant, max_delay: Duration) -> Vec<Instant> {
    let mut remaining = end.saturating_duration_since(start);
    if remaining > max_delay {
        remaining = max_delay;
    }
    let ms = remaining.as_millis() as u64;
    let mut rng = rand::thread_rng();
    let mut delays: Vec<Duration> = (0..n).map(|_| if ms == 0 { Duration::ZERO } else { Duration::from_millis((0.8 * rng.gen_range(0..ms) as f64) as u64) }).collect();
    delays.sort();
    delays.into_iter().map(|d| start + d).collect()
}

fn to_datetime(end: chrono::DateTime<chrono::FixedOffset>) -> Instant {
    let remaining = end.signed_duration_since(chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO);
    Instant::now().checked_add(remaining).unwrap_or_else(|| Instant::now() + Duration::from_secs(365 * 86400))
}

fn round_coins(round: &RoundState) -> Vec<ForeignCoin> {
    round
        .coinjoin_state
        .inputs()
        .filter_map(|(c, _)| {
            Some(ForeignCoin { outpoint: wasabi_proto::script::outpoint_from_hex(&c.outpoint)?, script: wasabi_proto::script::script_from_asm(&c.tx_out.script_pub_key).ok()?, amount: c.tx_out.value })
        })
        .collect()
}

impl CoinJoinClient {
    fn emit(&self, p: Progress) {
        let _ = self.progress.send(p);
    }

    fn log(round: &RoundState, msg: &str) -> String {
        format!("Round ({}): {msg}", &round.id[..8])
    }

    async fn wait_for_round(&self, exclude: &str, cancel: &CancellationToken) -> Result<RoundState, CjError> {
        self.emit(Progress::WaitingForRound);
        let last_minute = self.do_not_register_in_last_minute;
        let fut = self.updater.wait_for(
            None,
            None,
            |r| {
                r.input_registration_end().signed_duration_since(chrono::Utc::now()).to_std().map(|d| d > last_minute).unwrap_or(false)
                    && r.parameters().allowed_output_amounts.min < MINIMUM_OUTPUT_AMOUNT_SANITY
                    && r.phase() == Some(Phase::InputRegistration)
                    && !r.is_blame()
                    && r.id != exclude
            },
            MAX_WAITING_TIME_FOR_ROUND,
        );
        tokio::select! {
            r = fut => Ok(r?),
            _ = cancel.cancelled() => Err(CjError::Cancelled),
        }
    }

    async fn wait_for_blame_round(&self, blame_of: &str, cancel: &CancellationToken) -> Result<RoundState, CjError> {
        self.emit(Progress::WaitingForBlameRound);
        let fut = self.updater.wait_for(None, None, |r| r.blame_of.eq_ignore_ascii_case(blame_of), Duration::from_secs(300));
        let round = tokio::select! {
            r = fut => r?,
            _ = cancel.cancelled() => return Err(CjError::Cancelled),
        };
        let p = round.parameters();
        if round.phase() != Some(Phase::InputRegistration) {
            return Err(CjError::Other(format!("Blame Round ({}): Abandoning: the round is not in Input Registration but in '{:?}'.", round.id, round.phase())));
        }
        if p.allowed_output_amounts.min >= MINIMUM_OUTPUT_AMOUNT_SANITY {
            return Err(CjError::Other(format!("Blame Round ({}): Abandoning: the minimum output amount is too high.", round.id)));
        }
        if p.min_input_count_by_round < self.config.absolute_min_input_count {
            return Err(CjError::Other(format!("Blame Round ({}): Abandoning: the minimum input count was too low.", round.id)));
        }
        if let Some(floor) = self.key_chain.min_round_inputs() {
            if floor > p.min_input_count_by_round {
                return Err(CjError::Other(format!("Blame Round ({}): Abandoning: the round may close below the {floor} inputs the signing device requires.", round.id)));
            }
        }
        if p.fee_rate_sat_per_vb() > self.config.max_mining_fee_rate_sat_vb {
            return Err(CjError::Other(format!("Blame Round ({}): Abandoning: the mining fee rate for the round was {} sat/vb but maximum allowed is {}.", round.id, p.fee_rate_sat_per_vb(), self.config.max_mining_fee_rate_sat_vb)));
        }
        Ok(round)
    }

    /// `StartCoinJoinAsync`
    pub async fn start_coin_join(&self, candidates: impl Fn() -> Vec<CjCoin>, cancel: CancellationToken) -> Result<CoinJoinResult, CjError> {
        let signable = |coins: Vec<CjCoin>| -> Result<Vec<CjCoin>, CjError> {
            let n = coins.len();
            let s: Vec<CjCoin> = coins.into_iter().filter(|c| self.key_chain.can_sign(c.script_type)).collect();
            if s.is_empty() {
                return Err(CjError::client(CoinjoinError::NoCoinsEligibleToMix, "None of the wallet's coins can be signed by this device."));
            }
            if s.len() < n {
                tracing::info!("Leaving out {} coin(s) the signing device cannot sign.", n - s.len());
            }
            Ok(s)
        };
        let mut exclude = String::new();
        let mut my_coins: Vec<CjCoin>;
        let mut round: RoundState;
        loop {
            signable(candidates())?;
            round = self.wait_for_round(&exclude, &cancel).await?;
            let p = round.parameters().clone();
            if !round.is_blame() {
                if p.fee_rate_sat_per_vb() > self.config.max_mining_fee_rate_sat_vb {
                    let msg = format!("Mining fee rate was {} sat/vB but max allowed is {}.", p.fee_rate_sat_per_vb(), self.config.max_mining_fee_rate_sat_vb);
                    tracing::info!("{}", Self::log(&round, &msg));
                    return Err(CjError::client(CoinjoinError::MiningFeeRateTooHigh, msg));
                }
                if let Some(floor) = self.key_chain.min_round_inputs() {
                    if floor > p.min_input_count_by_round {
                        let msg = format!("This coordinator closes rounds with as few as {} inputs, but the signing device requires at least {floor}, so it could refuse to sign. Lower the minimum input count in the coinjoin settings, or use a coordinator that builds larger rounds.", p.min_input_count_by_round);
                        return Err(CjError::client(CoinjoinError::MinInputCountTooLow, msg));
                    }
                }
                if p.min_input_count_by_round < self.config.absolute_min_input_count {
                    let msg = format!("Min input count for the round was {} but min allowed is {}.", p.min_input_count_by_round, self.config.absolute_min_input_count);
                    tracing::info!("{}", Self::log(&round, &msg));
                    return Err(CjError::client(CoinjoinError::MinInputCountTooLow, msg));
                }
            }
            let coin_candidates = signable(candidates())?;
            let liquidity_clue = {
                let clue = self.liquidity_clue.lock().await;
                clue.unwrap_or(crate::selector::MAXIMUM_NUMBER_OF_BITCOINS_SATS).min(p.max_suggested_amount)
            };
            let supported = self.destinations.supported_script_types();
            let in_types: Vec<ScriptType> = p.allowed_input_types.iter().filter_map(|t| ScriptType::from_u8(*t)).collect();
            let out_types: Vec<ScriptType> = p.allowed_output_types.iter().filter_map(|t| ScriptType::from_u8(*t)).collect();
            let Some(params) = UtxoSelectionParameters::from_round(
                (p.allowed_input_amounts.min, p.allowed_input_amounts.max),
                (p.allowed_output_amounts.min, p.allowed_output_amounts.max),
                in_types.clone(),
                &out_types,
                FeeRate::from_fee_per_k(p.mining_fee_rate),
                &supported,
                &mut rand::thread_rng(),
            ) else {
                exclude = round.id.clone();
                tracing::info!("{}", Self::log(&round, "Skipping the round since it allows no output type or denomination this wallet can use."));
                continue;
            };
            my_coins = self.selector.select_coins_for_round(&coin_candidates, &params, liquidity_clue, &mut rand::thread_rng());
            if !in_types.contains(&ScriptType::P2WPKH) || !out_types.contains(&ScriptType::P2WPKH) {
                exclude = round.id.clone();
                tracing::info!("{}", Self::log(&round, "Skipping the round since it doesn't support P2WPKH inputs and outputs."));
                continue;
            }
            if my_coins.is_empty() {
                exclude = round.id.clone();
                tracing::info!("{}", Self::log(&round, "Skipping the round since none of the wallet's coins is suitable for it."));
                continue;
            }
            if p.max_suggested_amount != 0 && my_coins.iter().any(|c| c.amount > p.max_suggested_amount) {
                exclude = round.id.clone();
                tracing::info!("{}", Self::log(&round, &format!("Skipping the round for more optimal mixing. Max suggested amount is '{}' sat.", p.max_suggested_amount)));
                continue;
            }
            break;
        }
        let mut restrictions = Restrictions::Unrestricted;
        loop {
            let p = round.parameters();
            let round_timeout = round.input_registration_timeout.0 + p.connection_confirmation_timeout.0 + p.output_registration_timeout.0 + p.transaction_signing_timeout.0 + EXTRA_ROUND_TIMEOUT_MARGIN;
            let round_cancel = cancel.child_token();
            let timed = round_cancel.clone();
            let timer = tokio::spawn(async move {
                tokio::time::sleep(round_timeout).await;
                timed.cancel();
            });
            let result = self.start_round(my_coins.clone(), restrictions.clone(), round.clone(), round_cancel).await;
            timer.abort();
            match result? {
                RoundOutcome::Disrupted { my_signed, all_round_coins, max_suggested_amount } => {
                    my_coins = my_signed;
                    restrictions = Restrictions::Blame { previous_round_signed_coins: all_round_coins, suggested_amount: max_suggested_amount };
                    tracing::info!("{}", Self::log(&round, "Waiting for the blame round."));
                    round = self.wait_for_blame_round(&round.id, &cancel).await?;
                }
                RoundOutcome::Success { coins, output_scripts, unsigned_tx, costs } => return Ok(CoinJoinResult::Success { coins, output_scripts, unsigned_tx, costs }),
                RoundOutcome::Failed => return Ok(CoinJoinResult::Failed),
            }
        }
    }

    /// `StartRoundAsync`
    async fn start_round(&self, my_coins: Vec<CjCoin>, restrictions: Restrictions, round: RoundState, cancel: CancellationToken) -> Result<RoundOutcome, CjError> {
        let round_id = round.id.clone();
        let ended = CancellationToken::new();
        let updater = self.updater.clone();
        let ended_token = ended.clone();
        let rid = round_id.clone();
        let wait_round_ended = tokio::spawn(async move {
            let r = updater.wait_for(Some(&rid), Some(Phase::Ended), |_| true, Duration::from_secs(24 * 3600)).await;
            ended_token.cancel();
            r
        });
        let outcome: Result<RoundOutcome, CjError> = async {
            let cancel_or_ended = CancellationToken::new();
            {
                let c = cancel.clone();
                let e = ended.clone();
                let t = cancel_or_ended.clone();
                tokio::spawn(async move {
                    tokio::select! { _ = c.cancelled() => {}, _ = e.cancelled() => {} }
                    t.cancel();
                });
            }
            let proceed = self.proceed_with_round(&round, &my_coins, &restrictions, &cancel_or_ended).await;
            let (signed_alices, output_txouts, unsigned_tx) = match proceed {
                Ok(v) => v,
                Err(CjError::Cancelled) if ended.is_cancelled() => (vec![], vec![], None),
                Err(CjError::Await(AwaitError::UnexpectedPhase { actual: Phase::Ended, .. })) => (vec![], vec![], None),
                Err(e) if e.api_code() == Some("WrongPhase") && matches!(&e, CjError::Arena(ArenaError::Api(a)) if a.wrong_phase() == Some(Phase::Ended)) => (vec![], vec![], None),
                Err(e) => return Err(e),
            };
            let my_signed: Vec<CjCoin> = signed_alices.iter().map(|a| a.coin.clone()).collect();
            let output_scripts: Vec<ScriptBuf> = output_txouts.iter().map(|o| o.script_pubkey.clone()).collect();
            let final_state = match wait_round_ended.await {
                Ok(Ok(rs)) => rs,
                Ok(Err(e)) => return Err(CjError::UnknownRoundEnding { coins: my_signed, output_scripts, msg: e.to_string() }),
                Err(e) => return Err(CjError::UnknownRoundEnding { coins: my_signed, output_scripts, msg: e.to_string() }),
            };
            let end_state = final_state.end_round_state();
            let hash = unsigned_tx.as_ref().map(|t| t.compute_txid().to_string()).unwrap_or_else(|| "Not available".into());
            let msg = match end_state {
                EndRoundState::TransactionBroadcasted => format!("Broadcast. Coinjoin TxId: ({hash})"),
                EndRoundState::TransactionBroadcastFailed => format!("Failed to broadcast. Coinjoin TxId: ({hash})"),
                EndRoundState::AbortedWithError => "Round abnormally finished.".into(),
                EndRoundState::AbortedNotEnoughAlices => "Aborted. Not enough participants.".into(),
                EndRoundState::AbortedNotEnoughAlicesSigned => "Aborted. Not enough participants signed the coinjoin transaction.".into(),
                EndRoundState::NotAllAlicesSign => "Aborted. Some Alices didn't sign. Go to blame round.".into(),
                EndRoundState::AbortedNotAllAlicesConfirmed => "Aborted. Some Alices didn't confirm.".into(),
                EndRoundState::AbortedLoadBalancing => "Aborted. Load balancing registrations.".into(),
                EndRoundState::None => "Unknown.".into(),
            };
            tracing::info!("{}", Self::log(&final_state, &msg));
            self.emit(Progress::RoundEnded { round_id: round_id.clone(), end_state });
            if my_signed.is_empty() && end_state == EndRoundState::TransactionBroadcasted {
                return Err(CjError::client(CoinjoinError::UserWasntInRound, "No inputs participated in this round."));
            }
            if my_signed.is_empty() && end_state == EndRoundState::NotAllAlicesSign {
                return Ok(RoundOutcome::Failed);
            }
            Ok(match end_state {
                EndRoundState::TransactionBroadcasted => {
                    let fee_rate = FeeRate::from_fee_per_k(final_state.parameters().mining_fee_rate);
                    let costs = calculate_costs(&final_state, fee_rate, &my_signed, &output_txouts);
                    RoundOutcome::Success { coins: my_signed, output_scripts, unsigned_tx: unsigned_tx.expect("signed implies tx"), costs }
                }
                EndRoundState::NotAllAlicesSign => RoundOutcome::Disrupted { my_signed, all_round_coins: round_coins(&final_state), max_suggested_amount: final_state.parameters().max_suggested_amount },
                _ => RoundOutcome::Failed,
            })
        }
        .await;
        self.emit(Progress::LeavingCriticalPhase);
        if let Err(e) = &outcome {
            tracing::debug!("{}", Self::log(&round, &e.to_string()));
        }
        outcome
    }

    async fn proceed_with_round(&self, round: &RoundState, my_coins: &[CjCoin], restrictions: &Restrictions, cancel: &CancellationToken) -> Result<(Vec<AliceClient>, Vec<TxOut>, Option<Transaction>), CjError> {
        let result = async {
            let alices = self.register_and_confirm(my_coins, round, cancel).await?;
            if alices.is_empty() {
                let banned = self.coins_banned.lock().await;
                let any_banned = my_coins.iter().any(|c| banned.contains(&c.outpoint));
                let e = if any_banned { CoinjoinError::CoinsRejected } else { CoinjoinError::UserWasntInRound };
                return Err(CjError::client(e, format!("None of the {} inputs could be registered.", my_coins.len())));
            }
            tracing::info!("{}", Self::log(round, &format!("Successfully registered {} inputs.", alices.len())));
            *self.coins_in_critical_phase.lock().await = alices.iter().map(|a| a.coin.clone()).collect();
            let outputs = self.output_registration_phase(&round.id, &alices, restrictions, cancel).await?;
            let (unsigned, signed) = self.signing_phase(&round.id, alices, &outputs, cancel).await?;
            self.update_liquidity_clue(round.parameters().max_suggested_amount, &unsigned, &outputs).await;
            Ok((signed, outputs, Some(unsigned)))
        }
        .await;
        self.coins_in_critical_phase.lock().await.clear();
        result
    }

    /// `CreateRegisterAndConfirmCoinsAsync` / `ProceedWithInputRegAndConfirmAsync`
    async fn register_and_confirm(&self, coins: &[CjCoin], round: &RoundState, cancel: &CancellationToken) -> Result<Vec<AliceClient>, CjError> {
        let p = round.parameters();
        let inreg_end = round.input_registration_end();
        self.emit(Progress::EnteringInputRegistration { round_id: round.id.clone(), end: inreg_end });
        let remaining = inreg_end.signed_duration_since(chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO);
        let strict_inreg_deadline = Instant::now() + remaining;
        let inreg_deadline = Instant::now() + remaining + EXTRA_PHASE_TIMEOUT_MARGIN;
        let confirm_deadline = Instant::now() + remaining + p.connection_confirmation_timeout.0 + EXTRA_PHASE_TIMEOUT_MARGIN;
        let registrations_cancel = CancellationToken::new();
        let confirmations_cancel = CancellationToken::new();
        let entered_critical = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let last_unexpected_phase: Arc<Mutex<Option<AwaitError>>> = Arc::new(Mutex::new(None));
        let registration_deadline = to_datetime(inreg_end).checked_sub(Duration::from_secs(60)).unwrap_or_else(Instant::now);
        let dates = scheduled_instants(coins.len(), Instant::now(), registration_deadline, Duration::from_secs(365 * 24 * 3600));
        tracing::debug!("{}", Self::log(round, &format!("Inputs({}) registration started - it will end in: {:?}.", coins.len(), remaining)));

        let mut tasks = Vec::new();
        for (coin, date) in coins.iter().cloned().zip(dates) {
            let round = round.clone();
            let registrations_cancel = registrations_cancel.clone();
            let confirmations_cancel = confirmations_cancel.clone();
            let cancel = cancel.clone();
            let entered_critical = entered_critical.clone();
            let last_unexpected_phase = last_unexpected_phase.clone();
            tasks.push(async move {
                let delay = date.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.cancelled() => return Err(CjError::Cancelled),
                    _ = registrations_cancel.cancelled() => return Ok(None),
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(confirm_deadline)) => return Ok(None),
                }
                let r = self
                    .register_input(&round, coin.clone(), strict_inreg_deadline, inreg_deadline, confirm_deadline, &registrations_cancel, &confirmations_cancel, &cancel)
                    .await;
                match r {
                    Ok(alice) => {
                        if !entered_critical.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            self.emit(Progress::EnteringCriticalPhase);
                        }
                        Ok(Some(alice))
                    }
                    Err(CjError::Cancelled) if cancel.is_cancelled() => Err(CjError::Cancelled),
                    Err(CjError::Cancelled) => Ok(None),
                    Err(CjError::Await(e @ AwaitError::UnexpectedPhase { .. })) => {
                        *last_unexpected_phase.lock().await = Some(e);
                        Ok(None)
                    }
                    Err(e) => {
                        match e.api_code() {
                            Some("RoundNotFound") => {
                                tracing::info!("{}", Self::log(&round, &format!("{} arrived too late because the round doesn't exist anymore. Aborting input registrations.", coin.outpoint)));
                                registrations_cancel.cancel();
                                confirmations_cancel.cancel();
                            }
                            Some("WrongPhase") => {
                                let phase = match &e {
                                    CjError::Arena(ArenaError::Api(a)) => a.wrong_phase(),
                                    _ => None,
                                };
                                tracing::info!("{}", Self::log(&round, &format!("{} arrived too late. Aborting input registrations: 'WrongPhase'.", coin.outpoint)));
                                if phase != Some(Phase::InputRegistration) {
                                    registrations_cancel.cancel();
                                    if phase != Some(Phase::ConnectionConfirmation) {
                                        confirmations_cancel.cancel();
                                    }
                                }
                                if phase == Some(Phase::Ended) {
                                    return Err(e);
                                }
                            }
                            Some("AliceAlreadyRegistered") => tracing::info!("{}", Self::log(&round, &format!("{} was already registered.", coin.outpoint))),
                            Some("AliceAlreadyConfirmedConnection") => tracing::info!("{}", Self::log(&round, &format!("{} already confirmed connection.", coin.outpoint))),
                            Some("InputSpent") => tracing::warn!("{}", Self::log(&round, &format!("{} is spent according to the coordinator. The wallet is not fully synchronized, corrupted or the coordinator lies.", coin.outpoint))),
                            Some("InputBanned") | Some("InputLongBanned") => {
                                let until = match &e {
                                    CjError::Arena(ArenaError::Api(a)) => a.banned_until(),
                                    _ => None,
                                }
                                .unwrap_or_else(|| (chrono::Utc::now() + chrono::Duration::days(1)).fixed_offset());
                                self.coins_banned.lock().await.insert(coin.outpoint);
                                self.emit(Progress::CoinBanned { outpoint: coin.outpoint, until });
                                tracing::info!("{}", Self::log(&round, &format!("{} is banned until {until}.", coin.outpoint)));
                            }
                            Some("InputNotWhitelisted") => tracing::warn!("{}", Self::log(&round, &format!("{} cannot be registered in the blame round.", coin.outpoint))),
                            Some(code) => tracing::info!("{}", Self::log(&round, &format!("{} cannot be registered: '{code}'.", coin.outpoint))),
                            None => tracing::warn!("{}", Self::log(&round, &e.to_string())),
                        }
                        Ok(None)
                    }
                }
            });
        }
        let results = join_all(tasks).await;
        let mut alices = Vec::new();
        for r in results {
            match r {
                Ok(Some(a)) => alices.push(a),
                Ok(None) => {}
                Err(e) => return Err(e),
            }
        }
        if alices.is_empty() {
            if let Some(e) = last_unexpected_phase.lock().await.take() {
                return Err(CjError::Await(e));
            }
        } else {
            self.emit(Progress::EnteringConnectionConfirmation { round_id: round.id.clone() });
        }
        Ok(alices)
    }

    /// `AliceClient.CreateRegisterAndConfirmInputAsync`
    #[allow(clippy::too_many_arguments)]
    async fn register_input(
        &self,
        round: &RoundState,
        coin: CjCoin,
        strict_inreg_deadline: Instant,
        inreg_deadline: Instant,
        confirm_deadline: Instant,
        registrations_cancel: &CancellationToken,
        confirmations_cancel: &CancellationToken,
        cancel: &CancellationToken,
    ) -> Result<AliceClient, CjError> {
        let http = (self.make_client)(&format!("alice-{}", coin.outpoint)).map_err(ArenaError::from)?;
        let arena = ArenaClient::new(round, &self.config.coordinator_identifier, http)?;
        let register = AliceClient::register(round, arena, coin.clone(), &self.key_chain);
        let mut alice = tokio::select! {
            r = register => r?,
            _ = cancel.cancelled() => return Err(CjError::Cancelled),
            _ = registrations_cancel.cancelled() => return Err(CjError::Cancelled),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(inreg_deadline)) => return Err(CjError::Cancelled),
        };
        let confirm = async {
            loop {
                let _ = self.updater.wait_for(Some(&alice.round_id), Some(Phase::ConnectionConfirmation), |_| true, alice.confirmation_timeout).await;
                match alice.try_confirm().await {
                    Ok(true) => {
                        tracing::info!("round {}: connection confirmed for {}", &alice.round_id[..8], alice.coin.outpoint);
                        return Ok(());
                    }
                    Ok(false) => tokio::time::sleep(Duration::from_secs(1)).await,
                    Err(e) => return Err(CjError::from(e)),
                }
            }
        };
        let confirmed: Result<(), CjError> = tokio::select! {
            r = confirm => r,
            _ = cancel.cancelled() => Err(CjError::Cancelled),
            _ = confirmations_cancel.cancelled() => Err(CjError::Cancelled),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(confirm_deadline)) => Err(CjError::Cancelled),
        };
        match confirmed {
            Ok(()) => Ok(alice),
            Err(e) => {
                let no_unregister = matches!(e.api_code(), Some("RoundNotFound") | Some("WrongPhase") | Some("AliceAlreadyRegistered") | Some("AliceAlreadyConfirmedConnection"))
                    || matches!(e, CjError::Await(AwaitError::UnexpectedPhase { .. }));
                if !no_unregister {
                    let removed_by_backend = alice.last_successful_confirmation + round.parameters().connection_confirmation_timeout.0;
                    if removed_by_backend > strict_inreg_deadline && Instant::now() < strict_inreg_deadline {
                        alice.try_unregister().await;
                    }
                }
                Err(e)
            }
        }
    }

    fn create_bob(&self, round: &RoundState) -> Result<BobClient, CjError> {
        let identity: String = (0..20).map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>())).collect();
        let http = (self.make_client)(&format!("bob-{identity}")).map_err(ArenaError::from)?;
        Ok(BobClient { round_id: round.id.clone(), arena: ArenaClient::new(round, &self.config.coordinator_identifier, http)? })
    }

    /// `ProceedWithOutputRegistrationPhaseAsync`
    async fn output_registration_phase(&self, round_id: &str, alices: &[AliceClient], restrictions: &Restrictions, cancel: &CancellationToken) -> Result<Vec<TxOut>, CjError> {
        let round = tokio::select! {
            r = self.updater.wait_for(Some(round_id), Some(Phase::OutputRegistration), |_| true, Duration::from_secs(24 * 3600)) => r?,
            _ = cancel.cancelled() => return Err(CjError::Cancelled),
        };
        let p = round.parameters().clone();
        let fee_rate = FeeRate::from_fee_per_k(p.mining_fee_rate);
        let remaining = p.output_registration_timeout.0.saturating_sub(QUERY_FREQUENCY);
        let now = Instant::now();
        if let Restrictions::Blame { previous_round_signed_coins, suggested_amount } = restrictions {
            if *suggested_amount != p.max_suggested_amount {
                tracing::warn!("{}", Self::log(&round, &format!("Suggested amount is {}. Value {suggested_amount} was expected. Is coordinator cheating?", p.max_suggested_amount)));
                return Err(CjError::Other(format!("Round ({}) uses invalid suggested amount.", round.id)));
            }
            for c in round_coins(&round) {
                if !previous_round_signed_coins.iter().any(|w| w.outpoint == c.outpoint) {
                    tracing::warn!("{}", Self::log(&round, &format!("Coin '{}' is not whitelisted for this round. Is coordinator cheating?", c.outpoint)));
                    return Err(CjError::Other(format!("Round ({}) contains coin '{}' that is not allowed.", round.id, c.outpoint)));
                }
            }
        }
        let outreg_end = now + remaining.mul_f64(0.8);
        let ready_to_sign_end = outreg_end + remaining.mul_f64(0.2);
        self.emit(Progress::EnteringOutputRegistration { round_id: round.id.clone() });
        let phase_deadline = now + remaining + EXTRA_PHASE_TIMEOUT_MARGIN;
        let phase_cancel = cancel.child_token();
        {
            let t = phase_cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(phase_deadline)).await;
                t.cancel();
            });
        }
        let registered: Vec<OutPoint> = alices.iter().map(|a| a.coin.outpoint).collect();
        let available_vsizes: Vec<i64> = alices.iter().map(|a| a.issued_vsize.iter().map(|c| c.value()).sum()).collect();
        let all_coins = round_coins(&round);
        let (ours, theirs): (Vec<ForeignCoin>, Vec<ForeignCoin>) = all_coins.into_iter().partition(|c| registered.contains(&c.outpoint));
        let registered_effective: Vec<i64> = alices.iter().map(|a| a.effective_value()).collect();
        let their_effective: Vec<i64> = theirs.iter().map(|c| c.amount - fee_rate.get_fee(script_input_vsize(&c.script))).collect();
        for a in alices {
            if !ours.iter().any(|o| o.script == a.coin.script && o.amount == a.coin.amount) {
                return Err(CjError::client(CoinjoinError::CoordinatorLiedAboutInputs, "Coordinator lied about registered inputs. It probably tries to be malicious."));
            }
        }
        if let Some(v) = &self.input_verifier {
            v(theirs.clone()).await.map_err(|m| CjError::client(CoinjoinError::CoordinatorLiedAboutInputs, m))?;
        }
        let outputs = self.get_outputs(&round.id, &p, &registered_effective, &their_effective, available_vsizes.iter().sum())?;
        let inputs: Vec<(i64, i64)> = alices.iter().zip(&available_vsizes).map(|(a, v)| (a.effective_value(), *v)).collect();
        let out_values: Vec<(i64, i64)> = outputs.iter().map(|o| (effective_cost(o.value.to_sat() as i64, &o.script_pubkey, fee_rate), script_output_vsize(&o.script_pubkey))).collect();
        if inputs.iter().any(|(a, _)| *a <= 0) {
            return Err(CjError::Other("Not enough funds to pay for the fees.".into()));
        }
        let graph = DependencyGraph::resolve(&inputs, &out_values, p.max_amount_credential_value, p.max_vsize_credential_value()).map_err(|e| CjError::Other(e.to_string()))?;
        let result: Result<(), CjError> = async {
            tracing::info!("{}", Self::log(&round, "Starting reissuances."));
            let sched = Scheduler::new(&graph);
            sched.run_reissuances(self, &round, alices, &phase_cancel).await?;
            tracing::debug!("{}", Self::log(&round, &format!("Output registration started - it will end in: {:?}.", outreg_end.saturating_duration_since(Instant::now()))));
            let dates = scheduled_instants(outputs.len(), Instant::now(), outreg_end, MAXIMUM_REQUEST_DELAY);
            let errors = sched.run_output_registrations(self, &round, &outputs, dates, &phase_cancel).await?;
            if errors.is_empty() {
                tracing::info!("{}", Self::log(&round, &format!("Outputs({}) were registered.", outputs.len())));
            }
            for (script, code) in errors {
                if code.as_deref() == Some("AlreadyRegisteredScript") {
                    self.destinations.set_used(&[script.clone()]);
                    tracing::info!("{}", Self::log(&round, &format!("Script ({script}) was already registered. Continuing...")));
                } else {
                    tracing::info!("{}", Self::log(&round, &format!("Script ({script}) registration failed by unknown reasons. Continuing...")));
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            if cancel.is_cancelled() {
                return Err(CjError::Cancelled);
            }
            tracing::info!("{}", Self::log(&round, &format!("Failed to register outputs with message '{e}'. Ignoring...")));
        }
        tracing::debug!("{}", Self::log(&round, "ReadyToSign phase started."));
        self.ready_to_sign(alices, ready_to_sign_end, &phase_cancel).await;
        tracing::debug!("{}", Self::log(&round, &format!("Alices({}) are ready to sign.", alices.len())));
        Ok(outputs)
    }

    /// `PaymentAwareOutputProvider.GetOutputs`: the best set of pending payments first, then the
    /// remaining value decomposed as usual.
    fn get_outputs(&self, round_id: &str, p: &wasabi_proto::RoundParameters, registered_effective: &[i64], their_effective: &[i64], available_vsize: i64) -> Result<Vec<TxOut>, CjError> {
        let fee_rate = FeeRate::from_fee_per_k(p.mining_fee_rate);
        let supported = self.destinations.supported_script_types();
        let out_types: Vec<ScriptType> = p.allowed_output_types.iter().filter_map(|t| ScriptType::from_u8(*t)).collect();
        let min_reasonable = min_reasonable_output_amount(&out_types, &supported, fee_rate, p.allowed_output_amounts.min);
        let mut rng = rand::thread_rng();
        let mut outs = Vec::new();
        let mut available_vsize = available_vsize;
        let mut to_decompose: Vec<i64> = registered_effective.to_vec();
        let mut paying = false;
        if let Some(batch) = &self.payments {
            let set = batch.best_set(to_decompose.iter().sum(), available_vsize, &out_types, p.allowed_output_amounts.min, p.allowed_output_amounts.max, fee_rate);
            if !set.is_empty() {
                let total: i64 = set.iter().map(|pm| effective_cost(pm.amount, &pm.script, fee_rate)).sum();
                available_vsize -= set.iter().map(|pm| script_output_vsize(&pm.script)).sum::<i64>();
                for pm in &set {
                    tracing::info!("round {}: paying {} sat to {} inside the coinjoin (payment {})", &round_id[..round_id.len().min(8)], pm.amount, pm.script, pm.id);
                    outs.push(TxOut { value: Amount::from_sat(pm.amount as u64), script_pubkey: pm.script.clone() });
                }
                batch.move_in_progress(&set.iter().map(|pm| pm.id.clone()).collect::<Vec<_>>(), round_id);
                // Take the largest registered values that cover the payments out of the decomposer's
                // view; what they overshoot by comes back as one virtual value.
                let remaining_amount = to_decompose.iter().sum::<i64>() - total;
                to_decompose.sort_by(|a, b| b.cmp(a));
                let mut acc = 0;
                let mut used = 0;
                for v in &to_decompose {
                    if acc > total {
                        break;
                    }
                    acc += v;
                    used += 1;
                }
                let mut rest: Vec<i64> = to_decompose[used..].to_vec();
                let overshoot = remaining_amount - rest.iter().sum::<i64>();
                if overshoot > 0 {
                    rest.push(overshoot);
                }
                to_decompose = rest;
                paying = true;
            }
        }
        if to_decompose.iter().sum::<i64>() <= 0 {
            return Ok(outs);
        }
        let decomposer = AmountDecomposer::new(fee_rate, min_reasonable, p.allowed_output_amounts.max, available_vsize, supported.clone(), &mut rng);
        let mut all: Vec<i64> = their_effective.to_vec();
        all.extend_from_slice(registered_effective);
        let values: Vec<Output> = decomposer.decompose(to_decompose.iter().sum(), &all, paying, &mut rng)?;
        let taproot_count = values.iter().filter(|o| o.script_type == ScriptType::Taproot).count();
        let segwit_count = values.iter().filter(|o| o.script_type == ScriptType::P2WPKH).count();
        let mut taproot = self.destinations.next_destinations(taproot_count, true);
        let mut segwit = self.destinations.next_destinations(segwit_count, false);
        for o in values {
            let script = if o.script_type == ScriptType::Taproot { taproot.pop() } else { segwit.pop() }.ok_or_else(|| CjError::Other("not enough destinations".into()))?;
            outs.push(TxOut { value: Amount::from_sat(o.amount as u64), script_pubkey: script });
        }
        Ok(outs)
    }

    async fn ready_to_sign(&self, alices: &[AliceClient], end: Instant, cancel: &CancellationToken) {
        let dates = scheduled_instants(alices.len(), Instant::now(), end, MAXIMUM_REQUEST_DELAY);
        let tasks = alices.iter().zip(dates).map(|(a, d)| async move {
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(d)) => {}
                _ = cancel.cancelled() => return,
            }
            if let Err(e) = a.arena.ready_to_sign(&a.round_id, &a.alice_id).await {
                tracing::info!("round {}: failed to register signal ready to sign with message {e}. Ignoring...", &a.round_id[..8]);
            }
        });
        join_all(tasks).await;
    }

    /// `ProceedWithSigningStateAsync`
    async fn signing_phase(&self, round_id: &str, alices: Vec<AliceClient>, outputs: &[TxOut], cancel: &CancellationToken) -> Result<(Transaction, Vec<AliceClient>), CjError> {
        let round = tokio::select! {
            r = self.updater.wait_for(Some(round_id), Some(Phase::TransactionSigning), |_| true, Duration::from_secs(24 * 3600)) => r?,
            _ = cancel.cancelled() => return Err(CjError::Cancelled),
        };
        let p = round.parameters().clone();
        let remaining = p.transaction_signing_timeout.0.saturating_sub(Duration::from_secs(10));
        let signing_end = Instant::now() + remaining;
        self.emit(Progress::EnteringSigning { round_id: round.id.clone() });
        let phase_cancel = cancel.child_token();
        {
            let t = phase_cancel.clone();
            let deadline = Instant::now() + remaining + EXTRA_PHASE_TIMEOUT_MARGIN;
            tokio::spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                t.cancel();
            });
        }
        let unsigned = build_unsigned_coinjoin(&round)?;
        let actual_input_count = unsigned.tx.input.len();
        let solo = actual_input_count == alices.len();
        let forbidden_solo = solo && !self.config.allow_solo_coinjoining;
        if forbidden_solo {
            tracing::info!("{}", Self::log(&round, "I am the only one in that coinjoin."));
        }
        let too_few = (actual_input_count as i32) < self.config.absolute_min_input_count;
        if too_few {
            tracing::info!("{}", Self::log(&round, &format!("Transaction has {actual_input_count} inputs but minimum required is {}.", self.config.absolute_min_input_count)));
        }
        let all_outputs_present = sanity_check(outputs, &unsigned.tx.output);
        if !all_outputs_present {
            tracing::info!("{}", Self::log(&round, "There are missing outputs."));
        }
        let balance: i64 = unsigned.prevouts.iter().map(|o| o.value.to_sat() as i64).sum::<i64>() - unsigned.tx.output.iter().map(|o| o.value.to_sat() as i64).sum::<i64>();
        let vsize: i64 = unsigned.prevouts.iter().map(|o| script_input_vsize(&o.script_pubkey)).sum::<i64>() + unsigned.tx.output.iter().map(|o| script_output_vsize(&o.script_pubkey)).sum::<i64>();
        let effective_fee_per_k = if vsize > 0 { ((balance as f64) / (vsize as f64) * 1000.0) as i64 } else { 0 };
        let taking_extra_fees = (effective_fee_per_k as f64) <= (p.mining_fee_rate as f64) * 0.90;
        if taking_extra_fees {
            tracing::info!("{}", Self::log(&round, "Effective fee rate of the transaction is lower than expected."));
        }
        let must_sign_all = !forbidden_solo && !too_few && all_outputs_present && !taking_extra_fees;
        if !must_sign_all {
            tracing::info!("{}", Self::log(&round, "A subset of inputs will be signed."));
        }
        let mut to_sign = alices;
        if !must_sign_all {
            let i = rand::thread_rng().gen_range(0..to_sign.len());
            to_sign.remove(i);
        }
        let delay = if p.delay_transaction_signing { Duration::from_secs(50) } else { Duration::ZERO };
        let start = Instant::now() + delay;
        if must_sign_all {
            self.emit(Progress::TransactionSigned { txid: unsigned.tx.compute_txid(), inputs: unsigned.tx.input.iter().map(|i| i.previous_output).collect() });
        }
        self.sign_transaction(&to_sign, &unsigned, start, signing_end, &phase_cancel).await?;
        tracing::info!("{}", Self::log(&round, &format!("{} of your Alices have signed the coinjoin transaction.", to_sign.len())));
        Ok((unsigned.tx, to_sign))
    }

    async fn sign_transaction(&self, alices: &[AliceClient], unsigned: &UnsignedCoinJoin, start: Instant, end: Instant, cancel: &CancellationToken) -> Result<(), CjError> {
        if alices.is_empty() {
            return Ok(());
        }
        let max_delay = Duration::from_secs(50);
        let mut start = start;
        let unsigned = Arc::new(UnsignedCoinJoin { tx: unsigned.tx.clone(), prevouts: unsigned.prevouts.clone(), ownership_proofs: unsigned.ownership_proofs.clone() });
        if self.key_chain.signing_takes_time() {
            let kc = self.key_chain.clone();
            let u = unsigned.clone();
            let first = alices[0].coin.outpoint;
            tokio::task::spawn_blocking(move || kc.sign(&u, &first)).await.map_err(|e| CjError::Other(e.to_string()))?.map_err(|e| CjError::Other(e.to_string()))?;
            start = Instant::now();
        }
        let dates = scheduled_instants(alices.len(), start, end, max_delay);
        let tasks = alices.iter().zip(dates).map(|(a, d)| {
            let unsigned = unsigned.clone();
            async move {
                tokio::select! {
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(d)) => {}
                    _ = cancel.cancelled() => return Err(CjError::Cancelled),
                }
                let kc = self.key_chain.clone();
                let u = unsigned.clone();
                let op = a.coin.outpoint;
                let witness: Witness = tokio::task::spawn_blocking(move || kc.sign(&u, &op)).await.map_err(|e| CjError::Other(e.to_string()))?.map_err(|e| CjError::Other(e.to_string()))?;
                let index = unsigned.tx.input.iter().position(|i| i.previous_output == op).ok_or_else(|| CjError::Other("input not in coinjoin".into()))? as u32;
                let witness_hex = hex::encode_upper(bitcoin::consensus::encode::serialize(&witness));
                match a.arena.sign_transaction(&a.round_id, index, &witness_hex).await {
                    Ok(()) => {
                        tracing::info!("round {}: posted a signature for {}", &a.round_id[..8], op);
                        Ok(())
                    }
                    Err(ArenaError::Api(e)) if e.error_code() == Some("WitnessAlreadyProvided") => Ok(()),
                    Err(e) => Err(CjError::from(e)),
                }
            }
        });
        for r in join_all(tasks).await {
            r?;
        }
        Ok(())
    }

    async fn update_liquidity_clue(&self, max_suggested_amount: i64, unsigned: &Transaction, my_outputs: &[TxOut]) {
        let my: HashSet<(u64, ScriptBuf)> = my_outputs.iter().map(|o| (o.value.to_sat(), o.script_pubkey.clone())).collect();
        let foreign: Vec<i64> = unsigned.output.iter().filter(|o| !my.contains(&(o.value.to_sat(), o.script_pubkey.clone()))).map(|o| o.value.to_sat() as i64).collect();
        if let Some(clue) = calculate_liquidity_clue(&foreign) {
            if max_suggested_amount / 2 > clue {
                *self.liquidity_clue.lock().await = Some(clue);
            }
        }
    }
}

/// `LiquidityClueProvider.TryCalculateLiquidityClue`
pub fn calculate_liquidity_clue(foreign_output_values: &[i64]) -> Option<i64> {
    let mut denoms: Vec<i64> = foreign_output_values.iter().copied().filter(|v| STD_DENOMS.contains(v)).collect();
    denoms.sort_unstable();
    denoms.dedup();
    if denoms.is_empty() {
        return None;
    }
    let take = ((denoms.len() as f64) * 0.1).ceil() as usize;
    let mut top: Vec<i64> = denoms.iter().rev().take(take).copied().collect();
    top.sort_unstable();
    top.get(top.len() / 2).copied()
}

pub const STD_DENOMS: [i64; 79] = [
    5000, 6561, 8192, 10000, 13122, 16384, 19683, 20000, 32768, 39366, 50000, 59049, 65536, 100000, 118098, 131072, 177147, 200000, 262144, 354294, 500000, 524288, 531441, 1000000, 1048576, 1062882, 1594323,
    2000000, 2097152, 3188646, 4194304, 4782969, 5000000, 8388608, 9565938, 10000000, 14348907, 16777216, 20000000, 28697814, 33554432, 43046721, 50000000, 67108864, 86093442, 100000000, 129140163, 134217728,
    200000000, 258280326, 268435456, 387420489, 500000000, 536870912, 774840978, 1000000000, 1073741824, 1162261467, 2000000000, 2147483648, 2324522934, 3486784401, 4294967296, 5000000000, 6973568802,
    8589934592, 10000000000, 10460353203, 17179869184, 20000000000, 20920706406, 31381059609, 34359738368, 50000000000, 62762119218, 68719476736, 94143178827, 100000000000, 137438953472,
];

/// `SigningState.CreateUnsignedTransaction`: inputs by amount desc then outpoint bytes, outputs
/// consolidated per script, by value desc then script bytes; version 1, locktime 0, final sequence.
pub fn build_unsigned_coinjoin(round: &RoundState) -> Result<UnsignedCoinJoin, CjError> {
    let mut inputs: Vec<(ForeignCoin, Vec<u8>)> = Vec::new();
    for (c, proof) in round.coinjoin_state.inputs() {
        let outpoint = wasabi_proto::script::outpoint_from_hex(&c.outpoint).ok_or_else(|| CjError::Other("bad outpoint".into()))?;
        let script = wasabi_proto::script::script_from_asm(&c.tx_out.script_pub_key).map_err(|e| CjError::Other(e.to_string()))?;
        inputs.push((ForeignCoin { outpoint, script, amount: c.tx_out.value }, hex::decode(proof).map_err(|e| CjError::Other(e.to_string()))?));
    }
    inputs.sort_by(|(a, _), (b, _)| b.amount.cmp(&a.amount).then_with(|| outpoint_bytes(&a.outpoint).cmp(&outpoint_bytes(&b.outpoint))));
    let mut grouped: HashMap<ScriptBuf, i64> = HashMap::new();
    let mut order: Vec<ScriptBuf> = Vec::new();
    for o in round.coinjoin_state.outputs() {
        let script = wasabi_proto::script::script_from_asm(&o.script_pub_key).map_err(|e| CjError::Other(e.to_string()))?;
        if !grouped.contains_key(&script) {
            order.push(script.clone());
        }
        *grouped.entry(script).or_default() += o.value;
    }
    let mut outputs: Vec<(ScriptBuf, i64)> = order.into_iter().map(|s| { let v = grouped[&s]; (s, v) }).collect();
    outputs.sort_by(|(sa, va), (sb, vb)| vb.cmp(va).then_with(|| sa.as_bytes().cmp(sb.as_bytes())));
    let tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: inputs.iter().map(|(c, _)| TxIn { previous_output: c.outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }).collect(),
        output: outputs.into_iter().map(|(s, v)| TxOut { value: Amount::from_sat(v as u64), script_pubkey: s }).collect(),
    };
    let prevouts = inputs.iter().map(|(c, _)| TxOut { value: Amount::from_sat(c.amount as u64), script_pubkey: c.script.clone() }).collect();
    let ownership_proofs = inputs.iter().map(|(c, p)| (c.outpoint, p.clone())).collect();
    Ok(UnsignedCoinJoin { tx, prevouts, ownership_proofs })
}

fn outpoint_bytes(op: &OutPoint) -> Vec<u8> {
    let mut v = op.txid.to_byte_array().to_vec();
    v.extend_from_slice(&op.vout.to_le_bytes());
    v
}

/// `CoinJoinClient.SanityCheck`
pub fn sanity_check(expected: &[TxOut], coinjoin_outputs: &[TxOut]) -> bool {
    let mut consolidated: HashMap<ScriptBuf, u64> = HashMap::new();
    for o in expected {
        *consolidated.entry(o.script_pubkey.clone()).or_default() += o.value.to_sat();
    }
    consolidated.iter().all(|(script, value)| coinjoin_outputs.iter().any(|o| &o.script_pubkey == script && o.value.to_sat() >= *value))
}

fn calculate_costs(round: &RoundState, fee_rate: FeeRate, my_inputs: &[CjCoin], my_outputs: &[TxOut]) -> CoinjoinCosts {
    let my_scripts: HashSet<ScriptBuf> = my_outputs.iter().map(|o| o.script_pubkey.clone()).collect();
    let registered: Vec<(ScriptBuf, i64)> = round
        .coinjoin_state
        .outputs()
        .filter_map(|o| wasabi_proto::script::script_from_asm(&o.script_pub_key).ok().map(|s| (s, o.value)))
        .filter(|(s, _)| my_scripts.contains(s))
        .collect();
    let mining_fee: i64 = my_inputs.iter().map(|c| fee_rate.get_fee(c.script_type.input_vsize())).sum::<i64>() + registered.iter().map(|(s, _)| fee_rate.get_fee(script_output_vsize(s))).sum::<i64>();
    let wasted_dust = my_inputs.iter().map(|c| c.amount).sum::<i64>() - registered.iter().map(|(_, v)| v).sum::<i64>() - mining_fee;
    CoinjoinCosts { mining_fee, wasted_dust }
}

/// `DependencyGraphTaskScheduler`: every edge is a credential slot filled by the request that
/// produces it and awaited by the request that presents it.
struct Scheduler {
    graph: DependencyGraph,
    slots: [Vec<watch::Sender<Option<Credential>>>; 2],
}

impl Scheduler {
    fn new(graph: &DependencyGraph) -> Self {
        let mk = |n: usize| (0..n).map(|_| watch::channel(None).0).collect::<Vec<_>>();
        Self { graph: graph.clone(), slots: [mk(graph.edge_sets[0].edges.len()), mk(graph.edge_sets[1].edges.len())] }
    }

    async fn await_edges(&self, ct: CredentialType, edge_ids: &[usize]) -> Result<Vec<Credential>, CjError> {
        let mut out = Vec::with_capacity(edge_ids.len());
        for id in edge_ids {
            let mut rx = self.slots[ct as usize][*id].subscribe();
            let v = rx.wait_for(|v| v.is_some()).await.map_err(|_| CjError::Other("credential slot closed".into()))?;
            out.push(v.clone().unwrap());
        }
        Ok(out)
    }

    fn fill(&self, ct: CredentialType, edge_ids: &[usize], creds: Vec<Credential>) {
        if creds.len() < edge_ids.len() {
            tracing::warn!("{} {:?} credential(s) issued for {} edge(s); the dependent requests cannot proceed.", creds.len(), ct, edge_ids.len());
        }
        for (id, c) in edge_ids.iter().zip(creds) {
            // `send` drops the value when nobody has subscribed yet (the consumer task may not have
            // been polled up to its subscribe), which left every dependent request waiting forever.
            self.slots[ct as usize][*id].send_replace(Some(c));
        }
    }

    /// `SmartRequestNode.StartReissuanceAsync` for one node: present `amount_in`/`vsize_in`,
    /// request the out-edge values, fill the out-edge slots.
    async fn reissue_node(&self, bob: &BobClient, node: usize, amount_in: Vec<Credential>, vsize_in: Vec<Credential>) -> Result<(), CjError> {
        let amount_out = self.graph.out_edges(node, CredentialType::Amount);
        let vsize_out = self.graph.out_edges(node, CredentialType::Vsize);
        let amounts: Vec<i64> = amount_out.iter().map(|e| e.value).collect();
        let vsizes: Vec<i64> = vsize_out.iter().map(|e| e.value).collect();
        let amounts_req = add_extra_credential_requests(&amounts, amount_in.iter().map(|c| c.value()).sum());
        let vsizes_req = add_extra_credential_requests(&vsizes, vsize_in.iter().map(|c| c.value()).sum());
        let issued = bob.reissue(&amounts_req, &vsizes_req, &amount_in, &vsize_in).await?;
        let (amount_creds, _) = separate_extra_credentials(&issued.amount, &amounts);
        let (vsize_creds, _) = separate_extra_credentials(&issued.vsize, &vsizes);
        self.fill(CredentialType::Amount, &amount_out.iter().map(|e| e.id).collect::<Vec<_>>(), amount_creds);
        self.fill(CredentialType::Vsize, &vsize_out.iter().map(|e| e.id).collect::<Vec<_>>(), vsize_creds);
        Ok(())
    }

    /// `StartReissuancesAsync` (connection-confirmation reissuances + reissuance nodes).
    async fn run_reissuances(&self, client: &CoinJoinClient, round: &RoundState, alices: &[AliceClient], cancel: &CancellationToken) -> Result<(), CjError> {
        let inputs = self.graph.inputs();
        let mut tasks: Vec<Pin<Box<dyn Future<Output = Result<(), CjError>> + Send + '_>>> = Vec::new();
        for (alice, node) in alices.iter().zip(inputs) {
            let bob = client.create_bob(round)?;
            let amount_in: Vec<Credential> = alice.issued_amount.iter().take(2).cloned().collect();
            let vsize_in: Vec<Credential> = alice.issued_vsize.iter().take(2).cloned().collect();
            tasks.push(Box::pin(async move { self.reissue_node(&bob, node, amount_in, vsize_in).await }));
        }
        for node in self.graph.reissuances() {
            let bob = client.create_bob(round)?;
            tasks.push(Box::pin(async move {
                let a_in: Vec<usize> = self.graph.in_edges(node, CredentialType::Amount).iter().map(|e| e.id).collect();
                let v_in: Vec<usize> = self.graph.in_edges(node, CredentialType::Vsize).iter().map(|e| e.id).collect();
                let amount_in = self.await_edges(CredentialType::Amount, &a_in).await?;
                let vsize_in = self.await_edges(CredentialType::Vsize, &v_in).await?;
                self.reissue_node(&bob, node, amount_in, vsize_in).await
            }));
        }
        let all = try_join_all(tasks);
        tokio::select! {
            r = all => r?,
            _ = cancel.cancelled() => return Err(CjError::Cancelled),
        };
        Ok(())
    }

    /// `StartOutputRegistrationsAsync`; returns `(script, error code)` for failed registrations.
    async fn run_output_registrations(&self, client: &CoinJoinClient, round: &RoundState, outputs: &[TxOut], dates: Vec<Instant>, cancel: &CancellationToken) -> Result<Vec<(ScriptBuf, Option<String>)>, CjError> {
        let nodes = self.graph.outputs();
        let mut tasks: Vec<Pin<Box<dyn Future<Output = Result<Option<(ScriptBuf, Option<String>)>, CjError>> + Send + '_>>> = Vec::new();
        for ((txout, node), date) in outputs.iter().zip(nodes).zip(dates) {
            let bob = client.create_bob(round)?;
            tasks.push(Box::pin(async move {
                let a_in: Vec<usize> = self.graph.in_edges(node, CredentialType::Amount).iter().map(|e| e.id).collect();
                let v_in: Vec<usize> = self.graph.in_edges(node, CredentialType::Vsize).iter().map(|e| e.id).collect();
                let amount = self.await_edges(CredentialType::Amount, &a_in).await?;
                let vsize = self.await_edges(CredentialType::Vsize, &v_in).await?;
                tokio::time::sleep_until(tokio::time::Instant::from_std(date)).await;
                let asm = wasabi_proto::script::script_to_asm(&txout.script_pubkey);
                match bob.register_output(&asm, &amount, &vsize).await {
                    Ok(()) => Ok(None),
                    Err(ArenaError::Api(e)) => {
                        tracing::debug!("Output registration error, code:'{:?}' message:'{e}'.", e.error_code());
                        Ok(Some((txout.script_pubkey.clone(), e.error_code().map(str::to_string))))
                    }
                    Err(e) => Err(CjError::from(e)),
                }
            }));
        }
        let all = join_all(tasks);
        let results = tokio::select! {
            r = all => r,
            _ = cancel.cancelled() => return Err(CjError::Cancelled),
        };
        let mut errors = Vec::new();
        for r in results {
            if let Some(e) = r? {
                errors.push(e);
            }
        }
        Ok(errors)
    }
}

/// `SmartRequestNode.AddExtraCredentialRequests`
fn add_extra_credential_requests(values: &[i64], sum: i64) -> Vec<i64> {
    let mut non_zero: Vec<i64> = values.iter().copied().filter(|v| *v > 0).collect();
    if non_zero.len() == 2 {
        return non_zero;
    }
    let missing = sum - values.iter().sum::<i64>();
    if missing > 0 {
        non_zero.push(missing);
    }
    while non_zero.len() < 2 {
        non_zero.push(0);
    }
    non_zero
}

/// `SmartRequestNode.SeparateExtraCredentials`: issued credentials matched to the required values in order.
fn separate_extra_credentials(issued: &[Credential], required: &[i64]) -> (Vec<Credential>, Vec<Credential>) {
    let mut wanted = Vec::new();
    let mut extra = Vec::new();
    let mut it = issued.iter();
    for req in required {
        for c in it.by_ref() {
            if c.value() == *req {
                wanted.push(c.clone());
                break;
            } else {
                extra.push(c.clone());
            }
        }
    }
    for c in it {
        extra.push(c.clone());
    }
    (wanted, extra)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn scheduler_keeps_a_credential_filled_before_anyone_subscribes() {
        use super::*;
        let g = DependencyGraph::resolve(&[(10, 10)], &[(6, 4)], 1_000, 1_000).unwrap();
        let s = Scheduler::new(&g);
        let edge = g.out_edges(g.inputs()[0], CredentialType::Amount)[0].id;
        s.fill(CredentialType::Amount, &[edge], vec![Credential([0u8; 105])]);
        let got = tokio::time::timeout(Duration::from_secs(1), s.await_edges(CredentialType::Amount, &[edge])).await.expect("a filled slot must resolve for a late subscriber").unwrap();
        assert_eq!(got.len(), 1);
    }

    use super::*;

    #[test]
    fn extra_credentials_and_separation() {
        assert_eq!(add_extra_credential_requests(&[500, 0], 700), vec![500, 200]);
        assert_eq!(add_extra_credential_requests(&[300, 400], 700), vec![300, 400]);
        assert_eq!(add_extra_credential_requests(&[0, 0], 0), vec![0, 0]);
        assert_eq!(add_extra_credential_requests(&[700], 700), vec![700, 0]);
    }

    #[test]
    fn liquidity_clue_takes_top_decile_median() {
        let clue = calculate_liquidity_clue(&[5000, 100000, 1000000, 1000000, 7, 50000000]).unwrap();
        assert_eq!(clue, 50000000);
    }

    #[test]
    fn unsigned_coinjoin_matches_wasabi_ordering() {
        // SigningState.SortedInputs: amount desc, then outpoint bytes; SortedOutputs: per script, value desc, then script bytes.
        let spk_a = "0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let spk_b = "1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let proof = hex::encode([0u8; 4]);
        let outpoint = |b: u8, vout: u32| -> String {
            let mut v = vec![b; 32];
            v.extend_from_slice(&vout.to_le_bytes());
            hex::encode_upper(v)
        };
        let json = serde_json::json!({
            "id": "00".repeat(32), "blameOf": "00".repeat(32),
            "amountCredentialIssuerParameters": {"cw": "02".repeat(33)[..66], "i": "02".repeat(33)[..66]},
            "vsizeCredentialIssuerParameters": {"cw": "02".repeat(33)[..66], "i": "02".repeat(33)[..66]},
            "phase": 3, "endRoundState": 0, "inputRegistrationStart": "2026-10-17T20:07:52.3679128+00:00", "inputRegistrationTimeout": "0d 0h 21m 0s",
            "coinjoinState": {"Type": "SigningState", "Witnesses": {}, "IsFullySigned": false, "Events": [
                {"Type": "RoundCreated", "RoundParameters": {"Network": "Main", "MiningFeeRate": 500, "MaxSuggestedAmount": 1, "MinInputCountByRound": 1, "MaxInputCountByRound": 9,
                    "AllowedInputAmounts": {"Min": 1, "Max": 9}, "AllowedOutputAmounts": {"Min": 1, "Max": 9}, "AllowedInputTypes": [4, 7], "AllowedOutputTypes": [4, 7],
                    "StandardInputRegistrationTimeout": "0d 0h 1m 0s", "ConnectionConfirmationTimeout": "0d 0h 1m 0s", "OutputRegistrationTimeout": "0d 0h 1m 0s", "TransactionSigningTimeout": "0d 0h 1m 0s",
                    "BlameInputRegistrationTimeout": "0d 0h 1m 0s", "MinAmountCredentialValue": 1, "MaxAmountCredentialValue": 9, "MaxVsizeAllocationPerAlice": 255, "CoordinationIdentifier": "x", "DelayTransactionSigning": false}},
                {"Type": "InputAdded", "Coin": {"Outpoint": outpoint(0x11, 1), "TxOut": {"ScriptPubKey": spk_a, "Value": 5000}}, "OwnershipProof": proof},
                {"Type": "InputAdded", "Coin": {"Outpoint": outpoint(0x22, 0), "TxOut": {"ScriptPubKey": spk_b, "Value": 7000}}, "OwnershipProof": proof},
                {"Type": "InputAdded", "Coin": {"Outpoint": outpoint(0x11, 0), "TxOut": {"ScriptPubKey": spk_a, "Value": 5000}}, "OwnershipProof": proof},
                {"Type": "OutputAdded", "Output": {"ScriptPubKey": spk_a, "Value": 3000}},
                {"Type": "OutputAdded", "Output": {"ScriptPubKey": spk_b, "Value": 8000}},
                {"Type": "OutputAdded", "Output": {"ScriptPubKey": spk_a, "Value": 2000}}
            ]}
        });
        let round: RoundState = serde_json::from_value(json).unwrap();
        let u = build_unsigned_coinjoin(&round).unwrap();
        assert_eq!(u.tx.version, Version::ONE);
        assert_eq!(u.tx.input.len(), 3);
        assert_eq!(u.prevouts[0].value.to_sat(), 7000);
        assert_eq!(u.tx.input[1].previous_output.vout, 0, "same txid: lower vout bytes first");
        assert_eq!(u.tx.input[2].previous_output.vout, 1);
        assert_eq!(u.tx.output.len(), 2, "outputs to the same script are merged");
        assert_eq!(u.tx.output[0].value.to_sat(), 8000);
        assert_eq!(u.tx.output[1].value.to_sat(), 5000);
        assert!(u.tx.input.iter().all(|i| i.sequence == Sequence::MAX));
    }

    #[test]
    fn scheduled_instants_are_sorted_and_capped() {
        let now = Instant::now();
        let d = scheduled_instants(5, now, now + Duration::from_secs(100), Duration::from_secs(10));
        assert!(d.windows(2).all(|w| w[0] <= w[1]));
        assert!(d.iter().all(|t| *t <= now + Duration::from_secs(8)));
    }
}
