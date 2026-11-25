use std::{cmp::Reverse, mem, time::Duration};

use flux::{Timer, spine::SpineProducers};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot, pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ};
use silver_common::{
    LeanVmHealthEvent, LeanVmReq, LeanVmResp, Nanos, TCacheProducer, TCacheRead, TCacheReader,
    TProducer,
    ssz_view::{MAX_VALIDATORS_PER_COMMITTEE, SingleAttestationPqView},
    ticker::SlotTicker,
};

use super::{
    Aggregate, VerifiedVote,
    claims::Vote,
    leaf::{LeafAggregation, LeafKey, ProvedAggregate},
    merge::MergeAggregation,
    rolling::{POOL_SLOTS, Rolling, RollingJob, claims_of},
    strategy::Batch,
};
use crate::{counters::BeaconStateCounters, tile::Producers};

/// A merge waits this fraction of the next slot for that slot's block to be
/// verified: 3 s of 12 s, the attestation deadline.
const MERGE_WAIT_DIVISOR: u64 = 4;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AggregationKey {
    Leaf(LeafKey),
    Merge(Slot),
}

impl AggregationKey {
    fn slot(&self) -> Slot {
        match self {
            Self::Leaf(leaf) => leaf.slot,
            Self::Merge(slot) => *slot,
        }
    }
}

/// What one request to the leanVM sidecar is for.
enum Job {
    Batch(AggregationKey, Batch),
    Rolling(RollingJob),
}

/// The leanVM sidecar as the aggregator sees it: one request at a time, and
/// none while it is down.
#[derive(Default)]
enum LeanVm {
    #[default]
    Down,
    Idle,
    Busy {
        request_id: u64,
        job: Job,
        sent: Nanos,
    },
}

impl LeanVm {
    fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    fn up(&mut self) {
        if let Self::Down = self {
            *self = Self::Idle;
        }
    }

    /// The job that was in flight, now lost.
    fn down(&mut self) -> Option<Job> {
        match mem::take(self) {
            Self::Busy { job, .. } => Some(job),
            Self::Down | Self::Idle => None,
        }
    }

    /// Becomes idle if `request_id` is in flight, handing back its job and
    /// when it went out.
    fn take_answered(&mut self, request_id: u64) -> Option<(Job, Nanos)> {
        match mem::take(self) {
            Self::Busy { request_id: id, job, sent } if id == request_id => {
                *self = Self::Idle;
                Some((job, sent))
            }
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Every aggregation this node runs. One `LeanVmReq` is in flight at a time,
/// across all aggregations. Events only change state; `send_next` sends.
pub struct PqAggregator {
    leaves: FxHashMap<LeafKey, LeafAggregation>,
    /// An event changed state since `send_next` last found nothing to send.
    changed: bool,
    /// By attestation slot.
    merges: FxHashMap<Slot, MergeAggregation>,
    /// How long a slot's votes wait after its block arrives before they are
    /// proved. `None`: they are proved as they arrive.
    leaf_delay: Option<Nanos>,
    /// The newest slot whose block arrived, and when.
    block_arrived: Option<(Slot, Nanos)>,
    /// When the next aggregation opens unless a block opens it first. No
    /// event marks that moment, so `send_next` watches the clock until then.
    next_opens: Option<Nanos>,
    /// The newest slot whose block is done with the leanVM sidecar.
    block_settled: Slot,
    /// `None`: a block gets only the merge of the newest slot it may
    /// include.
    rolling: Option<Rolling>,
    leanvm: LeanVm,
    next_request_id: u64,
    leaf_round_trip: Timer,
    merge_round_trip: Timer,
    roll_round_trip: Timer,
    reduce_round_trip: Timer,
}

impl Default for PqAggregator {
    fn default() -> Self {
        Self {
            leaves: FxHashMap::default(),
            merges: FxHashMap::default(),
            leaf_delay: None,
            block_arrived: None,
            next_opens: None,
            block_settled: 0,
            rolling: None,
            changed: false,
            leanvm: LeanVm::default(),
            next_request_id: 0,
            leaf_round_trip: Timer::new("silver", "leanvm_prove"),
            merge_round_trip: Timer::new("silver", "leanvm_merge"),
            roll_round_trip: Timer::new("silver", "leanvm_roll"),
            reduce_round_trip: Timer::new("silver", "leanvm_reduce"),
        }
    }
}

impl PqAggregator {
    /// Keeps one proof of the pooled votes not yet on chain, across slots.
    pub fn enable_rolling(&mut self) {
        self.rolling = Some(Rolling::default());
    }

    pub fn is_rolling(&self) -> bool {
        self.rolling.is_some()
    }

    /// Votes of a slot are proved `delay` after the slot's block arrives, so
    /// that the first batch holds the votes the block released. Without a
    /// block they are proved from their aggregation cutoff.
    pub fn delay_leaves(&mut self, delay: Duration) {
        self.leaf_delay = Some(Nanos::from_millis(delay.as_millis() as u64));
    }

    /// The block of `slot` passed its proposer signature check.
    pub fn on_block_arrived(&mut self, slot: Slot, ticker: &SlotTicker) {
        let Some(delay) = self.leaf_delay else { return };
        if self.block_arrived.is_some_and(|(newest, _)| newest >= slot) {
            return;
        }
        let now = ticker.since_genesis();
        self.block_arrived = Some((slot, now));
        let opens = now + delay;
        (self.leaves.iter_mut())
            .filter(|(leaf, _)| leaf.slot <= slot)
            .for_each(|(_, leaf)| leaf.open_by(opens));
        self.watch(opens);
    }

    /// When a leaf of `slot` made now starts proving.
    fn leaf_opens(&self, slot: Slot, cutoff: Nanos) -> Nanos {
        let Some(delay) = self.leaf_delay else { return Nanos(0) };
        match self.block_arrived {
            Some((newest, at)) if newest == slot => (at + delay).min(cutoff),
            Some((newest, _)) if newest > slot => Nanos(0),
            _ => cutoff,
        }
    }

    fn watch(&mut self, opens: Nanos) {
        self.next_opens = Some(self.next_opens.map_or(opens, |held| held.min(opens)));
    }

    /// `last_position` is the last place a local aggregator of the vote's
    /// committee holds in its aggregation committee. Votes are taken until
    /// its cutoff and proved until its aggregate is due.
    pub fn add_vote(&mut self, vote: VerifiedVote, last_position: u64, ticker: &SlotTicker) {
        let leaf = LeafKey::new(&vote);
        if vote.committee_position >= vote.committee_len.min(MAX_VALIDATORS_PER_COMMITTEE) {
            let (committee_position, committee_len) = (vote.committee_position, vote.committee_len);
            silver_log::error!(
                slot = leaf.slot,
                committee_position,
                committee_len,
                "vote outside committee"
            );
            return;
        }
        let cutoff = ticker.aggregation_cutoff(leaf.slot, last_position);
        if ticker.since_genesis() >= cutoff {
            silver_log::debug!(slot = leaf.slot, "vote after the aggregation cutoff");
            return;
        }
        let opens = self.leaf_opens(leaf.slot, cutoff);
        self.watch(opens);
        // TODO: the aggregate due time stands in for the VC's pull. A VC that
        // pulls later gets a proof frozen at the due time. Consider ending on
        // the last local aggregator's pull instead.
        let deadline = ticker.pq_aggregate_due(leaf.slot, last_position);
        let aggregation = self.leaves.entry(leaf).or_insert_with(|| {
            let data = SingleAttestationPqView::data(vote.single);
            LeafAggregation::new(*data.as_bytes(), vote.committee_len, opens, deadline)
        });
        let (position, signature) =
            (vote.committee_position, SingleAttestationPqView::signature(vote.single));
        let added = aggregation.add(Vote::new(position, vote.pubkey, vote.message, signature));
        debug_assert!(added, "the position was checked against the largest committee");
        self.changed = true;
    }

    /// `aggregate` is verified. It joins the merge of its attestation slot,
    /// until the first block to include it is due or the rolling proof has
    /// taken the merge in. A merge refuses it once it holds too many
    /// committees.
    ///
    /// The merge is proved in the next slot, once that slot's block is done
    /// with the leanVM sidecar, so that the merge does not delay the block.
    /// It stops waiting for a late block at the attestation deadline.
    pub fn add_aggregate(&mut self, aggregate: Aggregate, ticker: &SlotTicker) {
        BeaconStateCounters::PqMergeClaimsOffered.add(aggregate.claims.len() as u64);
        let slot = aggregate.group.slot;
        let deadline = ticker.slot_start(slot + MIN_ATTESTATION_INCLUSION_DELAY_PQ);
        let awaited = self.rolling.as_ref().is_none_or(|rolling| rolling.awaits(slot));
        if ticker.since_genesis() >= deadline || !awaited {
            silver_log::debug!(slot, "aggregate after its slot's merge ended");
            return;
        }
        let opens = if self.block_settled > slot {
            ticker.since_genesis()
        } else {
            ticker.slot_start(slot + 1) + Nanos(ticker.slot_start(1).0 / MERGE_WAIT_DIVISOR)
        };
        self.watch(opens);
        let merge =
            (self.merges.entry(slot)).or_insert_with(|| MergeAggregation::new(opens, deadline));
        if !merge.add(aggregate) {
            silver_log::warn!(slot, "aggregate dropped: the merge holds too many committees");
            return;
        }
        self.changed = true;
    }

    /// A response to a request that is not in flight is ignored. A body that
    /// cannot be read counts as no answer.
    pub fn on_response(&mut self, resp: LeanVmResp, reader: &mut TCacheReader) {
        let acquired = resp.body.map(|read| reader.acquire(read));
        let body = acquired.as_ref().and_then(|acquired| acquired.buffer().ok());
        if body.is_none() && acquired.is_some() {
            silver_log::error!(request_id = resp.request_id, "leanvm response unreadable");
        }
        let Some((job, sent)) = self.leanvm.take_answered(resp.request_id) else { return };
        if body.is_some() {
            let round_trip = match job {
                Job::Batch(AggregationKey::Leaf(_), _) => &mut self.leaf_round_trip,
                Job::Batch(AggregationKey::Merge(_), _) => &mut self.merge_round_trip,
                Job::Rolling(RollingJob::Roll { .. }) => &mut self.roll_round_trip,
                Job::Rolling(RollingJob::Reduce { .. }) => &mut self.reduce_round_trip,
            };
            round_trip.emit_latency_from_nanos(sent, Nanos::now());
        }
        self.finish(job, body.map(|(body, _)| body));
        self.changed = true;
    }

    /// A leanVM sidecar that goes down fails the batch in flight at once. The
    /// transport's `None` answer for it comes later and is ignored.
    pub fn on_health(&mut self, health: LeanVmHealthEvent) {
        if health.ready {
            self.leanvm.up();
        } else if let Some(job) = self.leanvm.down() {
            self.finish(job, None);
        }
        self.changed = true;
    }

    /// Drops the aggregations of slots before `floor`. The request in flight
    /// for one still occupies the leanVM sidecar until its response arrives.
    ///
    /// Called as slot `floor + 1` starts. The block of that slot may include
    /// the `POOL_SLOTS` slots up to `floor - 1`.
    pub fn prune_before(&mut self, floor: Slot) {
        self.leaves.retain(|leaf, _| leaf.slot >= floor);
        self.merges.retain(|&slot, _| slot + MIN_ATTESTATION_INCLUSION_DELAY_PQ >= floor);
        if let Some(rolling) = &mut self.rolling {
            rolling.expire_before(floor.saturating_sub(POOL_SLOTS));
        }
        self.changed = true;
    }

    /// The block of `slot` was imported, rejected or dropped: its proofs no
    /// longer wait on the leanVM sidecar. The merges of earlier slots open.
    pub fn on_block_settled(&mut self, slot: Slot, ticker: &SlotTicker) {
        self.block_settled = self.block_settled.max(slot);
        let now = ticker.since_genesis();
        (self.merges.iter_mut())
            .filter(|(merged, _)| **merged < slot)
            .for_each(|(_, merge)| merge.open_by(now));
        self.changed = true;
    }

    /// A block included the votes of `validators` for attestation slot
    /// `slot`: the rolling proof no longer needs them.
    pub fn on_chain(&mut self, slot: Slot, validators: &[u32]) {
        if let Some(rolling) = &mut self.rolling {
            rolling.include_on_chain(slot, validators);
            self.changed = true;
        }
    }

    /// Sends a batch of the highest priority aggregation, if the leanVM
    /// sidecar is idle. The tile calls it once per loop, after the events.
    ///
    /// It returns at once until an event changes state. A full tcache leaves
    /// `changed` set, so the next loop retries. It is not a failure.
    pub fn send_next(
        &mut self,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        let now = ticker.since_genesis();
        if self.next_opens.is_some_and(|opens| now >= opens) {
            self.next_opens = None;
            self.changed = true;
        }
        if !self.changed || !self.leanvm.is_idle() {
            return;
        }
        let rolling_request = self.next_rolling_request(ticker, tcache);
        if let Some(rolling) = &self.rolling {
            BeaconStateCounters::PqMergedClaims.set(rolling.claims_len() as u64);
        }
        let (job, body) = if let Some((job, body)) = rolling_request {
            // `None`: the tcache is full. The next loop retries.
            let Some(body) = body else { return };
            (Job::Rolling(job), body)
        } else {
            let Some(key) = self.highest_priority(now) else {
                self.changed = false;
                return;
            };
            // `None`: the tcache is full, or a strategy bug counted a failure.
            // The next loop retries.
            let Some((batch, body)) = self.write_request(key, now, tcache) else { return };
            (Job::Batch(key, batch), body)
        };
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.leanvm = LeanVm::Busy { request_id, job, sent: Nanos::now() };
        producers.produce(LeanVmReq { request_id, body });
    }

    /// The next change to the rolling proof that needs the leanVM sidecar,
    /// with its request written to `tcache`, or `None` for a full tcache.
    /// Changes that need no proof are made here. It goes ahead of every
    /// batch: there are at most two a slot, and a proposal waits on them.
    ///
    /// A slot's merge is taken in once it has nothing left to prove. The
    /// merge itself stays, for a block whose rolling proof lacks that slot.
    fn next_rolling_request(
        &mut self,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
    ) -> Option<(RollingJob, Option<TCacheRead>)> {
        let now = ticker.since_genesis();
        let rolling = self.rolling.as_mut()?;
        loop {
            if let Some(groups) = rolling.next_reduction() {
                let kept = claims_of(&groups);
                let request = rolling.reduce_request(&kept)?;
                let body = tcache.write_with(request.len(), |out| request.write(out));
                return Some((RollingJob::Reduce { groups }, body));
            }
            let (&slot, merge) = (self.merges.iter())
                .filter(|(slot, merge)| rolling.awaits(**slot) && merge.is_proved())
                .min_by_key(|(slot, _)| **slot)?;
            if merge.priority(now).is_some() {
                return None;
            }
            let taken = merge.proved()?;
            let Some(request) = rolling.roll_request(&taken) else {
                rolling.start_with(slot, taken);
                continue;
            };
            let body = tcache.write_with(request.len(), |out| request.write(out));
            return Some((RollingJob::Roll { slot, taken }, body));
        }
    }

    pub fn aggregate(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<ProvedAggregate<'_>> {
        self.leaves.get(&LeafKey { slot, committee_index, data_root })?.proved(committee_index)
    }

    /// The attestations and proof for the body of the block at `slot`.
    pub fn block_proof(&self, slot: Slot) -> Option<(Vec<Vec<u8>>, &[u8])> {
        let newest = slot.checked_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ)?;
        let merged = self.merges.get(&newest).and_then(|merge| merge.block_proof());
        let Some(rolling) = &self.rolling else { return merged };
        // The rolling proof lacks the newest slot until its roll is proved,
        // and for good if that roll failed.
        rolling.block_proof_through(newest).or(merged).or_else(|| rolling.block_proof(slot))
    }

    /// A pruned aggregation drops its batch.
    fn finish(&mut self, job: Job, body: Option<&[u8]>) {
        let (key, batch) = match job {
            Job::Batch(key, batch) => (key, batch),
            Job::Rolling(job) => {
                let finished = self.rolling.as_mut().map(|rolling| rolling.finish(job, body));
                if let Some(Err(reason)) = finished {
                    silver_log::warn!(reason, "rolling proof request failed");
                }
                return;
            }
        };
        let rolls = self.rolling.is_some();
        let settled = match key {
            AggregationKey::Leaf(leaf) => (self.leaves.get_mut(&leaf))
                .map(|leaf| (leaf.finish(batch, body), leaf.core.is_stopped())),
            AggregationKey::Merge(slot) => self.merges.get_mut(&slot).map(|merge| {
                let finished = merge.finish(batch, body);
                if let (false, Some((claims, _))) = (rolls, merge.core.best_proof()) {
                    BeaconStateCounters::PqMergedClaims.set(claims.len() as u64);
                }
                (finished, merge.core.is_stopped())
            }),
        };
        let Some((Err(reason), stopped)) = settled else { return };
        let slot = key.slot();
        silver_log::warn!(slot, reason, "aggregation batch failed");
        if stopped {
            silver_log::warn!(slot, "aggregation stopped after repeated failures");
        }
    }

    /// The next batch of `key`, with its request written to `tcache`.
    fn write_request(
        &mut self,
        key: AggregationKey,
        now: Nanos,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        match key {
            AggregationKey::Leaf(leaf) => self.leaves.get_mut(&leaf)?.next_request(now, tcache),
            AggregationKey::Merge(slot) => self.merges.get_mut(&slot)?.next_request(now, tcache),
        }
    }

    /// Ties go to the lower key, so the order is total and deterministic.
    fn highest_priority(&self, now: Nanos) -> Option<AggregationKey> {
        let leaves = self.leaves.iter().filter_map(|(&leaf, aggregation)| {
            Some((aggregation.priority(now)?, Reverse(AggregationKey::Leaf(leaf))))
        });
        let merges = self.merges.iter().filter_map(|(&slot, aggregation)| {
            Some((aggregation.priority(now)?, Reverse(AggregationKey::Merge(slot))))
        });
        leaves.chain(merges).max().map(|(_, Reverse(key))| key)
    }
}
