use std::ops::Range;

use silver_beacon_state_data::{AGGREGATORS_PER_COMMITTEE, Slot};
use silver_common::{NewGossipMsg, TRead};
use silver_ssz::ssz_view::MAX_COMMITTEES_PER_SLOT_PQ;

use super::leanvm_verifier::ProofVerdict;

const MAX_AWAITING: usize = 2 * MAX_COMMITTEES_PER_SLOT_PQ * AGGREGATORS_PER_COMMITTEE;

pub(super) struct AwaitingProofs {
    pub msg: NewGossipMsg,
    pub pin: TRead,
    parked_at: Slot,
    requests: Range<u64>,
    unverified: usize,
}

#[derive(Default)]
pub(super) struct GossipProofs {
    awaiting: Vec<AwaitingProofs>,
}

impl GossipProofs {
    pub(super) fn is_full(&self) -> bool {
        self.awaiting.len() >= MAX_AWAITING
    }

    pub(super) fn park(
        &mut self,
        msg: NewGossipMsg,
        pin: TRead,
        parked_at: Slot,
        requests: Range<u64>,
    ) {
        debug_assert!(!requests.is_empty() && !self.is_full());
        let unverified = (requests.end - requests.start) as usize;
        self.awaiting.push(AwaitingProofs { msg, pin, parked_at, requests, unverified });
    }

    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.awaiting.retain(|awaiting| awaiting.parked_at >= floor);
    }

    pub(super) fn awaits(&self, request_id: u64) -> bool {
        self.awaiting.iter().any(|awaiting| awaiting.requests.contains(&request_id))
    }

    pub(super) fn on_verdict(
        &mut self,
        request_id: u64,
        verdict: ProofVerdict,
    ) -> Option<AwaitingProofs> {
        let index =
            self.awaiting.iter().position(|awaiting| awaiting.requests.contains(&request_id))?;
        if verdict == ProofVerdict::Valid {
            let awaiting = &mut self.awaiting[index];
            awaiting.unverified -= 1;
            if awaiting.unverified > 0 {
                return None;
            }
        }
        Some(self.awaiting.swap_remove(index))
    }
}
