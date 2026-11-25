use std::{collections::VecDeque, time::Instant};

use flux::Timer;
use lean_vm::{AggregateClaims, AggregateProof, lean_xmss::LeanXmssPublicKey};
use silver_common::Nanos;

use crate::tile::pq_aggregation::Claim;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVerdict {
    Valid,
    Invalid,
}

/// Verifies leanVM proofs inline, on the tile's thread. Each proof is judged
/// when [`Self::verify`] is called, under the id it returns, and its verdict
/// waits for [`Self::take_verdict`]: the caller first parks what waits on it.
pub struct LeanVmVerifier {
    verified: u64,
    claims: Vec<Claim>,
    verdicts: VecDeque<(u64, ProofVerdict)>,
    duration: Timer,
}

impl Default for LeanVmVerifier {
    fn default() -> Self {
        Self {
            verified: 0,
            claims: Vec::new(),
            verdicts: VecDeque::new(),
            duration: Timer::new("silver", "leanvm_verify"),
        }
    }
}

impl LeanVmVerifier {
    /// Builds leanVM's verifying program, so the first proof does not pay for
    /// it. Decoding builds it: the proof's first field is sized by it.
    pub fn warm_up() {
        let started = Instant::now();
        let _ = AggregateProof::from_bytes(&[0; 8]);
        silver_log::info!(elapsed = ?started.elapsed(), "leanvm verifier ready");
    }

    /// Judges whether `proof` proves exactly the set of `claims`.
    pub fn verify(&mut self, claims: impl IntoIterator<Item = Claim>, proof: &[u8]) -> u64 {
        let started = Nanos::now();
        self.claims.clear();
        self.claims.extend(claims);
        self.claims.sort_unstable();
        self.claims.dedup();
        debug_assert!(!self.claims.is_empty(), "leanVM has nothing to check against");
        // A key's bytes order as the key does, so the claims stay sorted.
        let lean_xmss = self.claims.iter().map(|claim| {
            let (pubkey, message) = claim.split_first_chunk::<32>().expect("64-byte claim");
            (LeanXmssPublicKey::from_bytes(pubkey), message.try_into().expect("64-byte claim"))
        });
        let claims = AggregateClaims {
            lean_xmss: lean_xmss.collect(),
            lean_sphincs: vec![],
            da_commitment: None,
        };
        let valid = AggregateProof::from_bytes(proof).is_some_and(|proof| proof.verify(&claims));
        self.duration.emit_latency_from_nanos(started, Nanos::now());

        let request_id = self.next_request_id();
        self.verified += 1;
        let verdict = if valid { ProofVerdict::Valid } else { ProofVerdict::Invalid };
        self.verdicts.push_back((request_id, verdict));
        request_id
    }

    /// Ids go out in order, so the proofs verified between two calls form a
    /// range.
    pub fn next_request_id(&self) -> u64 {
        self.verified
    }

    pub fn take_verdict(&mut self) -> Option<(u64, ProofVerdict)> {
        self.verdicts.pop_front()
    }
}
