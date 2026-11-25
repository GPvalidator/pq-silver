use std::time::Instant;

use flux::Timer;
use lean_vm::{AggregateClaims, AggregateProof, lean_xmss::LeanXmssPublicKey};
use silver_beacon_state_data::{ValidatorsView, pq::xmss_pubkey};
use silver_common::Nanos;

use crate::{
    stf::StarkClaims,
    tile::pq_aggregation::{Claim, claim},
};

/// Verifies leanVM proofs on the tile's thread, so a verify blocks the loop
/// for its duration.
pub enum LeanVmVerifier {
    LeanVm {
        sorted: Vec<Claim>,
        duration: Timer,
    },
    /// Spec vectors and tests carry no real proofs.
    #[cfg(any(test, feature = "ef_tests"))]
    Fixed(bool),
}

impl Default for LeanVmVerifier {
    fn default() -> Self {
        Self::LeanVm { sorted: Vec::new(), duration: Timer::new("silver", "leanvm_verify") }
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

    /// How many proofs `stark` collected from `data`, or `None` at the first
    /// invalid one.
    pub fn stark_proofs_valid(
        &mut self,
        stark: &StarkClaims,
        data: &[u8],
        validators: &ValidatorsView,
    ) -> Option<usize> {
        let mut proofs = 0;
        for (signed, proof) in stark.proofs(data) {
            let claims = signed.map(|(signer, message)| {
                claim(xmss_pubkey(validators.pubkey(signer as usize)), message)
            });
            if !self.verify(claims, proof) {
                return None;
            }
            proofs += 1;
        }
        Some(proofs)
    }

    /// Whether `proof` proves exactly the set of `claims`.
    pub fn verify(&mut self, claims: impl IntoIterator<Item = Claim>, proof: &[u8]) -> bool {
        let (sorted, duration) = match self {
            Self::LeanVm { sorted, duration } => (sorted, duration),
            #[cfg(any(test, feature = "ef_tests"))]
            Self::Fixed(valid) => return *valid,
        };
        let started = Nanos::now();
        sorted.clear();
        sorted.extend(claims);
        sorted.sort_unstable();
        sorted.dedup();
        debug_assert!(!sorted.is_empty(), "leanVM has nothing to check against");
        // A key's bytes order as the key does, so the claims stay sorted.
        let lean_xmss = sorted.iter().map(|claim| {
            let (pubkey, message) = claim.split_first_chunk::<32>().expect("64-byte claim");
            (LeanXmssPublicKey::from_bytes(pubkey), message.try_into().expect("64-byte claim"))
        });
        let claims = AggregateClaims {
            lean_xmss: lean_xmss.collect(),
            lean_sphincs: vec![],
            da_commitment: None,
        };
        let valid = AggregateProof::from_bytes(proof).is_some_and(|proof| proof.verify(&claims));
        duration.emit_latency_from_nanos(started, Nanos::now());
        silver_log::debug!(valid, "leanvm proof verdict");
        valid
    }
}
