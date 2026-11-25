//! The leanVM tile: proves `aggregate` bodies in this process. Proofs are
//! verified where they arrive, in `beacon_state`.
//!
//! [`LeanVmTile`] takes `LeanVmReq` bodies off the spine and answers each
//! with a `LeanVmResp`, its body the prover's response (status byte
//! included), or `None` for no answer. `LeanVmHealthEvent` says the prover is
//! ready.
//!
//! The tile's thread proves. leanVM's pool runs the thread that calls
//! `aggregate` as its worker 0, so the tile's core is a prover core, and the
//! pool's other workers run on the rest of the prover cores. A proof blocks
//! the tile for its duration: requests arriving during it are taken once it
//! ends.

#[cfg(test)]
mod tests;
mod wire;

use std::collections::VecDeque;

use flux::{spine::SpineAdapter, tile::Tile, utils::try_thread_boot};
use flux_profiler::timed;
use lean_vm::{AggregateProof, OutputClaims};
use silver_common::{
    IngestionTime, LeanVmHealthEvent, LeanVmReq, LeanVmResp, SilverSpine, TCacheError, TCacheId,
    TCacheProducer, TCacheReader, TCacheTable, TProducer, TReadMode,
};
use wire::{Refusal, Rejection};

/// Aggregates taken off the spine and waiting for the prover. `beacon_state`
/// keeps one in flight, so a full queue means it lost track; past it each
/// request is answered `None`.
const MAX_QUEUED_AGGREGATES: usize = 16;

pub struct LeanVmTile {
    prover: Prover,
    reader: TCacheReader,
    producer: TProducer,
    aggregates: VecDeque<(u64, Vec<u8>)>,
    answers: Vec<LeanVmResp>,
}

enum Prover {
    /// No cores: every request is answered `None`.
    Off,
    /// The tile's core first. Starts in `try_init`, on the tile's thread.
    Cold(Vec<usize>),
    Warm,
}

impl Tile<SilverSpine> for LeanVmTile {
    /// Before any tile runs, so no request sent while the prover warms up
    /// goes unseen.
    fn on_attach(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.subscribe_broadcast::<LeanVmReq>();
    }

    /// Announces the prover before the first loop, so a reader sees it ready
    /// before its first answer.
    fn try_init(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        if let Prover::Cold(cores) = &self.prover {
            start_prover(cores);
            self.prover = Prover::Warm;
            silver_log::info!("leanvm prover ready");
            adapter.set_ingestion_time(IngestionTime::now());
            adapter.produce(LeanVmHealthEvent { ready: true });
        }
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.producer.loop_start();
        self.intake(adapter);
        if let Some((request_id, body)) = self.aggregates.pop_front() {
            let response = prove(&body);
            self.answer(request_id, &response);
            adapter.mark_work();
        }
        self.publish(adapter);
    }
}

impl LeanVmTile {
    /// `cores`: the tile's own core first, which the caller pins the tile
    /// to, then the prover's other cores. Empty for no prover.
    pub fn new(cores: Vec<usize>, tcaches: TCacheTable, producer: TProducer) -> Self {
        Self {
            prover: if cores.is_empty() { Prover::Off } else { Prover::Cold(cores) },
            reader: TCacheReader::new(tcaches),
            producer,
            aggregates: VecDeque::new(),
            answers: Vec::new(),
        }
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(
            TCacheId::BeaconStateHandoff,
            "leanvm_beacon_state_handoff",
            TReadMode::Sliding,
        )
    }

    /// Copies each request out of the tcache into the queue.
    fn intake(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        // The previous pass drained the queue.
        self.reader.free();
        let Self { prover, reader, aggregates, answers, .. } = self;
        adapter.consume(|req: LeanVmReq, _| {
            let request_id = req.request_id;
            let queued = match prover {
                Prover::Off | Prover::Cold(_) => false,
                Prover::Warm if aggregates.len() == MAX_QUEUED_AGGREGATES => {
                    silver_log::warn!(request_id, "leanvm aggregate queue full");
                    false
                }
                Prover::Warm => match copy_body(reader, req) {
                    Some(body) => {
                        aggregates.push_back((request_id, body));
                        true
                    }
                    None => false,
                },
            };
            if !queued {
                answers.push(LeanVmResp { request_id, body: None });
            }
        });
    }

    fn answer(&mut self, request_id: u64, response: &[u8]) {
        let body = self.producer.write_with(response.len(), |out| out.copy_from_slice(response));
        if body.is_none() {
            silver_log::error!(request_id, "leanvm tcache full; response dropped");
        }
        self.answers.push(LeanVmResp { request_id, body });
    }

    fn publish(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        for resp in self.answers.drain(..) {
            adapter.produce(resp);
        }
    }
}

/// The cores the prover may use: one hardware thread per physical core this
/// process may run on, from CPU `first` on, in order. A core whose sibling
/// thread lies below `first` is left out: a tile or the logger already runs
/// there. The prover gains nothing from a second thread on a core.
pub fn physical_cores(first: usize) -> Vec<usize> {
    let allowed = flux::core_affinity::get_core_ids().unwrap_or_default();
    let mut cores: Vec<usize> = allowed
        .into_iter()
        .map(|core| core.id)
        .filter(|&cpu| cpu >= first && first_sibling(cpu) == cpu)
        .collect();
    cores.sort_unstable();
    cores
}

/// The lowest CPU sharing `cpu`'s physical core, `cpu` itself when the
/// topology is unreadable.
fn first_sibling(cpu: usize) -> usize {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    let Ok(list) = std::fs::read_to_string(path) else { return cpu };
    // A list such as `1,17` or `0-1`: its first number is its lowest.
    let first = list.trim().split([',', '-']).next().and_then(|n| n.parse().ok());
    first.unwrap_or(cpu)
}

/// The request's body, if it is in an opened tcache and was not lapped
/// while copied.
fn copy_body(reader: &mut TCacheReader, req: LeanVmReq) -> Option<Vec<u8>> {
    let request_id = req.request_id;
    if !reader.is_open(req.body.id()) {
        silver_log::error!(request_id, "leanvm request outside the opened tcaches");
        return None;
    }
    let acquired = reader.acquire(req.body);
    let Ok((body, _)) = acquired.buffer() else {
        silver_log::warn!(request_id, "leanvm request lapped in the tcache");
        return None;
    };
    let body = body.to_vec();
    if acquired.revalidate().is_err() {
        silver_log::warn!(request_id, "leanvm request lapped in the tcache");
        return None;
    }
    Some(body)
}

/// Starts leanVM's pool on `cores`, then pins the calling thread back to
/// `cores[0]` and warms the prover up.
///
/// The pool's workers inherit the calling thread's CPU set, so it spans
/// every prover core while they start.
#[timed]
fn start_prover(cores: &[usize]) {
    try_thread_boot(cores, None).expect("pin to the leanvm cores");
    lean_vm::setup(cores.len());
    try_thread_boot(&cores[..1], None).expect("pin to the leanvm tile core");
    warm_up();
    silver_log::info!(?cores, "leanvm prover started");
}

/// A fresh process's first proofs are slower, touching memory the allocator
/// then keeps. This pays for it before the first request: a discarded leaf
/// over one blob, the one input that needs no key, and a full recursion over
/// it, at the rate used in practice.
fn warm_up() {
    let blobs = lean_vm::lean_da::BlobMatrix::build(&[[0; lean_vm::lean_da::BLOB_SYMBOLS]])
        .expect("one blob");
    let rate = 2;
    let leaf = lean_vm::aggregate(&[], vec![], vec![], Some(&blobs), OutputClaims::All, rate)
        .expect("the warm-up's leaf proves");
    let children = vec![leaf; lean_vm::MAX_RECURSIONS];
    lean_vm::aggregate(&children, vec![], vec![], None, OutputClaims::All, rate)
        .expect("the warm-up's recursion proves");
}

/// The response to an `aggregate` body. Proves on the calling thread.
#[timed]
fn prove(body: &[u8]) -> Vec<u8> {
    let request = match wire::decode_aggregate(body) {
        Ok(request) => request,
        Err(refusal) => return refuse(&refusal),
    };
    let shape = (request.children.len(), request.raw_lean_xmss.len(), request.log_inv_rate);
    let children = request
        .children
        .into_iter()
        .enumerate()
        .map(|(i, (claims, proof))| match AggregateProof::from_bytes(proof) {
            Some(proof) => Ok((claims, proof)),
            None => {
                let message = format!("child {i}'s proof does not decode");
                Err(Refusal { why: Rejection::InvalidChild, message })
            }
        })
        .collect::<Result<Vec<_>, _>>();
    let children = match children {
        Ok(children) => children,
        Err(refusal) => return refusal.encode(),
    };
    let blobs = match request.blobs.len() {
        0 => None,
        _ => match lean_vm::lean_da::BlobMatrix::build(&request.blobs) {
            Ok(blobs) => Some(blobs),
            Err(e) => {
                return Refusal { why: Rejection::InvalidInput, message: e.to_string() }.encode();
            }
        },
    };
    let output = request.output.as_ref().map_or(OutputClaims::All, OutputClaims::Only);
    let outcome = lean_vm::aggregate(
        &children,
        request.raw_lean_xmss,
        request.raw_lean_sphincs,
        blobs.as_ref(),
        output,
        request.log_inv_rate,
    );
    let (children, signatures, rate) = shape;
    match outcome {
        Ok((claims, proof)) => {
            silver_log::info!(children, signatures, rate, "leanvm proven");
            wire::encode_proven(&claims, &proof.to_bytes())
        }
        Err(error) => {
            silver_log::warn!(children, signatures, rate, %error, "leanvm refused");
            Refusal { why: error.into(), message: error.to_string() }.encode()
        }
    }
}

/// A body that is not a request.
fn refuse(refusal: &Refusal) -> Vec<u8> {
    silver_log::warn!(rejection = ?refusal.why, message = refusal.message, "leanvm request refused");
    refusal.encode()
}
