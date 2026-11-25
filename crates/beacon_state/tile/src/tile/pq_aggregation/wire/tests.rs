use super::*;

fn claim(tag: u8) -> Claim {
    [tag; 64]
}

/// Ascending in `index`.
fn numbered(index: usize) -> Claim {
    let mut claim = [0; 64];
    claim[..8].copy_from_slice(&(index as u64).to_be_bytes());
    claim
}

fn le(value: usize) -> [u8; 8] {
    (value as u64).to_le_bytes()
}

/// The protocol's `aggregate` layout, appended field by field.
fn naive_body(request: &AggregateRequest) -> Vec<u8> {
    let mut body = vec![OP_AGGREGATE, request.log_inv_rate];
    body.extend(le(request.proofs.len()));
    for (claims, proof) in &request.proofs {
        body.extend(le(8 + claims.len() * 64 + 8 + 1));
        body.extend(le(claims.len()));
        claims.iter().for_each(|claim| body.extend(claim));
        body.extend(le(0));
        body.push(0);
        body.extend(le(proof.len()));
        body.extend(*proof);
    }
    body.extend(le(request.signatures.len()));
    for (claim, signature) in &request.signatures {
        body.extend(*claim);
        body.extend(*signature);
    }
    body.extend([0; 8 + 8 + 1]);
    body
}

#[test]
fn the_length_is_exactly_the_bytes_written() {
    let signature = [5u8; XMSS_SIGNATURE_SIZE];
    let claims: Vec<Claim> = (0..=255).map(claim).collect();
    let signatures: Vec<_> = (0..2048).map(|i| (&claims[i % 256], &signature)).collect();
    let proof = vec![3u8; 1000];
    let best = (&claims[..100], &proof[..]);
    let sixteen: Vec<_> = (0..16).map(|i| (&claims[i..i + 1], &proof[..i])).collect();
    let shapes = [
        (vec![], vec![]),
        (vec![best], vec![]),
        (sixteen, vec![]),
        (vec![best], signatures.clone()),
        (vec![], signatures[..3].to_vec()),
    ];
    for (proofs, signatures) in shapes {
        let request = AggregateRequest { log_inv_rate: 2, proofs, signatures, output: None };
        let mut out = vec![0xAA; request.len()];
        request.write(&mut out);
        assert_eq!(out[0], 1, "aggregate op");
        assert_eq!(out, naive_body(&request));
    }
}

#[test]
fn the_longest_request_takes_exactly_the_bound() {
    let signature = [5u8; XMSS_SIGNATURE_SIZE];
    let claims: Vec<Claim> = (0..MAX_PROOF_CLAIMS).map(numbered).collect();
    let proof = vec![3u8; MAX_STARK_PROOF_SIZE];
    let best = (&claims[..], &proof[..]);
    let child = (&claims[..MAX_VALIDATORS_PER_COMMITTEE], &proof[..]);
    let merge = [vec![best], vec![child; MAX_PROOFS - 1]].concat();
    let shapes = [
        (vec![best], vec![(&claims[0], &signature); MAX_SIGNATURES]),
        (vec![child; MAX_PROOFS], vec![]),
        (merge, vec![]),
    ];
    let lens = shapes.map(|(proofs, signatures)| {
        AggregateRequest { log_inv_rate: 2, proofs, signatures, output: None }.body().len()
    });
    assert!(lens.iter().all(|&len| len <= MAX_REQUEST_LEN), "{lens:?}");
    assert_eq!(lens[2], MAX_REQUEST_LEN, "a merge on the largest best proof");
}

#[test]
#[should_panic(expected = "shorter than its slice")]
fn a_slice_longer_than_the_request_is_a_bug() {
    let request =
        AggregateRequest { log_inv_rate: 2, proofs: vec![], signatures: vec![], output: None };
    request.write(&mut vec![0; request.len() + 1]);
}

#[test]
fn a_good_response_decodes() {
    let body = AggregateResponse::encode(&[claim(1), claim(2)], b"proof");
    let AggregateResponse { claims, proof } = AggregateResponse::decode(&body).unwrap();
    assert_eq!(claims, [claim(1), claim(2)]);
    assert_eq!(proof, b"proof");
}

#[test]
fn every_malformed_response_is_refused() {
    let good = AggregateResponse::encode(&[claim(1), claim(2)], b"proof");
    assert!(AggregateResponse::decode(&[]).is_err());
    assert!(AggregateResponse::decode(&good[..good.len() - 1]).is_err(), "truncated");
    assert!(AggregateResponse::decode(&[good.clone(), vec![0]].concat()).is_err(), "trailing");
    assert!(
        AggregateResponse::decode(&AggregateResponse::encode(&[claim(2), claim(1)], b"p")).is_err(),
        "unsorted"
    );
    assert!(
        AggregateResponse::decode(&AggregateResponse::encode(&[claim(1), claim(1)], b"p")).is_err(),
        "repeated"
    );
    let many: Vec<Claim> = (0..=MAX_PROOF_CLAIMS).map(numbered).collect();
    assert!(
        AggregateResponse::decode(&AggregateResponse::encode(&many, b"p")).is_err(),
        "too many"
    );
    assert!(AggregateResponse::decode(&AggregateResponse::encode(&many[1..], b"p")).is_ok());

    let mut sphincs = good.clone();
    sphincs[1 + 8 + 8 + 128] = 1;
    assert!(AggregateResponse::decode(&sphincs).is_err(), "leanSPHINCS claims");
    let mut da = good.clone();
    da[1 + 8 + 8 + 128 + 8] = 1;
    assert!(AggregateResponse::decode(&da).is_err(), "DA commitment");

    let mut huge_count = good.clone();
    huge_count[9..17].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(AggregateResponse::decode(&huge_count).is_err(), "count beyond the bytes present");
}

#[test]
fn a_rejection_is_an_error() {
    let mut body = vec![1];
    body.extend(le(3));
    body.extend(b"bad");
    assert_eq!(AggregateResponse::decode(&body), Err("rejected by the leanvm prover"));
}
