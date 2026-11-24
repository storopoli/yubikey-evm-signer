//! EIP-7951 P256VERIFY precompile test vectors.
//!
//! These test vectors are from the official EIP-7951 specification,
//! originally sourced from the Wycheproof project.

// Silence unused crate dependency warnings for test binary
use aes as _;
use alloy_primitives as _;
use alloy_rlp as _;
use des as _;
use flate2 as _;
use getrandom as _;
#[cfg(feature = "pcsc")]
use pcsc as _;
use rpassword as _;
use subtle as _;
use thiserror as _;
use zeroize as _;

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::{AffinePoint, ProjectivePoint, Scalar, Sec1Point};
use serde::Deserialize;
use yubikey_evm_signer_core::crypto::p256_verify;

/// The NIST P-256 field prime `p`, big-endian.
const P256_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

#[derive(Deserialize)]
struct TestVector {
    #[serde(rename = "Input")]
    input: String,
    #[serde(rename = "Expected")]
    expected: String,
    #[serde(rename = "Name")]
    name: String,
}

#[test]
fn test_eip7951_vectors() {
    let json_data = include_str!("eip7951_test_vectors.json");
    let vectors: Vec<TestVector> =
        serde_json::from_str(json_data).expect("Failed to parse test vectors JSON");

    let mut passed = 0;
    let mut failed = 0;

    for vector in &vectors {
        let input = hex::decode(&vector.input).expect("Failed to decode input hex");
        let result = p256_verify(&input);
        let expected_valid = !vector.expected.is_empty();

        if result == expected_valid {
            passed += 1;
        } else {
            failed += 1;
            eprintln!(
                "FAILED: {} - expected {}, got {}",
                vector.name, expected_valid, result
            );
        }
    }

    eprintln!("\nTest results: {passed} passed, {failed} failed");
    assert_eq!(failed, 0, "Some test vectors failed");
}

/// Loads the official vectors as `(input bytes, expected validity)`.
fn load_vectors() -> Vec<(Vec<u8>, bool)> {
    let json_data = include_str!("eip7951_test_vectors.json");
    let vectors: Vec<TestVector> =
        serde_json::from_str(json_data).expect("Failed to parse test vectors JSON");
    vectors
        .iter()
        .map(|v| {
            (
                hex::decode(&v.input).expect("Failed to decode input hex"),
                !v.expected.is_empty(),
            )
        })
        .collect()
}

/// Adds two 32-byte big-endian integers, returning `None` on overflow past 2^256.
fn add_be(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    (carry == 0).then_some(out)
}

#[test]
fn eip7951_rejects_wrong_length_inputs() {
    let vectors = load_vectors();
    assert!(vectors.iter().all(|(input, _)| input.len() == 160));
    let (valid, _) = vectors
        .iter()
        .find(|(_, expected)| *expected)
        .expect("at least one valid vector");
    assert!(p256_verify(valid));

    let mut long_161 = valid.clone();
    long_161.push(0);
    let mut long_192 = valid.clone();
    long_192.extend_from_slice(&[0u8; 32]);
    let mut prefixed_161 = vec![0u8];
    prefixed_161.extend_from_slice(valid);

    for input in [
        Vec::new(),
        valid[..159].to_vec(),
        valid[1..].to_vec(),
        long_161,
        prefixed_161,
        long_192,
    ] {
        assert!(!p256_verify(&input), "accepted {}-byte input", input.len());
    }
}

#[test]
fn eip7951_rejects_non_canonical_public_key_coordinates() {
    // Find a curve point Q with a small x-coordinate, so that x + p still fits in
    // 32 bytes and is a non-canonical encoding of the same field element.
    let q = (0u8..=255)
        .find_map(|x| {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[32] = x;
            let sec1 = Sec1Point::from_bytes(compressed).ok()?;
            AffinePoint::from_sec1_point(&sec1).into_option()
        })
        .expect("a small-x point exists");
    let q_sec1 = q.to_sec1_point(false);
    let qx: [u8; 32] = q_sec1.as_bytes()[1..33].try_into().unwrap();
    let qy: [u8; 32] = q_sec1.as_bytes()[33..65].try_into().unwrap();

    // Build a valid (hash, r, s) for Q without its private key: pick a, b, set
    // R = a*G + b*Q, r = R.x mod n, s = r / b, hash = a * s. Then u1 = a, u2 = b.
    let a = Scalar::from(3u64);
    let b = Scalar::from(5u64);
    let r_point = (ProjectivePoint::GENERATOR * a + ProjectivePoint::from(q) * b).to_affine();
    let r = <Scalar as Reduce<p256::U256>>::reduce(&p256::U256::from_be_slice(&r_point.x()));
    let s = r * b.invert().unwrap();
    let hash = a * s;

    let input = |x: &[u8; 32], y: &[u8; 32]| {
        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash.to_repr());
        input.extend_from_slice(&r.to_repr());
        input.extend_from_slice(&s.to_repr());
        input.extend_from_slice(x);
        input.extend_from_slice(y);
        input
    };

    // Canonical coordinates verify
    assert!(p256_verify(&input(&qx, &qy)));

    // qx + p encodes the same field element but is >= p and must be rejected
    let qx_plus_p = add_be(&qx, &P256_P).expect("small x leaves room for x + p");
    assert!(!p256_verify(&input(&qx_plus_p, &qy)));

    // qx or qy equal to p or 2^256 - 1 (both >= p) must be rejected
    for out_of_range in [P256_P, [0xFF; 32]] {
        assert!(!p256_verify(&input(&out_of_range, &qy)));
        assert!(!p256_verify(&input(&qx, &out_of_range)));
    }
}
