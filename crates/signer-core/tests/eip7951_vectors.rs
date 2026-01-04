//! EIP-7951 P256VERIFY precompile test vectors.
//!
//! These test vectors are from the official EIP-7951 specification,
//! originally sourced from the Wycheproof project.

// Silence unused crate dependency warnings for test binary
use alloy_primitives as _;
use alloy_rlp as _;
use des as _;
use p256 as _;
use pcsc as _;
use thiserror as _;

use serde::Deserialize;
use yubikey_evm_signer_core::crypto::p256_verify;

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
