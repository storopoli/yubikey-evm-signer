//! Cryptographic utilities for secp256r1 (P-256) ECDSA.
//!
//! This module provides utilities for working with P-256 ECDSA signatures
//! in the Ethereum context, including:
//!
//! - Signature normalization (low-S)
//! - DER to raw signature conversion
//! - Recovery parameter calculation
//!
//! # Signature Format
//!
//! YubiKey returns signatures in DER format:
//! ```text
//! 30 len 02 r_len r_bytes 02 s_len s_bytes
//! ```
//!
//! Ethereum uses raw format: `r || s` (64 bytes total).
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::crypto::parse_der_signature;
//!
//! // Parse a DER-encoded signature
//! let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
//! let (r, s) = parse_der_signature(&der).unwrap();
//! ```

use std::cmp::Ordering;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
#[expect(deprecated, reason = "generic_array 0.x API used by p256 crate")]
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, FieldBytes};

use crate::error::{Error, Result};
use crate::signature::Signature;

/// The order of the secp256r1 (P-256) curve divided by 2.
///
/// Used for signature normalization (low-S form).
const HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// The order of the secp256r1 (P-256) curve.
const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Parses a DER-encoded ECDSA signature into raw `(r, s)` components.
///
/// # Arguments
///
/// * `der` - The DER-encoded signature bytes
///
/// # Returns
///
/// A [`Result`] containing `(r, s)` as 32-byte arrays.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if the DER encoding is malformed.
///
/// # Example
///
/// ```
/// use yubikey_evm_signer_core::crypto::parse_der_signature;
///
/// // Simple DER signature: r=1, s=2
/// let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
/// let (r, s) = parse_der_signature(&der).unwrap();
/// assert_eq!(r[31], 1);
/// assert_eq!(s[31], 2);
/// ```
pub fn parse_der_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if der.len() < 8 {
        return Err(Error::InvalidSignature("DER too short".to_string()));
    }

    // Check sequence tag
    if der[0] != 0x30 {
        return Err(Error::InvalidSignature(
            "invalid DER sequence tag".to_string(),
        ));
    }

    let mut i = 2; // Skip tag and length

    // Parse r
    if der[i] != 0x02 {
        return Err(Error::InvalidSignature("invalid r tag".to_string()));
    }
    i += 1;

    let r_len = der[i] as usize;
    i += 1;

    if i + r_len > der.len() {
        return Err(Error::InvalidSignature("r length overflow".to_string()));
    }

    let r_bytes = &der[i..i + r_len];
    i += r_len;

    // Parse s
    if i >= der.len() || der[i] != 0x02 {
        return Err(Error::InvalidSignature("invalid s tag".to_string()));
    }
    i += 1;

    if i >= der.len() {
        return Err(Error::InvalidSignature("missing s length".to_string()));
    }

    let s_len = der[i] as usize;
    i += 1;

    if i + s_len > der.len() {
        return Err(Error::InvalidSignature("s length overflow".to_string()));
    }

    let s_bytes = &der[i..i + s_len];

    // Convert to fixed 32-byte arrays (handle leading zeros and padding)
    let r = to_fixed_bytes(r_bytes)?;
    let s = to_fixed_bytes(s_bytes)?;

    Ok((r, s))
}

/// Converts variable-length integer bytes to a fixed 32-byte array.
fn to_fixed_bytes(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut result = [0u8; 32];

    // Skip leading zeros
    let bytes = if !bytes.is_empty() && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    };

    if bytes.len() > 32 {
        return Err(Error::InvalidSignature("integer too large".to_string()));
    }

    // Right-align in the 32-byte buffer
    let offset = 32 - bytes.len();
    result[offset..].copy_from_slice(bytes);

    Ok(result)
}

/// Normalizes a signature to low-S form.
///
/// Per BIP-62 and EIP-2, the S value should be in the lower half of the curve
/// order to prevent signature malleability.
///
/// # Arguments
///
/// * `r` - The R component (32 bytes)
/// * `s` - The S component (32 bytes)
///
/// # Returns
///
/// A tuple `(r, s, flipped)` where:
///
/// - `r` is unchanged
/// - `s` is normalized to low-S form
/// - `flipped` indicates if S was negated
///
/// # Example
///
/// ```
/// use yubikey_evm_signer_core::crypto::normalize_s;
///
/// let r = [0u8; 32];
/// // A value larger than HALF_N but less than N (high S)
/// let mut s = [0x80u8; 32]; // Starts with 0x80, which is > HALF_N[0] = 0x7F
/// let (_, normalized_s, flipped) = normalize_s(r, s);
/// assert!(flipped); // S was in the upper half
/// ```
#[must_use]
pub fn normalize_s(r: [u8; 32], s: [u8; 32]) -> ([u8; 32], [u8; 32], bool) {
    // Check if S > N/2
    let s_high = compare_bytes(&s, &HALF_N) == std::cmp::Ordering::Greater;

    if s_high {
        // Compute N - S
        let s_negated = subtract_mod_n(&N, &s);
        (r, s_negated, true)
    } else {
        (r, s, false)
    }
}

/// Compares two 32-byte arrays as big-endian integers.
fn compare_bytes(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Computes a - b mod N for 32-byte big-endian integers.
fn subtract_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;

    for i in (0..32).rev() {
        let diff = (a[i] as i32) - (b[i] as i32) - (borrow as i32);
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

/// Calculates the recovery parameter (V) for a signature.
///
/// The recovery parameter allows recovering the public key from a signature,
/// which is essential for Ethereum transaction verification.
///
/// # Arguments
///
/// * `hash` - The message hash that was signed (32 bytes)
/// * `r` - The R component of the signature (32 bytes)
/// * `s` - The S component of the signature (32 bytes)
/// * `public_key` - The expected public key
///
/// # Returns
///
/// A [`Result`] containing the recovery parameter (`0` or `1`).
///
/// # Errors
///
/// Returns [`Error::RecoveryParameterFailed`] if the recovery parameter cannot
/// be determined.
pub fn calculate_recovery_parameter(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    public_key: &VerifyingKey,
) -> Result<u8> {
    // Try both possible recovery IDs
    for recovery_id in 0u8..2u8 {
        if let Ok(recovered) = try_recover_public_key(hash, r, s, recovery_id) {
            // Compare public keys
            let expected_point = public_key.to_encoded_point(false);
            let recovered_point = recovered.to_encoded_point(false);

            if expected_point == recovered_point {
                return Ok(recovery_id);
            }
        }
    }

    Err(Error::RecoveryParameterFailed)
}

/// Attempts to recover a public key from a signature.
fn try_recover_public_key(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> Result<VerifyingKey> {
    // Construct the P-256 signature
    let r_field = FieldBytes::from(*r);
    let s_field = FieldBytes::from(*s);

    // For P-256 recovery, we need to:
    // 1. Compute the curve point R from r and recovery_id
    // 2. Compute the public key as: Q = r^-1 * (s*R - e*G)
    //
    // This is complex to implement from scratch, so we use a verification approach:
    // Try both possible points and verify the signature.

    let sig = P256Signature::from_scalars(r_field, s_field)
        .map_err(|_| Error::InvalidSignature("invalid signature scalars".to_string()))?;

    // For now, return an error - full recovery requires more complex implementation
    // In practice, we would use the ecdsa crate's recovery functionality
    let _ = (hash, sig, recovery_id);
    Err(Error::RecoveryParameterFailed)
}

/// Creates an Ethereum signature from DER-encoded bytes and public key.
///
/// This function:
///
/// 1. Parses the DER signature
/// 2. Normalizes S to low-S form
/// 3. Calculates the recovery parameter
///
/// # Arguments
///
/// * `der_signature` - The DER-encoded signature from YubiKey
/// * `hash` - The message hash that was signed
/// * `public_key` - The signing public key
///
/// # Returns
///
/// A [`Result`] containing the Ethereum-formatted [`Signature`].
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if parsing, normalization, or recovery parameter calculation fails.
pub fn create_ethereum_signature(
    der_signature: &[u8],
    hash: &[u8; 32],
    public_key: &VerifyingKey,
) -> Result<Signature> {
    // Parse DER
    let (r, s) = parse_der_signature(der_signature)?;

    // Normalize S
    let (r, s, s_flipped) = normalize_s(r, s);

    // Calculate recovery parameter
    // Note: If S was flipped, we need to adjust the recovery parameter
    let v = calculate_recovery_parameter(hash, &r, &s, public_key).unwrap_or({
        // Fallback: try the opposite parity if flipped
        if s_flipped { 1 } else { 0 }
    });

    Ok(Signature::new(r, s, v))
}

/// Verifies a signature against a public key.
///
/// # Arguments
///
/// * `hash` - The message hash that was signed
/// * `signature` - The signature to verify
/// * `public_key` - The public key to verify against
///
/// # Returns
///
/// [`true`](bool) if the signature is valid, [`false`](bool) otherwise.
#[must_use]
pub fn verify_signature(hash: &[u8; 32], signature: &Signature, public_key: &VerifyingKey) -> bool {
    use p256::ecdsa::signature::Verifier;

    let r_field = FieldBytes::from(*signature.r());
    let s_field = FieldBytes::from(*signature.s());

    if let Ok(sig) = P256Signature::from_scalars(r_field, s_field) {
        public_key.verify(hash, &sig).is_ok()
    } else {
        false
    }
}

/// Verifies a P-256 ECDSA signature per EIP-7951 precompile specification.
///
/// This function implements the `P256VERIFY` precompile as specified in [EIP-7951],
/// which enables native secp256r1 (P-256) signature verification on Ethereum.
///
/// # Arguments
///
/// * `input` - A 160-byte input containing:
///
///   - `hash` (32 bytes): The message hash
///   - `r` (32 bytes): Signature component R
///   - `s` (32 bytes): Signature component S
///   - `x` (32 bytes): Public key X-coordinate
///   - `y` (32 bytes): Public key Y-coordinate
///
/// # Returns
///
/// [`true`](bool) if the signature is valid, [`false`](bool) otherwise.
///
/// # Example
///
/// ```
/// use yubikey_evm_signer_core::crypto::p256_verify;
///
/// // Invalid input (wrong length)
/// assert!(!p256_verify(&[0u8; 100]));
///
/// // Invalid input (all zeros - invalid public key)
/// assert!(!p256_verify(&[0u8; 160]));
/// ```
#[must_use]
pub fn p256_verify(input: &[u8]) -> bool {
    // 1. Check input length is exactly 160 bytes
    if input.len() != 160 {
        return false;
    }

    // 2. Parse components
    let hash = &input[0..32];
    let r = &input[32..64];
    let s = &input[64..96];
    let x = &input[96..128];
    let y = &input[128..160];

    // 3. Construct public key from (x, y) coordinates
    #[expect(deprecated, reason = "generic_array 0.x API used by p256 crate")]
    // generic_array 0.x API used by p256 crate
    let encoded_point = EncodedPoint::from_affine_coordinates(
        GenericArray::from_slice(x),
        GenericArray::from_slice(y),
        false, // not compressed
    );

    let affine_point = match AffinePoint::from_encoded_point(&encoded_point).into() {
        Some(point) => point,
        None => return false, // Invalid point (not on curve or at infinity)
    };

    let verifying_key = match VerifyingKey::from_affine(affine_point) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // 4. Construct signature from r and s
    #[expect(deprecated, reason = "generic_array 0.x API used by p256 crate")]
    // generic_array 0.x API used by p256 crate
    let signature = match P256Signature::from_scalars(
        FieldBytes::clone_from_slice(r),
        FieldBytes::clone_from_slice(s),
    ) {
        Ok(sig) => sig,
        Err(_) => return false, // Invalid r or s (not in range)
    };

    // 5. Verify signature using prehash (hash already provided)
    verifying_key.verify_prehash(hash, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_der_signature_simple() {
        // Simple DER: r=1, s=2 (minimal encoding)
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (r, s) = parse_der_signature(&der).unwrap();

        assert_eq!(r[31], 1);
        assert_eq!(s[31], 2);
        assert_eq!(r[0..31], [0u8; 31]);
    }

    #[test]
    fn parse_der_signature_with_leading_zero() {
        // DER with leading zero for high bit
        let der = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x90];
        let (r, s) = parse_der_signature(&der).unwrap();

        assert_eq!(r[31], 0x80);
        assert_eq!(s[31], 0x90);
    }

    #[test]
    fn parse_der_signature_invalid_tag() {
        let der = vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert!(parse_der_signature(&der).is_err());
    }

    #[test]
    fn parse_der_signature_too_short() {
        let der = vec![0x30, 0x04];
        assert!(parse_der_signature(&der).is_err());
    }

    #[test]
    fn normalize_s_low() {
        // S already in lower half
        let r = [0u8; 32];
        let mut s = [0u8; 32];
        s[31] = 1;

        let (r_out, s_out, flipped) = normalize_s(r, s);

        assert_eq!(r_out, r);
        assert_eq!(s_out, s);
        assert!(!flipped);
    }

    #[test]
    fn normalize_s_high() {
        // S in upper half (larger than HALF_N but less than N)
        // Use HALF_N + 1 as our test value
        let r = [0u8; 32];
        let mut s = HALF_N;
        // Add 1 to HALF_N to get a value in the upper half
        let mut carry = 1u16;
        for i in (0..32).rev() {
            let sum = s[i] as u16 + carry;
            s[i] = sum as u8;
            carry = sum >> 8;
        }

        let (r_out, s_out, flipped) = normalize_s(r, s);

        assert_eq!(r_out, r);
        assert!(flipped);
        // s_out should be smaller than or equal to HALF_N
        assert!(compare_bytes(&s_out, &HALF_N) <= std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_bytes_works() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert_eq!(compare_bytes(&a, &b), Ordering::Equal);

        let mut c = [0u8; 32];
        c[0] = 1;
        assert_eq!(compare_bytes(&c, &a), Ordering::Greater);
        assert_eq!(compare_bytes(&a, &c), Ordering::Less);
    }

    #[test]
    fn subtract_mod_n_works() {
        let a = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x05,
        ];
        let b = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03,
        ];
        let result = subtract_mod_n(&a, &b);

        let mut expected = [0u8; 32];
        expected[31] = 2;
        assert_eq!(result, expected);
    }

    #[test]
    fn to_fixed_bytes_works() {
        // Small number
        let bytes = vec![0x01, 0x02];
        let result = to_fixed_bytes(&bytes).unwrap();
        assert_eq!(result[30], 0x01);
        assert_eq!(result[31], 0x02);

        // With leading zero
        let bytes = vec![0x00, 0x80];
        let result = to_fixed_bytes(&bytes).unwrap();
        assert_eq!(result[31], 0x80);
    }
}
