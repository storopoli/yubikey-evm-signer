//! Cryptographic utilities for secp256r1 (P-256) ECDSA and EIP-191 hashing.
//!
//! This module provides utilities for working with P-256 ECDSA signatures
//! in the Ethereum context, including:
//!
//! - Signature normalization (low-S)
//! - DER to raw signature conversion
//! - Public key recovery and recovery parameter calculation
//! - Prehash signature verification (EIP-7951 compatible)
//! - EIP-191 personal message hashing
//!
//! # Signature Format
//!
//! YubiKey returns signatures in ASN.1 DER format:
//! ```text
//! 30 len 02 r_len r_bytes 02 s_len s_bytes
//! ```
//!
//! Ethereum uses raw format: `r || s` (64 bytes total), plus recovery ID `v`.
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::crypto::parse_der_signature;
//!
//! // Parse a DER-encoded signature
//! let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
//! let (r, s) = parse_der_signature(&der).unwrap();
//! assert_eq!(r[31], 1);
//! assert_eq!(s[31], 2);
//! ```

use alloy_primitives::{B256, keccak256};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::scalar::IsHigh;
use p256::elliptic_curve::sec1::FromSec1Point;
use p256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, Sec1Point};

use crate::error::{Error, Result};
use crate::signature::Signature;

/// Computes the [EIP-191] personal message hash (`personal_sign`).
///
/// Formats the message as `"\x19Ethereum Signed Message:\n" || byte_len || message`
/// and returns its Keccak-256 digest.
///
/// # Arguments
///
/// * `message` - The raw message bytes to hash
///
/// # Returns
///
/// The 32-byte Keccak-256 hash ready for signing.
///
/// # Example
///
/// ```
/// use yubikey_evm_signer_core::crypto::eip191_hash;
///
/// let hash = eip191_hash(b"Hello, Ethereum!");
/// assert!(!hash.is_zero());
/// ```
///
/// [EIP-191]: https://eips.ethereum.org/EIPS/eip-191
#[must_use]
pub fn eip191_hash(message: &[u8]) -> B256 {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = Vec::with_capacity(prefix.len() + message.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(message);
    keccak256(&data)
}

/// Parses a canonical ASN.1 DER-encoded ECDSA signature into raw `(r, s)` components.
///
/// Strictly validates canonical DER structure, rejects trailing bytes, and ensures
/// both scalars satisfy `1 <= r < N` and `1 <= s < N` for NIST P-256.
///
/// # Arguments
///
/// * `der` - The DER-encoded signature bytes
///
/// # Returns
///
/// A [`Result`] containing `(r, s)` as 32-byte big-endian arrays.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if the DER encoding is malformed,
/// non-canonical, contains trailing bytes, or has out-of-range scalars.
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
    let sig = P256Signature::from_der(der)
        .map_err(|_| Error::InvalidSignature("invalid ASN.1 DER signature".to_string()))?;

    let (r, s) = sig.split_bytes();
    Ok((r.into(), s.into()))
}

/// Normalizes a P-256 signature scalar `s` to low-S form.
///
/// Per BIP-62 and EIP-2, the `s` value must be in the lower half of the curve
/// order (`1 <= s <= N / 2`) to prevent signature malleability.
///
/// # Arguments
///
/// * `s` - The 32-byte big-endian S component
///
/// # Returns
///
/// A [`Result`] containing `(normalized_s, flipped)` where `flipped` is `true`
/// if `s` was replaced by `N - s`.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if `s == 0` or `s >= N`.
///
/// # Example
///
/// ```
/// use yubikey_evm_signer_core::crypto::normalize_s;
///
/// // A value larger than N/2 but less than N (high S)
/// let s = [0x80u8; 32];
/// let (normalized_s, flipped) = normalize_s(s).unwrap();
/// assert!(flipped);
/// assert_ne!(normalized_s, s);
/// ```
pub fn normalize_s(s: [u8; 32]) -> Result<([u8; 32], bool)> {
    let scalar = NonZeroScalar::from_repr(FieldBytes::from(s))
        .into_option()
        .ok_or_else(|| {
            Error::InvalidSignature("signature scalar s must be in range 1..N".to_string())
        })?;

    if bool::from(scalar.is_high()) {
        let negated = -scalar;
        Ok((negated.to_repr().into(), true))
    } else {
        Ok((s, false))
    }
}

/// Recovers a P-256 verifying key from a prehashed digest, signature scalars, and recovery ID.
///
/// Computes `Q = r^-1 * (s * R - z * G)` on NIST P-256 where `R` is the curve point
/// with x-coordinate `r` and y-parity `recovery_id & 1`.
///
/// Only `R.x = r` is tried. If the signer's nonce point had `R.x` in `[n, p)` (so that
/// `r = R.x - n`), recovery fails closed with [`Error::RecoveryParameterFailed`]
/// instead of trying `R.x = r + n`. For honestly generated nonces this happens with
/// probability about `2^-130`.
///
/// # Arguments
///
/// * `hash` - The 32-byte prehashed message digest
/// * `r` - The 32-byte big-endian R scalar
/// * `s` - The 32-byte big-endian S scalar
/// * `recovery_id` - The recovery parameter (`0` for even Y, `1` for odd Y)
///
/// # Returns
///
/// A [`Result`] containing the recovered [`VerifyingKey`].
///
/// # Errors
///
/// - [`Error::RecoveryParameterFailed`] if `recovery_id >= 2`, `R` cannot be decompressed,
///   or the recovered point is at infinity
/// - [`Error::InvalidSignature`] if `r` or `s` is zero or `>= N`
pub fn try_recover_public_key(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> Result<VerifyingKey> {
    if recovery_id >= 2 {
        return Err(Error::RecoveryParameterFailed);
    }

    let sig = P256Signature::from_scalars(FieldBytes::from(*r), FieldBytes::from(*s))
        .map_err(|_| Error::InvalidSignature("signature scalars must be in range 1..N".into()))?;

    // Decompress R from x = r and y-parity = recovery_id & 1
    let mut compressed_r = [0u8; 33];
    compressed_r[0] = 0x02 | (recovery_id & 1);
    compressed_r[1..].copy_from_slice(r);

    let sec1_r =
        Sec1Point::from_bytes(&compressed_r).map_err(|_| Error::RecoveryParameterFailed)?;
    let r_affine = AffinePoint::from_sec1_point(&sec1_r)
        .into_option()
        .ok_or(Error::RecoveryParameterFailed)?;
    let r_point = ProjectivePoint::from(r_affine);

    // Compute Q = r^-1 * (s * R - z * G)
    let (r_scalar, s_scalar) = sig.split_scalars();
    let z = <Scalar as Reduce<p256::U256>>::reduce(&p256::U256::from_be_slice(hash));
    let r_inv = r_scalar
        .invert()
        .into_option()
        .ok_or(Error::RecoveryParameterFailed)?;
    let u1 = -(r_inv * z);
    let u2 = r_inv * *s_scalar;

    let q_point = (ProjectivePoint::GENERATOR * u1) + (r_point * u2);
    VerifyingKey::from_affine(q_point.to_affine()).map_err(|_| Error::RecoveryParameterFailed)
}

/// Calculates the recovery parameter (`v`) for a signature and expected public key.
///
/// Tests recovery IDs `0` and `1` and returns the one that recovers `public_key`.
///
/// # Arguments
///
/// * `hash` - The message hash that was signed (32 bytes)
/// * `r` - The R component of the signature (32 bytes)
/// * `s` - The S component of the signature (32 bytes)
/// * `public_key` - The expected signing public key
///
/// # Returns
///
/// A [`Result`] containing the recovery parameter (`0` or `1`).
///
/// # Errors
///
/// - [`Error::InvalidSignature`] if `r` or `s` is zero or `>= N`
/// - [`Error::RecoveryParameterFailed`] if neither recovery ID recovers `public_key`
pub fn calculate_recovery_parameter(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    public_key: &VerifyingKey,
) -> Result<u8> {
    // Validate scalars upfront so callers receive InvalidSignature for bad scalars
    let _ = P256Signature::from_scalars(FieldBytes::from(*r), FieldBytes::from(*s))
        .map_err(|_| Error::InvalidSignature("signature scalars must be in range 1..N".into()))?;

    let expected_point = public_key.to_sec1_point(false);

    for recovery_id in 0u8..2u8 {
        if let Ok(recovered) = try_recover_public_key(hash, r, s, recovery_id)
            && recovered.to_sec1_point(false) == expected_point
        {
            return Ok(recovery_id);
        }
    }

    Err(Error::RecoveryParameterFailed)
}

/// Creates an Ethereum signature from DER-encoded bytes and public key.
///
/// This function:
///
/// 1. Parses and validates the canonical DER signature
/// 2. Normalizes `s` to low-S form
/// 3. Calculates and verifies the recovery parameter (`0` or `1`)
///
/// # Arguments
///
/// * `der_signature` - The DER-encoded signature from YubiKey
/// * `hash` - The 32-byte message hash that was signed
/// * `public_key` - The signing public key
///
/// # Returns
///
/// A [`Result`] containing the Ethereum-formatted [`Signature`].
///
/// # Errors
///
/// - [`Error::InvalidSignature`] if DER parsing or scalar validation fails
/// - [`Error::RecoveryParameterFailed`] if the signature does not match `public_key`
pub fn create_ethereum_signature(
    der_signature: &[u8],
    hash: &[u8; 32],
    public_key: &VerifyingKey,
) -> Result<Signature> {
    let (r, s) = parse_der_signature(der_signature)?;
    let (s, _) = normalize_s(s)?;
    let v = calculate_recovery_parameter(hash, &r, &s, public_key)?;

    Signature::new(r, s, v)
}

/// Verifies a P-256 signature against a prehashed 32-byte digest and public key.
///
/// Uses raw prehash verification (matching [EIP-7951] and YubiKey PIV signing)
/// without applying an additional SHA-256 hash.
///
/// # Arguments
///
/// * `hash` - The 32-byte prehashed message digest
/// * `signature` - The signature to verify
/// * `public_key` - The public key to verify against
///
/// # Returns
///
/// [`true`](bool) if the signature is valid, [`false`](bool) otherwise.
///
/// [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951
#[must_use]
pub fn verify_signature(hash: &[u8; 32], signature: &Signature, public_key: &VerifyingKey) -> bool {
    let r_field = FieldBytes::from(*signature.r());
    let s_field = FieldBytes::from(*signature.s());

    if let Ok(sig) = P256Signature::from_scalars(r_field, s_field) {
        public_key.verify_prehash(hash, &sig).is_ok()
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
///
/// [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951
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
    let (Ok(x_bytes), Ok(y_bytes)) = (FieldBytes::try_from(x), FieldBytes::try_from(y)) else {
        return false;
    };
    let encoded_point = Sec1Point::from_affine_coordinates(
        &x_bytes, &y_bytes, false, // not compressed
    );

    let Some(affine_point) = AffinePoint::from_sec1_point(&encoded_point).into_option() else {
        return false; // Invalid point (not on curve or at infinity)
    };

    let Ok(verifying_key) = VerifyingKey::from_affine(affine_point) else {
        return false;
    };

    // 4. Construct signature from r and s
    let (Ok(r_bytes), Ok(s_bytes)) = (FieldBytes::try_from(r), FieldBytes::try_from(s)) else {
        return false;
    };
    let Ok(signature) = P256Signature::from_scalars(r_bytes, s_bytes) else {
        return false; // Invalid r or s (not in range)
    };

    // 5. Verify signature using prehash (hash already provided)
    verifying_key.verify_prehash(hash, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    use super::*;

    /// The order N of NIST P-256.
    const P256_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    /// Half the order N/2 of NIST P-256.
    const P256_HALF_N: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31,
        0x92, 0xA8,
    ];

    #[test]
    fn parse_der_signature_simple() {
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (r, s) = parse_der_signature(&der).unwrap();

        assert_eq!(r[31], 1);
        assert_eq!(s[31], 2);
        assert_eq!(r[0..31], [0u8; 31]);
    }

    #[test]
    fn parse_der_signature_with_leading_zero() {
        let der = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x90];
        let (r, s) = parse_der_signature(&der).unwrap();

        assert_eq!(r[31], 0x80);
        assert_eq!(s[31], 0x90);
    }

    #[test]
    fn parse_der_signature_rejects_malformed() {
        // Invalid tag
        assert!(parse_der_signature(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).is_err());
        // Too short
        assert!(parse_der_signature(&[0x30, 0x04]).is_err());
        // Trailing bytes
        assert!(
            parse_der_signature(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00]).is_err()
        );
        // Non-canonical leading zero when high bit is not set
        assert!(
            parse_der_signature(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02]).is_err()
        );
        // Zero scalar r = 0
        assert!(parse_der_signature(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x02]).is_err());
        // Zero scalar s = 0
        assert!(parse_der_signature(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00]).is_err());
        // Negative integer (high bit set without 0x00 prefix)
        assert!(parse_der_signature(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x02]).is_err());
        // Scalar >= N (r = N)
        let mut der_n = vec![0x30, 0x28, 0x02, 0x21, 0x00];
        der_n.extend_from_slice(&P256_N);
        der_n.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert!(parse_der_signature(&der_n).is_err());
    }

    #[test]
    fn normalize_s_low() {
        let mut s = [0u8; 32];
        s[31] = 1;

        let (s_out, flipped) = normalize_s(s).unwrap();
        assert_eq!(s_out, s);
        assert!(!flipped);

        // HALF_N itself is still low-S
        let (half_out, half_flipped) = normalize_s(P256_HALF_N).unwrap();
        assert_eq!(half_out, P256_HALF_N);
        assert!(!half_flipped);
    }

    #[test]
    fn normalize_s_high() {
        // HALF_N + 1 is the smallest high-S value
        let mut s = P256_HALF_N;
        let mut carry = 1u16;
        for byte in s.iter_mut().rev() {
            let sum = u16::from(*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }

        let (s_out, flipped) = normalize_s(s).unwrap();
        assert!(flipped);
        // N - (HALF_N + 1) == HALF_N because N is odd
        assert_eq!(s_out, P256_HALF_N);
    }

    #[test]
    fn normalize_s_rejects_zero_and_out_of_range() {
        assert!(matches!(
            normalize_s([0u8; 32]),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            normalize_s(P256_N),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            normalize_s([0xFF; 32]),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn end_to_end_sign_recover_verify_and_eip7951() {
        let key_bytes =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();
        let signing_key =
            SigningKey::from_bytes(&FieldBytes::try_from(key_bytes.as_slice()).unwrap()).unwrap();
        let verifying_key = *signing_key.verifying_key();

        let other_key_bytes =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let other_verifying_key =
            *SigningKey::from_bytes(&FieldBytes::try_from(other_key_bytes.as_slice()).unwrap())
                .unwrap()
                .verifying_key();

        let mut saw_v0 = false;
        let mut saw_v1 = false;
        let mut saw_high_s = false;

        // Sign multiple messages to cover both v=0 and v=1 and high-S normalization
        for i in 0u32..32 {
            let hash: [u8; 32] = keccak256(format!("message-{i}")).into();
            let raw_sig: P256Signature = signing_key.sign_prehash(&hash).unwrap();
            let (_, raw_s) = raw_sig.split_bytes();
            let raw_s_arr: [u8; 32] = raw_s.into();
            if normalize_s(raw_s_arr).unwrap().1 {
                saw_high_s = true;
            }

            let der_sig = raw_sig.to_der();
            let eth_sig =
                create_ethereum_signature(der_sig.as_bytes(), &hash, &verifying_key).unwrap();

            match eth_sig.v() {
                0 => saw_v0 = true,
                1 => saw_v1 = true,
                other => panic!("unexpected v={other}"),
            }

            // Low-S check
            assert!(!normalize_s(*eth_sig.s()).unwrap().1);

            // Direct prehash verification must succeed for the real key and fail for wrong key
            assert!(verify_signature(&hash, &eth_sig, &verifying_key));
            assert!(!verify_signature(&hash, &eth_sig, &other_verifying_key));

            // Public key recovery must reproduce exact verifying key
            let recovered =
                try_recover_public_key(&hash, eth_sig.r(), eth_sig.s(), eth_sig.v()).unwrap();
            assert_eq!(
                recovered.to_sec1_point(false),
                verifying_key.to_sec1_point(false)
            );

            // EIP-7951 precompile verification must also succeed
            let pubkey_sec1 = verifying_key.to_sec1_point(false);
            let mut input = Vec::with_capacity(160);
            input.extend_from_slice(&hash);
            input.extend_from_slice(eth_sig.r());
            input.extend_from_slice(eth_sig.s());
            input.extend_from_slice(&pubkey_sec1.as_bytes()[1..65]);
            assert!(p256_verify(&input));

            // Wrong public key must return RecoveryParameterFailed (no fallback!)
            let wrong = create_ethereum_signature(der_sig.as_bytes(), &hash, &other_verifying_key);
            assert!(matches!(wrong, Err(Error::RecoveryParameterFailed)));
        }

        assert!(saw_v0, "expected to observe v=0 across test messages");
        assert!(saw_v1, "expected to observe v=1 across test messages");
        assert!(saw_high_s, "expected to observe high-S normalization");
    }

    #[test]
    fn try_recover_public_key_rejects_invalid_inputs() {
        let hash = [0x11u8; 32];
        let one = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };

        // recovery_id >= 2
        assert!(matches!(
            try_recover_public_key(&hash, &one, &one, 2),
            Err(Error::RecoveryParameterFailed)
        ));
        assert!(matches!(
            try_recover_public_key(&hash, &one, &one, 27),
            Err(Error::RecoveryParameterFailed)
        ));

        // Zero r or s
        assert!(matches!(
            try_recover_public_key(&hash, &[0u8; 32], &one, 0),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            try_recover_public_key(&hash, &one, &[0u8; 32], 0),
            Err(Error::InvalidSignature(_))
        ));

        // Out-of-range r or s (>= N)
        assert!(matches!(
            try_recover_public_key(&hash, &P256_N, &one, 0),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            try_recover_public_key(&hash, &one, &P256_N, 0),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn eip191_known_answer_vectors() {
        // Known-answer vector: keccak256("\x19Ethereum Signed Message:\n11hello world")
        let hash = eip191_hash(b"hello world");
        assert_eq!(
            hex::encode(hash),
            "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"
        );

        // Empty message: keccak256("\x19Ethereum Signed Message:\n0")
        let empty = eip191_hash(b"");
        assert_eq!(
            hex::encode(empty),
            "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
        );

        // Multi-byte UTF-8 message uses byte length (not char count)
        let utf8_msg = "🔥"; // 4 UTF-8 bytes
        let utf8_hash = eip191_hash(utf8_msg.as_bytes());
        let expected = keccak256(b"\x19Ethereum Signed Message:\n4\xF0\x9F\x94\xA5");
        assert_eq!(utf8_hash, expected);
    }
}
