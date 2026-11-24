//! Ethereum transaction types and signing payload generation.
//!
//! This module provides types for representing Ethereum transactions and
//! generating the hash that needs to be signed. It supports:
//!
//! - **EIP-155 Legacy Transactions**: Traditional transactions with chain ID replay protection
//! - **EIP-1559 Transactions**: Type 2 transactions with priority fees and max fees
//!
//! # Signing Flow
//!
//! 1. Create a transaction with the appropriate type
//! 2. Call [`Transaction::signing_hash`] to get the hash to sign
//! 3. Sign the hash with the YubiKey
//! 4. Create the signed transaction with [`Transaction::signed_rlp`]
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::{Transaction, Eip1559Transaction, Address};
//! use alloy_primitives::U256;
//!
//! let tx = Transaction::Eip1559(Eip1559Transaction {
//!     chain_id: 1,
//!     nonce: 0,
//!     max_priority_fee_per_gas: U256::from(1_000_000_000u64),
//!     max_fee_per_gas: U256::from(100_000_000_000u64),
//!     gas_limit: 21000,
//!     to: Some(Address::zero()),
//!     value: U256::from(1_000_000_000_000_000_000u128),
//!     data: vec![],
//!     access_list: vec![],
//! });
//!
//! let hash = tx.signing_hash().unwrap();
//! // Sign this hash with YubiKey...
//! ```

use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::{Encodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::error::{Error, Result};
use crate::signature::Signature;

/// Serde helper for transaction calldata (`Vec<u8>`).
///
/// Serializes as a `0x`-prefixed hex string (e.g., `"0x"` for empty data) and
/// deserializes both hex strings (`"0x..."`, `"0X..."`, or `""`) and JSON
/// arrays of byte values (`[0xde, 0xad]`) for backwards compatibility.
mod hex_or_bytes {
    use core::fmt;

    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexOrBytesVisitor;

        impl<'de> Visitor<'de> for HexOrBytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a hex string (e.g. \"0x...\") or an array of bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let stripped = v
                    .strip_prefix("0x")
                    .or_else(|| v.strip_prefix("0X"))
                    .unwrap_or(v);
                if stripped.is_empty() {
                    return Ok(Vec::new());
                }
                hex::decode(stripped).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(v.to_vec())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(HexOrBytesVisitor)
    }
}

/// Strict serde deserializer for [`U256`] amount fields.
///
/// Accepts only a JSON unsigned integer, a non-empty string of ASCII decimal digits,
/// or `0x`/`0X` followed by one or more ASCII hex digits. Everything else (signs,
/// whitespace, `_` separators, `0b`/`0o` prefixes, empty strings, floats) is
/// rejected. Serialization is left to [`U256`]'s own `Serialize` implementation.
pub(crate) mod strict_u256 {
    use core::fmt;

    use alloy_primitives::U256;
    use serde::Deserializer;
    use serde::de::{self, Visitor};

    /// Parses a decimal-digit string or a `0x`/`0X`-prefixed hex-digit string.
    pub(crate) fn parse(s: &str) -> Option<U256> {
        let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(hex) => (hex, 16),
            None => (s, 10),
        };
        let valid_digit = |b: u8| {
            if radix == 16 {
                b.is_ascii_hexdigit()
            } else {
                b.is_ascii_digit()
            }
        };
        if digits.is_empty() || !digits.bytes().all(valid_digit) {
            return None;
        }
        U256::from_str_radix(digits, radix).ok()
    }

    struct StrictU256Visitor;

    impl Visitor<'_> for StrictU256Visitor {
        type Value = U256;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(
                "an unsigned integer, a decimal digit string, or a 0x-prefixed hex string",
            )
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(U256::from(v))
        }

        fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(U256::from(v))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse(v).ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(v), &self))
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictU256Visitor)
    }

    /// Like [`deserialize`], for optional fields (`null` maps to `None`).
    pub(crate) fn deserialize_option<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionVisitor;

        impl<'de> Visitor<'de> for OptionVisitor {
            type Value = Option<U256>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null or an unsigned integer")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize(deserializer).map(Some)
            }
        }

        deserializer.deserialize_option(OptionVisitor)
    }
}

/// Deserializes a required, nullable recipient address.
///
/// Unlike serde's default handling of `Option` fields, a missing `to` key is an
/// error; only an explicit JSON `null` means contract creation.
fn deserialize_required_to<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<Address>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Address>::deserialize(deserializer)
}

/// An access list entry for EIP-2930/EIP-1559 transactions.
///
/// Access lists specify which addresses and storage keys will be accessed
/// during transaction execution, potentially reducing gas costs.
///
/// Unknown JSON keys are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable)]
#[serde(deny_unknown_fields)]
pub struct AccessListEntry {
    /// The address being accessed.
    pub address: alloy_primitives::Address,

    /// The storage keys being accessed at this address.
    pub storage_keys: Vec<B256>,
}

/// An EIP-155 legacy transaction.
///
/// This is the traditional Ethereum transaction format with chain ID
/// replay protection as specified in [EIP-155].
///
/// When deserialized from JSON, unknown keys are rejected and `to` is required
/// (use an explicit `null` for contract creation). `U256` amounts accept a JSON
/// unsigned integer, a decimal digit string, or a `0x`-prefixed hex string.
///
/// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyTransaction {
    /// The chain ID for replay protection.
    pub chain_id: u64,

    /// The transaction nonce.
    pub nonce: u64,

    /// The gas price in wei.
    #[serde(deserialize_with = "strict_u256::deserialize")]
    pub gas_price: U256,

    /// The gas limit.
    pub gas_limit: u64,

    /// The recipient address, or `None` for contract creation.
    ///
    /// Required in JSON; an explicit `null` means contract creation.
    #[serde(deserialize_with = "deserialize_required_to")]
    pub to: Option<Address>,

    /// The value to transfer in wei.
    #[serde(deserialize_with = "strict_u256::deserialize")]
    pub value: U256,

    /// The transaction input data.
    #[serde(default, alias = "input", with = "hex_or_bytes")]
    pub data: Vec<u8>,
}

impl LegacyTransaction {
    /// Generates the signing hash for this transaction.
    ///
    /// For EIP-155 transactions, the signing hash is:
    /// `keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the 32-byte hash to be signed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChainId`] if `chain_id` is `0` (no replay protection).
    pub fn signing_hash(&self) -> Result<B256> {
        if self.chain_id == 0 {
            return Err(Error::InvalidChainId(0));
        }

        let mut buf = Vec::new();

        // For EIP-155, we encode: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        encode_rlp_list(&mut buf, |buf| {
            self.nonce.encode(buf);
            encode_u256(&self.gas_price, buf);
            self.gas_limit.encode(buf);
            encode_optional_address(&self.to, buf);
            encode_u256(&self.value, buf);
            self.data.as_slice().encode(buf);
            self.chain_id.encode(buf);
            0u8.encode(buf);
            0u8.encode(buf);
        });

        Ok(keccak256(&buf))
    }

    /// Creates a signed transaction by combining this transaction with a signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature from signing the hash
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the RLP-encoded signed transaction bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChainId`] if `chain_id` is `0`.
    pub fn signed_rlp(&self, signature: &Signature) -> Result<Vec<u8>> {
        if self.chain_id == 0 {
            return Err(Error::InvalidChainId(0));
        }

        let mut buf = Vec::new();

        // Calculate v with EIP-155 in u128 so large chain IDs cannot overflow:
        // v = chain_id * 2 + 35 + recovery_id
        let v = u128::from(self.chain_id) * 2 + 35 + u128::from(signature.v());

        // Encode: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        encode_rlp_list(&mut buf, |buf| {
            self.nonce.encode(buf);
            encode_u256(&self.gas_price, buf);
            self.gas_limit.encode(buf);
            encode_optional_address(&self.to, buf);
            encode_u256(&self.value, buf);
            self.data.as_slice().encode(buf);
            v.encode(buf);
            encode_bytes32(signature.r(), buf);
            encode_bytes32(signature.s(), buf);
        });

        Ok(buf)
    }
}

/// An EIP-1559 (Type 2) transaction.
///
/// This transaction type introduces:
///
/// - Base fee burning
/// - Priority fee (tip) for miners/validators
/// - More predictable gas pricing
///
/// See [EIP-1559] for details.
///
/// When deserialized from JSON, unknown keys are rejected and `to` is required
/// (use an explicit `null` for contract creation). `U256` amounts accept a JSON
/// unsigned integer, a decimal digit string, or a `0x`-prefixed hex string.
///
/// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Eip1559Transaction {
    /// The chain ID.
    pub chain_id: u64,

    /// The transaction nonce.
    pub nonce: u64,

    /// The maximum priority fee per gas (tip).
    #[serde(deserialize_with = "strict_u256::deserialize")]
    pub max_priority_fee_per_gas: U256,

    /// The maximum total fee per gas.
    #[serde(deserialize_with = "strict_u256::deserialize")]
    pub max_fee_per_gas: U256,

    /// The gas limit.
    pub gas_limit: u64,

    /// The recipient address, or `None` for contract creation.
    ///
    /// Required in JSON; an explicit `null` means contract creation.
    #[serde(deserialize_with = "deserialize_required_to")]
    pub to: Option<Address>,

    /// The value to transfer in wei.
    #[serde(deserialize_with = "strict_u256::deserialize")]
    pub value: U256,

    /// The transaction input data.
    #[serde(default, alias = "input", with = "hex_or_bytes")]
    pub data: Vec<u8>,

    /// The access list.
    #[serde(default)]
    pub access_list: Vec<AccessListEntry>,
}

impl Eip1559Transaction {
    /// The transaction type identifier for EIP-1559.
    pub const TX_TYPE: u8 = 0x02;

    /// Generates the signing hash for this transaction.
    ///
    /// For EIP-1559 transactions, the signing hash is:
    /// `keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
    ///   gasLimit, to, value, data, accessList]))`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the 32-byte hash to be signed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChainId`] if `chain_id` is `0`.
    pub fn signing_hash(&self) -> Result<B256> {
        if self.chain_id == 0 {
            return Err(Error::InvalidChainId(0));
        }

        let mut buf = Vec::with_capacity(256);

        // Type prefix
        buf.push(Self::TX_TYPE);

        // RLP encode the transaction fields
        encode_rlp_list(&mut buf, |buf| {
            self.chain_id.encode(buf);
            self.nonce.encode(buf);
            encode_u256(&self.max_priority_fee_per_gas, buf);
            encode_u256(&self.max_fee_per_gas, buf);
            self.gas_limit.encode(buf);
            encode_optional_address(&self.to, buf);
            encode_u256(&self.value, buf);
            self.data.as_slice().encode(buf);
            self.access_list.encode(buf);
        });

        Ok(keccak256(&buf))
    }

    /// Creates a signed transaction by combining this transaction with a signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature from signing the hash
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the RLP-encoded signed transaction bytes (with type prefix).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChainId`] if `chain_id` is `0`.
    pub fn signed_rlp(&self, signature: &Signature) -> Result<Vec<u8>> {
        if self.chain_id == 0 {
            return Err(Error::InvalidChainId(0));
        }

        let mut buf = Vec::with_capacity(256);

        // Type prefix
        buf.push(Self::TX_TYPE);

        // For EIP-1559, y_parity is 0 or 1
        let v = signature.v();

        encode_rlp_list(&mut buf, |buf| {
            self.chain_id.encode(buf);
            self.nonce.encode(buf);
            encode_u256(&self.max_priority_fee_per_gas, buf);
            encode_u256(&self.max_fee_per_gas, buf);
            self.gas_limit.encode(buf);
            encode_optional_address(&self.to, buf);
            encode_u256(&self.value, buf);
            self.data.as_slice().encode(buf);
            self.access_list.encode(buf);
            v.encode(buf);
            encode_bytes32(signature.r(), buf);
            encode_bytes32(signature.s(), buf);
        });

        Ok(buf)
    }
}

/// Encodes an RLP list using a closure to write elements.
fn encode_rlp_list<F>(out: &mut Vec<u8>, f: F)
where
    F: FnOnce(&mut Vec<u8>),
{
    let mut content = Vec::new();
    f(&mut content);

    let header = alloy_rlp::Header {
        list: true,
        payload_length: content.len(),
    };
    header.encode(out);
    out.extend_from_slice(&content);
}

/// Encodes a U256 as RLP (strips leading zeros).
fn encode_u256(value: &U256, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes::<32>();
    // Find first non-zero byte
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    let trimmed = &bytes[start..];
    if trimmed.is_empty() || (trimmed.len() == 1 && trimmed[0] == 0) {
        // Encode as empty byte string (0x80)
        out.push(0x80);
    } else {
        trimmed.encode(out);
    }
}

/// Encodes an optional address.
fn encode_optional_address(addr: &Option<Address>, out: &mut Vec<u8>) {
    match addr {
        Some(a) => a.inner().encode(out),
        None => {
            // Empty byte string for contract creation
            out.push(0x80);
        }
    }
}

/// Encodes a 32-byte array, stripping leading zeros.
fn encode_bytes32(bytes: &[u8; 32], out: &mut Vec<u8>) {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    let trimmed = &bytes[start..];
    if trimmed.is_empty() || (trimmed.len() == 1 && trimmed[0] == 0) {
        out.push(0x80);
    } else {
        trimmed.encode(out);
    }
}

/// A unified transaction type supporting multiple formats.
///
/// Serialized as an internally tagged JSON object whose `type` key is either
/// `"legacy"` or `"eip1559"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Transaction {
    /// EIP-155 legacy transaction.
    #[serde(rename = "legacy")]
    Legacy(LegacyTransaction),
    /// EIP-1559 (Type 2) transaction.
    #[serde(rename = "eip1559")]
    Eip1559(Eip1559Transaction),
}

impl Transaction {
    /// Returns the signing hash for this transaction.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the 32-byte hash that should be signed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChainId`] if `chain_id` is `0`.
    pub fn signing_hash(&self) -> Result<B256> {
        match self {
            Self::Legacy(tx) => tx.signing_hash(),
            Self::Eip1559(tx) => tx.signing_hash(),
        }
    }

    /// Returns the chain ID for this transaction.
    ///
    /// # Returns
    ///
    /// The chain ID.
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.chain_id,
            Self::Eip1559(tx) => tx.chain_id,
        }
    }

    /// Creates a signed transaction by combining this transaction with a signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature from signing the hash
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the RLP-encoded signed transaction bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChainId`] if `chain_id` is `0`.
    pub fn signed_rlp(&self, signature: &Signature) -> Result<Vec<u8>> {
        match self {
            Self::Legacy(tx) => tx.signed_rlp(signature),
            Self::Eip1559(tx) => tx.signed_rlp(signature),
        }
    }

    /// Parses a transaction from JSON.
    ///
    /// # Arguments
    ///
    /// * `json` - A JSON string representing the transaction
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the parsed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::JsonError`] if parsing fails, including unknown keys,
    /// a missing `to` key, or a malformed integer amount.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serializes the transaction to JSON.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::JsonError`] if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_eip155_official_vector() {
        // Official EIP-155 specification example:
        // nonce=9, gasPrice=20e9, gasLimit=21000, to=0x3535...3535, value=1e18, data="", chainId=1
        let tx = LegacyTransaction {
            chain_id: 1,
            nonce: 9,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21_000,
            to: Some(Address::new([0x35; 20])),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![],
        };

        assert_eq!(
            hex::encode(tx.signing_hash().unwrap()),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );

        // The EIP's r and s happen to be valid low-S P-256 scalars, so the official
        // signed transaction (v = 37 = 1 * 2 + 35 + 0) is a known answer for signed_rlp.
        let r: [u8; 32] =
            hex::decode("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")
                .unwrap()
                .try_into()
                .unwrap();
        let s: [u8; 32] =
            hex::decode("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
                .unwrap()
                .try_into()
                .unwrap();
        let sig = Signature::new(r, s, 0).unwrap();
        assert_eq!(
            hex::encode(tx.signed_rlp(&sig).unwrap()),
            concat!(
                "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000",
                "8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d899",
                "7f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
            )
        );
    }

    #[test]
    fn eip1559_known_answer_vector() {
        // EIP-1559 tx: chainId=1, nonce=0, maxPriorityFee=1, maxFee=2, gasLimit=21000,
        // to=0x0000...0001, value=0, data=0x, accessList=[]
        let mut to_bytes = [0u8; 20];
        to_bytes[19] = 1;
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            gas_limit: 21_000,
            to: Some(Address::new(to_bytes)),
            value: U256::ZERO,
            data: vec![],
            access_list: vec![],
        };

        // Payload: 0x02 || rlp([1, 0, 1, 2, 21000, 0x00..01, 0, "", []])
        // rlp items: 01, 80, 01, 02, 825208, 940000...0001, 80, 80, c0
        // total payload length = 1 + 1 + 1 + 1 + 3 + 21 + 1 + 1 + 1 = 31 (0x1f) -> list header 0xdf
        let expected_payload = hex::decode(concat!(
            "02df",
            "01",
            "80",
            "01",
            "02",
            "825208",
            "940000000000000000000000000000000000000001",
            "80",
            "80",
            "c0"
        ))
        .unwrap();
        assert_eq!(tx.signing_hash().unwrap(), keccak256(&expected_payload));

        // Signed RLP with r=1, s=2, v=1
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0u8; 32];
        s[31] = 2;
        let sig = Signature::new(r, s, 1).unwrap();
        let signed = tx.signed_rlp(&sig).unwrap();

        // Added items: v=01, r=01, s=02 => +3 bytes => payload len 34 (0x22) -> list header 0xe2
        let expected_signed = hex::decode(concat!(
            "02e2",
            "01",
            "80",
            "01",
            "02",
            "825208",
            "940000000000000000000000000000000000000001",
            "80",
            "80",
            "c0",
            "01",
            "01",
            "02"
        ))
        .unwrap();
        assert_eq!(signed, expected_signed);
    }

    #[test]
    fn transaction_enum_signing_hash() {
        let legacy = Transaction::Legacy(LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21000,
            to: None,
            value: U256::ZERO,
            data: vec![0x60, 0x80, 0x60, 0x40],
        });

        let eip1559 = Transaction::Eip1559(Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(100_000_000_000u64),
            gas_limit: 100000,
            to: None,
            value: U256::ZERO,
            data: vec![0x60, 0x80, 0x60, 0x40],
            access_list: vec![],
        });

        // Expected values computed independently (Python keccak256 + RLP).
        assert_eq!(
            hex::encode(legacy.signing_hash().unwrap()),
            "f538abbdf85a0d7b6aee12131da82ec4529fb8a489bce5afa3e36ecb7ce45484"
        );
        assert_eq!(
            hex::encode(eip1559.signing_hash().unwrap()),
            "ad72b2ec7e639f616dee88804b17cec3db21a952725dd75a691001659b71af63"
        );
    }

    /// Signature with r = 1, s = 2, y-parity 1 used by the EIP-1559 known-answer tests.
    fn r1_s2_v1() -> Signature {
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0u8; 32];
        s[31] = 2;
        Signature::new(r, s, 1).unwrap()
    }

    #[test]
    fn eip1559_known_answer_non_empty_access_list() {
        let mut key_one = [0u8; 32];
        key_one[31] = 1;
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 7,
            max_priority_fee_per_gas: U256::from(2_000_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            gas_limit: 50_000,
            to: Some(Address::new([0x11; 20])),
            value: U256::from(12_345u64),
            data: vec![0xde, 0xad, 0xbe, 0xef],
            access_list: vec![
                AccessListEntry {
                    address: alloy_primitives::Address::repeat_byte(0x22),
                    storage_keys: vec![B256::from(key_one), B256::repeat_byte(0xff)],
                },
                AccessListEntry {
                    address: alloy_primitives::Address::repeat_byte(0x33),
                    storage_keys: vec![],
                },
            ],
        };

        assert_eq!(
            hex::encode(tx.signing_hash().unwrap()),
            "240e1e0de1d6aad3fe8a040b68fd1688c35900636f1569f37626c70b406b40ef"
        );
        assert_eq!(
            hex::encode(tx.signed_rlp(&r1_s2_v1()).unwrap()),
            concat!(
                "02f8a4010784773594008506fc23ac0082c3509411111111111111111111111111111111111111118230",
                "3984deadbeeff872f859942222222222222222222222222222222222222222f842a00000000000000000",
                "000000000000000000000000000000000000000000000001a0ffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffd6943333333333333333333333333333333333333333c0010102"
            )
        );
    }

    #[test]
    fn eip1559_known_answer_contract_creation() {
        let tx = Eip1559Transaction {
            chain_id: 5,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            gas_limit: 100_000,
            to: None,
            value: U256::ZERO,
            data: vec![0x60, 0x80, 0x60, 0x40, 0x52],
            access_list: vec![],
        };

        assert_eq!(
            hex::encode(tx.signing_hash().unwrap()),
            "6d4ced661f89b6ed0bc7535d031bb9fc3550952722c5568b53053b4df5f3b3ad"
        );
        assert_eq!(
            hex::encode(tx.signed_rlp(&r1_s2_v1()).unwrap()),
            "02d405800102830186a08080856080604052c0010102"
        );
    }

    #[test]
    fn eip1559_known_answer_long_data() {
        // 100 bytes of calldata needs the long-string RLP header (0xb8 0x64) and the
        // payload needs the long-list header (0xf8 ..).
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 3,
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(2_000_000_000u64),
            gas_limit: 200_000,
            to: Some(Address::new([0x44; 20])),
            value: U256::ZERO,
            data: (0u8..100).collect(),
            access_list: vec![],
        };

        assert_eq!(
            hex::encode(tx.signing_hash().unwrap()),
            "342e7eed105c78386c84e2c7c940862f3a23261495435a9ab21358256303c678"
        );
        assert_eq!(
            hex::encode(tx.signed_rlp(&r1_s2_v1()).unwrap()),
            concat!(
                "02f8900103843b9aca00847735940083030d409444444444444444444444444444444444444444448",
                "0b864000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425",
                "262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e",
                "4f505152535455565758595a5b5c5d5e5f60616263c0010102"
            )
        );
    }

    #[test]
    fn signing_hash_rejects_chain_id_zero() {
        let legacy = LegacyTransaction {
            chain_id: 0,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
        };
        assert!(matches!(
            legacy.signing_hash(),
            Err(Error::InvalidChainId(0))
        ));
        assert!(matches!(
            Transaction::Legacy(legacy).signing_hash(),
            Err(Error::InvalidChainId(0))
        ));

        let eip1559 = Eip1559Transaction {
            chain_id: 0,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
            access_list: vec![],
        };
        assert!(matches!(
            eip1559.signing_hash(),
            Err(Error::InvalidChainId(0))
        ));
        assert!(matches!(
            Transaction::Eip1559(eip1559).signing_hash(),
            Err(Error::InvalidChainId(0))
        ));

        // The same rejection applies to JSON input with "chain_id": 0
        let json = r#"{
            "type": "eip1559",
            "chain_id": 0,
            "nonce": 0,
            "max_priority_fee_per_gas": "1",
            "max_fee_per_gas": "2",
            "gas_limit": 21000,
            "to": "0x0000000000000000000000000000000000000001",
            "value": "0"
        }"#;
        assert!(matches!(
            Transaction::from_json(json).unwrap().signing_hash(),
            Err(Error::InvalidChainId(0))
        ));
    }

    #[test]
    fn transaction_chain_id() {
        let legacy = Transaction::Legacy(LegacyTransaction {
            chain_id: 137,
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: 21000,
            to: None,
            value: U256::ZERO,
            data: vec![],
        });

        let eip1559 = Transaction::Eip1559(Eip1559Transaction {
            chain_id: 42161,
            nonce: 0,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            gas_limit: 21000,
            to: None,
            value: U256::ZERO,
            data: vec![],
            access_list: vec![],
        });

        assert_eq!(legacy.chain_id(), 137);
        assert_eq!(eip1559.chain_id(), 42161);
    }

    #[test]
    fn transaction_json_roundtrip_and_compat_formats() {
        let original = Transaction::Eip1559(Eip1559Transaction {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(100_000_000_000u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![0xde, 0xad, 0xbe, 0xef],
            access_list: vec![],
        });

        let json = original.to_json().unwrap();
        assert!(json.contains("\"0xdeadbeef\""));
        let recovered = Transaction::from_json(&json).unwrap();
        assert_eq!(original, recovered);

        // README.md / demo/app.js JSON format: "input": "0x", omitted access_list, decimal strings
        let readme_json = r#"{
            "type": "eip1559",
            "chain_id": 1,
            "nonce": 0,
            "max_priority_fee_per_gas": "1000000000",
            "max_fee_per_gas": "20000000000",
            "gas_limit": 21000,
            "to": "0x0000000000000000000000000000000000000001",
            "value": "1000000000000000000",
            "input": "0x"
        }"#;
        let parsed = Transaction::from_json(readme_json).unwrap();
        match parsed {
            Transaction::Eip1559(tx) => {
                assert_eq!(tx.chain_id, 1);
                assert!(tx.data.is_empty());
                assert!(tx.access_list.is_empty());
                assert!(tx.to.is_some());
            }
            Transaction::Legacy(_) => panic!("expected eip1559"),
        }

        // Contract deployment (to: null / omitted), uppercase 0X prefix, and byte array data
        let deploy_json = r#"{
            "type": "eip1559",
            "chain_id": 1,
            "nonce": 1,
            "max_priority_fee_per_gas": "1000",
            "max_fee_per_gas": "2000",
            "gas_limit": 100000,
            "to": null,
            "value": "0",
            "input": "0X60806040"
        }"#;
        let deploy_tx = Transaction::from_json(deploy_json).unwrap();
        match deploy_tx {
            Transaction::Eip1559(tx) => {
                assert!(tx.to.is_none());
                assert_eq!(tx.data, vec![0x60, 0x80, 0x60, 0x40]);
            }
            Transaction::Legacy(_) => panic!("expected eip1559"),
        }

        // Backwards-compatible byte array format for data on LegacyTransaction;
        // contract creation requires an explicit "to": null
        let legacy_byte_array = r#"{
            "type": "legacy",
            "chain_id": 1,
            "nonce": 5,
            "gas_price": "20000000000",
            "gas_limit": 21000,
            "to": null,
            "value": "0",
            "data": [222, 173, 190, 239]
        }"#;
        let legacy_tx = Transaction::from_json(legacy_byte_array).unwrap();
        match legacy_tx {
            Transaction::Legacy(tx) => {
                assert!(tx.to.is_none());
                assert_eq!(tx.data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            Transaction::Eip1559(_) => panic!("expected legacy"),
        }

        // Legacy round trip through the internally tagged enum, including `to: None`
        let legacy = Transaction::Legacy(LegacyTransaction {
            chain_id: 1,
            nonce: 5,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21000,
            to: None,
            value: U256::ZERO,
            data: vec![0x60],
        });
        let legacy_json = legacy.to_json().unwrap();
        assert!(legacy_json.contains("\"type\":\"legacy\""));
        assert!(legacy_json.contains("\"to\":null"));
        assert_eq!(Transaction::from_json(&legacy_json).unwrap(), legacy);
    }

    /// A valid EIP-1559 JSON object as a `serde_json::Map`, for mutation in tests.
    fn base_eip1559_json() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({
            "type": "eip1559",
            "chain_id": 1,
            "nonce": 0,
            "max_priority_fee_per_gas": "1000000000",
            "max_fee_per_gas": "20000000000",
            "gas_limit": 21000,
            "to": "0x0000000000000000000000000000000000000001",
            "value": "1000000000000000000",
            "data": "0x",
            "access_list": []
        })
        .as_object()
        .unwrap()
        .clone()
    }

    /// A valid legacy JSON object as a `serde_json::Map`, for mutation in tests.
    fn base_legacy_json() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({
            "type": "legacy",
            "chain_id": 1,
            "nonce": 0,
            "gas_price": "20000000000",
            "gas_limit": 21000,
            "to": "0x0000000000000000000000000000000000000001",
            "value": "1000000000000000000",
            "data": "0x"
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn parse_map(map: &serde_json::Map<String, serde_json::Value>) -> Result<Transaction> {
        Transaction::from_json(&serde_json::Value::Object(map.clone()).to_string())
    }

    #[test]
    fn transaction_json_rejects_unknown_keys_and_missing_to() {
        // The internally tagged `type` key still parses with deny_unknown_fields
        assert!(matches!(
            parse_map(&base_eip1559_json()).unwrap(),
            Transaction::Eip1559(_)
        ));
        assert!(matches!(
            parse_map(&base_legacy_json()).unwrap(),
            Transaction::Legacy(_)
        ));

        for base in [base_eip1559_json(), base_legacy_json()] {
            // Misspelled `to` ("To") is an unknown key, not contract creation
            let mut misspelled = base.clone();
            let to = misspelled.remove("to").unwrap();
            misspelled.insert("To".to_string(), to);
            assert!(matches!(parse_map(&misspelled), Err(Error::JsonError(_))));

            // Missing `to` is an error
            let mut missing = base.clone();
            missing.remove("to");
            let err = parse_map(&missing).unwrap_err();
            assert!(err.to_string().contains("missing field `to`"), "{err}");

            // Explicit null `to` is contract creation
            let mut create = base.clone();
            create.insert("to".to_string(), serde_json::Value::Null);
            let tx = parse_map(&create).unwrap();
            let to = match tx {
                Transaction::Legacy(tx) => tx.to,
                Transaction::Eip1559(tx) => tx.to,
            };
            assert!(to.is_none());

            // Arbitrary extra key is rejected
            let mut extra = base.clone();
            extra.insert("from".to_string(), serde_json::json!("0x00"));
            assert!(matches!(parse_map(&extra), Err(Error::JsonError(_))));

            // `input` alias is still accepted, but not together with `data`
            let mut input_alias = base.clone();
            input_alias.remove("data");
            input_alias.insert("input".to_string(), serde_json::json!("0xdeadbeef"));
            assert!(parse_map(&input_alias).is_ok());
            let mut both = base.clone();
            both.insert("input".to_string(), serde_json::json!("0xdeadbeef"));
            assert!(matches!(parse_map(&both), Err(Error::JsonError(_))));
        }

        // camelCase "accessList" is not silently dropped
        let mut camel = base_eip1559_json();
        camel.remove("access_list");
        camel.insert(
            "accessList".to_string(),
            serde_json::json!([{
                "address": "0x2222222222222222222222222222222222222222",
                "storage_keys": []
            }]),
        );
        assert!(matches!(parse_map(&camel), Err(Error::JsonError(_))));

        // Unknown keys inside access list entries are rejected
        let mut bad_entry = base_eip1559_json();
        bad_entry.insert(
            "access_list".to_string(),
            serde_json::json!([{
                "address": "0x2222222222222222222222222222222222222222",
                "storageKeys": []
            }]),
        );
        assert!(matches!(parse_map(&bad_entry), Err(Error::JsonError(_))));

        // A well-formed access list entry parses
        let mut good_entry = base_eip1559_json();
        good_entry.insert(
            "access_list".to_string(),
            serde_json::json!([{
                "address": "0x2222222222222222222222222222222222222222",
                "storage_keys": [
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ]
            }]),
        );
        match parse_map(&good_entry).unwrap() {
            Transaction::Eip1559(tx) => assert_eq!(tx.access_list[0].storage_keys.len(), 1),
            Transaction::Legacy(_) => panic!("expected eip1559"),
        }

        // Unknown transaction type is rejected
        let mut bad_type = base_eip1559_json();
        bad_type.insert("type".to_string(), serde_json::json!("eip2930"));
        assert!(matches!(parse_map(&bad_type), Err(Error::JsonError(_))));
    }

    #[test]
    fn transaction_json_u256_fields_are_strict() {
        let fields_1559 = ["value", "max_priority_fee_per_gas", "max_fee_per_gas"];
        let fields_legacy = ["value", "gas_price"];

        let accepted = [
            (serde_json::json!(16), U256::from(16u64)),
            (serde_json::json!(u64::MAX), U256::from(u64::MAX)),
            (serde_json::json!("16"), U256::from(16u64)),
            (serde_json::json!("0016"), U256::from(16u64)),
            (serde_json::json!("0x10"), U256::from(16u64)),
            (serde_json::json!("0X10"), U256::from(16u64)),
            (serde_json::json!("0xFf"), U256::from(255u64)),
            (serde_json::json!("0"), U256::ZERO),
            (
                serde_json::json!(
                    "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                ),
                U256::MAX,
            ),
            (
                serde_json::json!(format!("0x{}", "f".repeat(64))),
                U256::MAX,
            ),
        ];
        let rejected = [
            serde_json::json!("0x1_0"),
            serde_json::json!("1_000"),
            serde_json::json!("0b1"),
            serde_json::json!("0o7"),
            serde_json::json!(""),
            serde_json::json!("0x"),
            serde_json::json!(" 1"),
            serde_json::json!("1 "),
            serde_json::json!("+1"),
            serde_json::json!("-1"),
            serde_json::json!("1e18"),
            serde_json::json!("0xg"),
            serde_json::json!("ff"),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(1e30),
            serde_json::json!(null),
            serde_json::json!(true),
            // U256::MAX + 1
            serde_json::json!(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            ),
            serde_json::json!(format!("0x1{}", "0".repeat(64))),
        ];

        let get = |tx: &Transaction, field: &str| -> U256 {
            match (tx, field) {
                (Transaction::Eip1559(tx), "value") => tx.value,
                (Transaction::Eip1559(tx), "max_priority_fee_per_gas") => {
                    tx.max_priority_fee_per_gas
                }
                (Transaction::Eip1559(tx), "max_fee_per_gas") => tx.max_fee_per_gas,
                (Transaction::Legacy(tx), "value") => tx.value,
                (Transaction::Legacy(tx), "gas_price") => tx.gas_price,
                _ => unreachable!(),
            }
        };

        for (base, fields) in [
            (base_eip1559_json(), &fields_1559[..]),
            (base_legacy_json(), &fields_legacy[..]),
        ] {
            for field in fields {
                for (input, expected) in &accepted {
                    let mut map = base.clone();
                    map.insert((*field).to_string(), input.clone());
                    let tx = parse_map(&map)
                        .unwrap_or_else(|e| panic!("{field}={input} should parse: {e}"));
                    assert_eq!(get(&tx, field), *expected, "{field}={input}");
                }
                for input in &rejected {
                    let mut map = base.clone();
                    map.insert((*field).to_string(), input.clone());
                    assert!(
                        matches!(parse_map(&map), Err(Error::JsonError(_))),
                        "{field}={input} should be rejected"
                    );
                }
            }
        }

        // Serialization output is unchanged (ruint's 0x-prefixed lowercase hex)
        let tx =
            Transaction::from_json(&serde_json::Value::Object(base_eip1559_json()).to_string())
                .unwrap();
        let json = tx.to_json().unwrap();
        assert!(json.contains("\"value\":\"0xde0b6b3a7640000\""), "{json}");
        assert!(
            json.contains("\"max_fee_per_gas\":\"0x4a817c800\""),
            "{json}"
        );
        assert_eq!(Transaction::from_json(&json).unwrap(), tx);
    }

    #[test]
    fn signed_rlp_validation_and_large_chain_id_no_overflow() {
        let sig = Signature::new([1u8; 32], [2u8; 32], 1).unwrap();
        assert_eq!(sig.v(), 1);

        // chain_id == 0 must be rejected
        let zero_legacy = LegacyTransaction {
            chain_id: 0,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
        };
        assert!(matches!(
            zero_legacy.signed_rlp(&sig),
            Err(Error::InvalidChainId(0))
        ));

        let zero_1559 = Eip1559Transaction {
            chain_id: 0,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
            access_list: vec![],
        };
        assert!(matches!(
            zero_1559.signed_rlp(&sig),
            Err(Error::InvalidChainId(0))
        ));

        // u64::MAX chain_id must NOT overflow EIP-155 v calculation
        let max_chain_legacy = LegacyTransaction {
            chain_id: u64::MAX,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
        };
        // v = (2^64 - 1) * 2 + 35 + 1 = 0x020000000000000022, RLP 0x89 || 9 bytes
        let rlp = max_chain_legacy.signed_rlp(&sig).unwrap();
        assert_eq!(
            hex::encode(&rlp),
            concat!(
                "f8688001825208940000000000000000000000000000000000000000808089020000000000000022",
                "a00101010101010101010101010101010101010101010101010101010101010101",
                "a00202020202020202020202020202020202020202020202020202020202020202"
            )
        );
        assert_eq!(
            hex::encode(max_chain_legacy.signing_hash().unwrap()),
            "b48d94328e0ed474963920c683d2c4de675a3399b1e51e4024be953cecab7687"
        );
    }

    #[test]
    fn access_list_encoding_matches_manual_rlp() {
        let entry = AccessListEntry {
            address: alloy_primitives::Address::ZERO,
            storage_keys: vec![B256::ZERO],
        };

        let mut derived_buf = Vec::new();
        vec![entry.clone()].encode(&mut derived_buf);

        let mut manual_buf = Vec::new();
        encode_rlp_list(&mut manual_buf, |out| {
            encode_rlp_list(out, |out| {
                entry.address.encode(out);
                encode_rlp_list(out, |out| {
                    for key in &entry.storage_keys {
                        key.encode(out);
                    }
                });
            });
        });

        assert_eq!(derived_buf, manual_buf);

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
            access_list: vec![entry],
        };

        // Expected value computed independently (Python keccak256 + RLP).
        assert_eq!(
            hex::encode(tx.signing_hash().unwrap()),
            "af5ad7f2b610e3413e450e064629cc1f55af96b2a01aa772481e0c6250df3da7"
        );
    }
}
