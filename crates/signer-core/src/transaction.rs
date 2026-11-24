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
//! let hash = tx.signing_hash();
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

/// An access list entry for EIP-2930/EIP-1559 transactions.
///
/// Access lists specify which addresses and storage keys will be accessed
/// during transaction execution, potentially reducing gas costs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable)]
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
/// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTransaction {
    /// The chain ID for replay protection.
    pub chain_id: u64,

    /// The transaction nonce.
    pub nonce: u64,

    /// The gas price in wei.
    pub gas_price: U256,

    /// The gas limit.
    pub gas_limit: u64,

    /// The recipient address, or `None` for contract creation.
    #[serde(default)]
    pub to: Option<Address>,

    /// The value to transfer in wei.
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
    /// The 32-byte hash to be signed.
    #[must_use]
    pub fn signing_hash(&self) -> B256 {
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

        keccak256(&buf)
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
    /// - [`Error::InvalidChainId`] if `chain_id` is `0`
    /// - [`Error::InvalidSignature`] if `signature.v()` is greater than `1`
    pub fn signed_rlp(&self, signature: &Signature) -> Result<Vec<u8>> {
        if self.chain_id == 0 {
            return Err(Error::InvalidChainId(0));
        }
        if signature.v() > 1 {
            return Err(Error::InvalidSignature(format!(
                "invalid recovery parameter v: {}",
                signature.v()
            )));
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
/// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip1559Transaction {
    /// The chain ID.
    pub chain_id: u64,

    /// The transaction nonce.
    pub nonce: u64,

    /// The maximum priority fee per gas (tip).
    pub max_priority_fee_per_gas: U256,

    /// The maximum total fee per gas.
    pub max_fee_per_gas: U256,

    /// The gas limit.
    pub gas_limit: u64,

    /// The recipient address, or `None` for contract creation.
    #[serde(default)]
    pub to: Option<Address>,

    /// The value to transfer in wei.
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
    /// The 32-byte hash to be signed.
    #[must_use]
    pub fn signing_hash(&self) -> B256 {
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

        keccak256(&buf)
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
    /// - [`Error::InvalidChainId`] if `chain_id` is `0`
    /// - [`Error::InvalidSignature`] if `signature.v()` is greater than `1`
    pub fn signed_rlp(&self, signature: &Signature) -> Result<Vec<u8>> {
        if self.chain_id == 0 {
            return Err(Error::InvalidChainId(0));
        }
        if signature.v() > 1 {
            return Err(Error::InvalidSignature(format!(
                "invalid recovery parameter v: {}",
                signature.v()
            )));
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
    /// The 32-byte hash that should be signed.
    #[must_use]
    pub fn signing_hash(&self) -> B256 {
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
    /// - [`Error::InvalidChainId`] if `chain_id` is `0`
    /// - [`Error::InvalidSignature`] if `signature.v()` is greater than `1`
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
    /// Returns [`crate::Error::JsonError`] if parsing fails.
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
            hex::encode(tx.signing_hash()),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
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
        assert_eq!(tx.signing_hash(), keccak256(&expected_payload));

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

        assert!(!legacy.signing_hash().is_zero());
        assert!(!eip1559.signing_hash().is_zero());
        assert_ne!(legacy.signing_hash(), eip1559.signing_hash());
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

        // Backwards-compatible byte array format for data on LegacyTransaction
        let legacy_byte_array = r#"{
            "type": "legacy",
            "chain_id": 1,
            "nonce": 5,
            "gas_price": "20000000000",
            "gas_limit": 21000,
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
    }

    #[test]
    fn signed_rlp_validation_and_large_chain_id_no_overflow() {
        let sig = Signature::new([1u8; 32], [2u8; 32], 1).unwrap();

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
        let rlp = max_chain_legacy.signed_rlp(&sig).unwrap();
        assert!(!rlp.is_empty());
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

        assert!(!tx.signing_hash().is_zero());
    }
}
