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
//! 4. Create the signed transaction with the signature
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
use crate::error::Result;
use crate::signature::Signature;

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
    pub to: Option<Address>,

    /// The value to transfer in wei.
    pub value: U256,

    /// The transaction input data.
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
    /// The RLP-encoded signed transaction bytes.
    #[must_use]
    pub fn signed_rlp(&self, signature: &Signature) -> Vec<u8> {
        let mut buf = Vec::new();

        // Calculate v with EIP-155: v = chain_id * 2 + 35 + recovery_id
        let v = self.chain_id * 2 + 35 + u64::from(signature.v());

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

        buf
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
    pub to: Option<Address>,

    /// The value to transfer in wei.
    pub value: U256,

    /// The transaction input data.
    pub data: Vec<u8>,

    /// The access list.
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
            encode_access_list(&self.access_list, buf);
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
    /// The RLP-encoded signed transaction bytes (with type prefix).
    #[must_use]
    pub fn signed_rlp(&self, signature: &Signature) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Type prefix
        buf.push(Self::TX_TYPE);

        // For EIP-1559, v is just 0 or 1
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
            encode_access_list(&self.access_list, buf);
            v.encode(buf);
            encode_bytes32(signature.r(), buf);
            encode_bytes32(signature.s(), buf);
        });

        buf
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
        // Encode as empty byte (0x80)
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

/// Encodes an access list to RLP.
fn encode_access_list(access_list: &[AccessListEntry], out: &mut Vec<u8>) {
    encode_rlp_list(out, |out| {
        for entry in access_list {
            encode_rlp_list(out, |out| {
                entry.address.encode(out);
                encode_rlp_list(out, |out| {
                    for key in &entry.storage_keys {
                        key.encode(out);
                    }
                });
            });
        }
    });
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
    /// The RLP-encoded signed transaction bytes.
    #[must_use]
    pub fn signed_rlp(&self, signature: &Signature) -> Vec<u8> {
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
    fn legacy_transaction_signing_hash() {
        let tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![],
        };

        let hash = tx.signing_hash();
        assert!(!hash.is_zero());
    }

    #[test]
    fn eip1559_transaction_signing_hash() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(100_000_000_000u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![],
            access_list: vec![],
        };

        let hash = tx.signing_hash();
        assert!(!hash.is_zero());
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

        // Both should produce non-zero hashes
        assert!(!legacy.signing_hash().is_zero());
        assert!(!eip1559.signing_hash().is_zero());

        // And they should be different
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
    fn transaction_json_roundtrip() {
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
        let recovered = Transaction::from_json(&json).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn legacy_signed_rlp() {
        let tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![],
        };

        let sig = Signature::new([1u8; 32], [2u8; 32], 0);
        let rlp = tx.signed_rlp(&sig);

        // Should produce non-empty RLP
        assert!(!rlp.is_empty());
    }

    #[test]
    fn eip1559_signed_rlp() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(100_000_000_000u64),
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![],
            access_list: vec![],
        };

        let sig = Signature::new([1u8; 32], [2u8; 32], 1);
        let rlp = tx.signed_rlp(&sig);

        // Should start with type prefix
        assert_eq!(rlp[0], 0x02);
    }

    #[test]
    fn access_list_encoding() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            gas_limit: 21000,
            to: Some(Address::zero()),
            value: U256::ZERO,
            data: vec![],
            access_list: vec![AccessListEntry {
                address: alloy_primitives::Address::ZERO,
                storage_keys: vec![B256::ZERO],
            }],
        };

        let hash = tx.signing_hash();
        assert!(!hash.is_zero());
    }
}
