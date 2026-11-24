//! YubiKey EVM Signer Core Library
//!
//! This crate provides the core functionality for signing Ethereum transactions
//! using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA.
//!
//! # Overview
//!
//! With [EIP-7951], Ethereum supports native verification of secp256r1
//! signatures, enabling hardware security modules like YubiKey to be used
//! directly for transaction signing without curve conversion.
//!
//! This library provides:
//!
//! - **Transaction Types**: EIP-155 legacy and EIP-1559 transaction support
//! - **EIP-712**: Typed structured data hashing for human-readable signing
//! - **EIP-191**: Personal message hashing
//! - **YubiKey Integration**: PIV applet communication for key management and signing
//! - **Address Derivation**: Ethereum address computation from P-256 public keys
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Transaction  │   EIP-712    │   Address    │   Signature   │
//! │   Building    │   Hashing    │  Derivation  │    Types      │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    YubiKey PIV Layer                         │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
//! │  │  Slot   │  │  APDU   │  │   PIV   │  │    Transport    │ │
//! │  │ Mgmt    │  │ Encode  │  │ Session │  │   Abstraction   │ │
//! │  └─────────┘  └─────────┘  └─────────┘  └─────────────────┘ │
//! ├─────────────────────────────────────────────────────────────┤
//! │              Transport Layer (CCID / WebUSB)                 │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ## Creating a Transaction
//!
//! ```rust
//! use yubikey_evm_signer_core::{Transaction, Eip1559Transaction, Address};
//! use alloy_primitives::U256;
//!
//! // Create an EIP-1559 transaction
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
//! // Get the hash to sign
//! let hash = tx.signing_hash();
//! ```
//!
//! ## Signing with EIP-712 Typed Data
//!
//! ```rust
//! use yubikey_evm_signer_core::{TypedData, Eip712Domain, U256};
//! use serde_json::json;
//!
//! let domain = Eip712Domain {
//!     name: Some("My DApp".to_string()),
//!     version: Some("1".to_string()),
//!     chain_id: Some(U256::from(1)),
//!     verifying_contract: None,
//!     salt: None,
//! };
//!
//! let types = json!({
//!     "Transfer": [
//!         {"name": "to", "type": "address"},
//!         {"name": "amount", "type": "uint256"}
//!     ]
//! });
//!
//! let message = json!({
//!     "to": "0x0000000000000000000000000000000000000001",
//!     "amount": "1000000000000000000"
//! });
//!
//! let typed_data = TypedData::new(domain, types, "Transfer".to_string(), message).unwrap();
//! let hash = typed_data.signing_hash().unwrap();
//! ```
//!
//! ## Address Derivation
//!
//! ```rust
//! use yubikey_evm_signer_core::Address;
//!
//! // Derive address from a valid 64-byte P-256 public key (NIST P-256 generator G)
//! let pubkey_bytes = hex::decode(concat!(
//!     "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
//!     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
//! ))
//! .unwrap();
//! let address = Address::from_public_key_bytes(&pubkey_bytes).unwrap();
//! println!("Address: {address}");
//! ```
//!
//! # YubiKey Integration
//!
//! The library provides a transport-agnostic interface for YubiKey communication.
//! Implement the [`yubikey::Transport`] trait for your platform:
//!
//! - **Native**: Enable the optional `pcsc` feature to use CCID/PC/SC for desktop applications
//! - **Browser**: Use WebUSB for web applications (see `yubikey-evm-signer-wasm`)
//!
//! ```ignore
//! use yubikey_evm_signer_core::yubikey::{ManagementKeyAlgorithm, PivSession, Slot, Transport};
//!
//! // Create a transport (implementation depends on platform)
//! let transport: Box<dyn Transport> = create_transport()?;
//!
//! // Create a PIV session
//! let mut session = PivSession::new(transport);
//! session.select()?;
//!
//! // Authenticate management key before generating a key
//! session.authenticate_management_key_with(&mgmt_key, ManagementKeyAlgorithm::Aes192)?;
//! let public_key = session.generate_key(Slot::Authentication)?;
//!
//! // Verify PIN and sign a 32-byte digest
//! session.verify_pin("123456")?;
//! let signature = session.sign(Slot::Authentication, &hash)?;
//! ```
//!
//! # Feature Flags
//!
//! - `pcsc` (optional, disabled by default): Enables native smart-card communication via
//!   PC/SC (`yubikey::PcscTransport`) and the `yubikey-cli` example. Requires the system
//!   PC/SC library (`libpcsclite` on Linux, built-in on macOS and Windows).
//!
//! # Security Considerations
//!
//! - Private keys never leave the YubiKey hardware
//! - PIN verification is required before signing (except slot 9e)
//! - Management key mutual authentication is required for key generation
//! - Touch confirmation can be enforced for additional security
//! - Signatures are normalized to low-S form to prevent malleability
//!
//! [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951

// Silence unused dev-dependency warning in unit test target (rpassword is used by yubikey-cli)
#[cfg(test)]
use rpassword as _;

// Modules
pub mod address;
pub mod crypto;
pub mod eip712;
pub mod error;
pub mod signature;
pub mod transaction;
pub mod yubikey;

// Re-exports for convenience
pub use address::Address;
pub use crypto::eip191_hash;
pub use eip712::{Eip712Domain, TypedData};
pub use error::{Error, Result};
pub use signature::Signature;
pub use transaction::{AccessListEntry, Eip1559Transaction, LegacyTransaction, Transaction};

// Re-export commonly used alloy types
pub use alloy_primitives::{B256, U256};
