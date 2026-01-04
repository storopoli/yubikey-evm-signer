//! YubiKey EVM Signer Core Library
//!
//! This crate provides the core functionality for signing Ethereum transactions
//! using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA.
//!
//! # Overview
//!
//! With [EIP-7951], Ethereum now supports native verification of secp256r1
//! signatures, enabling hardware security modules like YubiKey to be used
//! directly for transaction signing without curve conversion.
//!
//! This library provides:
//!
//! - **Transaction Types**: EIP-155 legacy and EIP-1559 transaction support
//! - **EIP-712**: Typed structured data hashing for human-readable signing
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
//! use yubikey_evm_signer_core::{TypedData, Eip712Domain};
//! use serde_json::json;
//!
//! let domain = Eip712Domain {
//!     name: Some("My DApp".to_string()),
//!     version: Some("1".to_string()),
//!     chain_id: Some(1),
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
//! let typed_data = TypedData::new(domain, types, "Transfer".to_string(), message);
//! let hash = typed_data.signing_hash().unwrap();
//! ```
//!
//! ## Address Derivation
//!
//! ```rust
//! use yubikey_evm_signer_core::Address;
//!
//! // Derive address from a 64-byte public key (x || y)
//! let pubkey_bytes = [0u8; 64];
//! let address = Address::from_public_key_bytes(&pubkey_bytes).unwrap();
//! println!("Address: {address}");
//! ```
//!
//! # YubiKey Integration
//!
//! The library provides a transport-agnostic interface for YubiKey communication.
//! Implement the [`yubikey::Transport`] trait for your platform:
//!
//! - **Native**: Use CCID/PC/SC for desktop applications
//! - **Browser**: Use WebUSB for web applications (see `yubikey-evm-signer-wasm`)
//!
//! ```ignore
//! use yubikey_evm_signer_core::yubikey::{PivSession, Slot, Transport};
//!
//! // Create a transport (implementation depends on platform)
//! let transport: Box<dyn Transport> = create_transport()?;
//!
//! // Create a PIV session
//! let mut session = PivSession::new(transport);
//! session.select()?;
//! session.verify_pin("123456")?;
//!
//! // Generate a key
//! let public_key = session.generate_key(Slot::Authentication)?;
//!
//! // Sign data
//! let signature = session.sign(Slot::Authentication, &hash)?;
//! ```
//!
//! # Feature Flags
//!
//! This crate currently has no optional features. All functionality is
//! included by default.
//!
//! # Security Considerations
//!
//! - Private keys never leave the YubiKey hardware
//! - PIN verification is required before signing (except slot 9e)
//! - Touch confirmation can be enforced for additional security
//! - Signatures are normalized to low-S form to prevent malleability
//!
//! [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951

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
pub use eip712::{Eip712Domain, TypedData};
pub use error::{Error, Result};
pub use signature::Signature;
pub use transaction::{AccessListEntry, Eip1559Transaction, LegacyTransaction, Transaction};

// Re-export commonly used alloy types
pub use alloy_primitives::{B256, U256};
