//! EIP-712 typed structured data hashing.
//!
//! This module implements [EIP-712] for hashing typed structured data,
//! enabling human-readable signing of structured messages in Ethereum wallets.
//!
//! # Overview
//!
//! EIP-712 defines a standard for hashing and signing typed data, consisting of:
//!
//! 1. **Domain Separator**: Identifies the DApp and prevents replay across apps
//! 2. **Type Definitions**: Describe the structure of the data being signed
//! 3. **Message Data**: The actual data conforming to the type definitions
//!
//! # Hash Computation
//!
//! The final hash to sign is:
//! ```text
//! keccak256("\x19\x01" || domainSeparator || hashStruct(message))
//! ```
//!
//! # Example
//!
//! ```
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
//! // Create typed data from JSON
//! let types = json!({
//!     "Person": [
//!         {"name": "name", "type": "string"},
//!         {"name": "wallet", "type": "address"}
//!     ]
//! });
//!
//! let message = json!({
//!     "name": "Alice",
//!     "wallet": "0x0000000000000000000000000000000000000001"
//! });
//!
//! let typed_data = TypedData::new(domain, types, "Person".to_string(), message);
//! let hash = typed_data.signing_hash().unwrap();
//! ```
//!
//! [EIP-712]: https://eips.ethereum.org/EIPS/eip-712

use std::collections::HashMap;

use alloy_primitives::{Address as AlloyAddress, B256, U256, keccak256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// The EIP-712 domain separator parameters.
///
/// The domain separator is used to prevent signature replay attacks across
/// different applications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Domain {
    /// The human-readable name of the signing domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The version of the signing domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The chain ID where signatures are valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// The address of the contract verifying the signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,

    /// A disambiguating salt for the protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
}

impl Eip712Domain {
    /// Computes the domain separator hash.
    ///
    /// The domain separator is the hash of the EIP-712 domain type and values.
    ///
    /// # Returns
    ///
    /// The 32-byte domain separator hash.
    #[must_use]
    pub fn separator_hash(&self) -> B256 {
        // Build the type string for EIP712Domain
        let mut type_parts = vec!["EIP712Domain("];
        let mut value_parts = Vec::new();

        if self.name.is_some() {
            type_parts.push("string name");
            value_parts.push("name");
        }
        if self.version.is_some() {
            if value_parts.is_empty() {
                type_parts.push("string version");
            } else {
                type_parts.push(",string version");
            }
            value_parts.push("version");
        }
        if self.chain_id.is_some() {
            if value_parts.is_empty() {
                type_parts.push("uint256 chainId");
            } else {
                type_parts.push(",uint256 chainId");
            }
            value_parts.push("chainId");
        }
        if self.verifying_contract.is_some() {
            if value_parts.is_empty() {
                type_parts.push("address verifyingContract");
            } else {
                type_parts.push(",address verifyingContract");
            }
            value_parts.push("verifyingContract");
        }
        if self.salt.is_some() {
            if value_parts.is_empty() {
                type_parts.push("bytes32 salt");
            } else {
                type_parts.push(",bytes32 salt");
            }
            value_parts.push("salt");
        }
        type_parts.push(")");

        let type_string: String = type_parts.concat();
        let type_hash = keccak256(type_string.as_bytes());

        // Encode the domain values
        let mut encoded = type_hash.to_vec();

        if let Some(ref name) = self.name {
            encoded.extend_from_slice(keccak256(name.as_bytes()).as_slice());
        }
        if let Some(ref version) = self.version {
            encoded.extend_from_slice(keccak256(version.as_bytes()).as_slice());
        }
        if let Some(chain_id) = self.chain_id {
            let mut buf = [0u8; 32];
            buf[24..].copy_from_slice(&chain_id.to_be_bytes());
            encoded.extend_from_slice(&buf);
        }
        if let Some(ref contract) = self.verifying_contract {
            let addr = parse_address(contract).unwrap_or(AlloyAddress::ZERO);
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(addr.as_slice());
            encoded.extend_from_slice(&buf);
        }
        if let Some(ref salt) = self.salt {
            let salt_bytes = parse_bytes32(salt).unwrap_or([0u8; 32]);
            encoded.extend_from_slice(&salt_bytes);
        }

        keccak256(&encoded)
    }
}

/// A type field definition for EIP-712.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeField {
    /// The name of the field.
    pub name: String,

    /// The type of the field (e.g., "string", "uint256", "address").
    #[serde(rename = "type")]
    pub field_type: String,
}

/// Typed structured data for EIP-712 signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedData {
    /// The EIP-712 domain.
    pub domain: Eip712Domain,

    /// The type definitions.
    pub types: HashMap<String, Vec<TypeField>>,

    /// The primary type being signed.
    pub primary_type: String,

    /// The message data.
    pub message: Value,
}

impl TypedData {
    /// Creates a new typed data instance.
    ///
    /// # Arguments
    ///
    /// * `domain` - The EIP-712 domain separator parameters
    /// * `types` - JSON object containing type definitions
    /// * `primary_type` - The name of the primary type being signed
    /// * `message` - The message data as a JSON value
    ///
    /// # Returns
    ///
    /// A new [`TypedData`] instance.
    #[must_use]
    pub fn new(domain: Eip712Domain, types: Value, primary_type: String, message: Value) -> Self {
        let types_map = parse_types(&types);
        Self {
            domain,
            types: types_map,
            primary_type,
            message,
        }
    }

    /// Computes the signing hash for this typed data.
    ///
    /// The hash is computed as:
    /// `keccak256("\x19\x01" || domainSeparator || hashStruct(message))`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the 32-byte hash to sign.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTypedData`] if the type definitions or message
    /// are malformed.
    pub fn signing_hash(&self) -> Result<B256> {
        let domain_separator = self.domain.separator_hash();
        let struct_hash = self.hash_struct(&self.primary_type, &self.message)?;

        // Compute final hash: keccak256("\x19\x01" || domainSeparator || structHash)
        let mut data = Vec::with_capacity(2 + 32 + 32);
        data.extend_from_slice(&[0x19, 0x01]);
        data.extend_from_slice(domain_separator.as_slice());
        data.extend_from_slice(struct_hash.as_slice());

        Ok(keccak256(&data))
    }

    /// Computes the hash of a struct.
    ///
    /// `hashStruct(s) = keccak256(typeHash || encodeData(s))`
    fn hash_struct(&self, type_name: &str, data: &Value) -> Result<B256> {
        let type_hash = self.type_hash(type_name)?;
        let encoded_data = self.encode_data(type_name, data)?;

        let mut buf = Vec::with_capacity(32 + encoded_data.len());
        buf.extend_from_slice(type_hash.as_slice());
        buf.extend_from_slice(&encoded_data);

        Ok(keccak256(&buf))
    }

    /// Computes the type hash for a given type name.
    ///
    /// `typeHash = keccak256(encodeType(type))`
    fn type_hash(&self, type_name: &str) -> Result<B256> {
        let type_string = self.encode_type(type_name)?;
        Ok(keccak256(type_string.as_bytes()))
    }

    /// Encodes the type definition as a string.
    fn encode_type(&self, type_name: &str) -> Result<String> {
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| Error::UndefinedType(type_name.to_string()))?;

        let mut result = format!("{type_name}(");
        let field_strings: Vec<String> = fields
            .iter()
            .map(|f| format!("{} {}", f.field_type, f.name))
            .collect();
        result.push_str(&field_strings.join(","));
        result.push(')');

        // Add referenced types (sorted alphabetically)
        let mut referenced_types: Vec<&str> = Vec::new();
        for field in fields {
            if let Some(ref_type) = self.get_referenced_type(&field.field_type)
                && ref_type != type_name
                && !referenced_types.contains(&ref_type)
            {
                referenced_types.push(ref_type);
            }
        }
        referenced_types.sort();

        for ref_type in referenced_types {
            let ref_fields = self
                .types
                .get(ref_type)
                .ok_or_else(|| Error::UndefinedType(ref_type.to_string()))?;

            result.push_str(ref_type);
            result.push('(');
            let ref_field_strings: Vec<String> = ref_fields
                .iter()
                .map(|f| format!("{} {}", f.field_type, f.name))
                .collect();
            result.push_str(&ref_field_strings.join(","));
            result.push(')');
        }

        Ok(result)
    }

    /// Gets the referenced struct type from a field type, if any.
    fn get_referenced_type<'a>(&self, field_type: &'a str) -> Option<&'a str> {
        // Handle array types
        let base_type = field_type.strip_suffix("[]").unwrap_or(field_type);

        // Check if it's a struct type (not a primitive)
        if self.types.contains_key(base_type) {
            Some(base_type)
        } else {
            None
        }
    }

    /// Encodes the data according to the type definition.
    fn encode_data(&self, type_name: &str, data: &Value) -> Result<Vec<u8>> {
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| Error::UndefinedType(type_name.to_string()))?;

        let obj = data
            .as_object()
            .ok_or_else(|| Error::InvalidTypedData("expected object".to_string()))?;

        let mut encoded = Vec::new();

        for field in fields {
            let value = obj
                .get(&field.name)
                .ok_or_else(|| Error::InvalidTypedData(format!("missing field: {}", field.name)))?;

            let field_encoded = self.encode_field(&field.field_type, value)?;
            encoded.extend_from_slice(&field_encoded);
        }

        Ok(encoded)
    }

    /// Encodes a single field value.
    fn encode_field(&self, field_type: &str, value: &Value) -> Result<Vec<u8>> {
        // Handle array types
        if let Some(base_type) = field_type.strip_suffix("[]") {
            let arr = value
                .as_array()
                .ok_or_else(|| Error::InvalidTypedData("expected array".to_string()))?;

            let mut items_encoded = Vec::new();
            for item in arr {
                items_encoded.extend_from_slice(&self.encode_field(base_type, item)?);
            }
            return Ok(keccak256(&items_encoded).to_vec());
        }

        // Handle struct types
        if self.types.contains_key(field_type) {
            let hash = self.hash_struct(field_type, value)?;
            return Ok(hash.to_vec());
        }

        // Handle primitive types
        encode_primitive(field_type, value)
    }

    /// Parses typed data from a JSON string.
    ///
    /// # Arguments
    ///
    /// * `json` - A JSON string containing the typed data
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the parsed typed data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JsonError`] if parsing fails.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serializes the typed data to JSON.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JsonError`] if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Parses type definitions from JSON.
fn parse_types(types: &Value) -> HashMap<String, Vec<TypeField>> {
    let mut result = HashMap::new();

    if let Some(obj) = types.as_object() {
        for (type_name, fields) in obj {
            if let Some(arr) = fields.as_array() {
                let type_fields: Vec<TypeField> = arr
                    .iter()
                    .filter_map(|f| serde_json::from_value(f.clone()).ok())
                    .collect();
                result.insert(type_name.clone(), type_fields);
            }
        }
    }

    result
}

/// Encodes a primitive type value.
fn encode_primitive(field_type: &str, value: &Value) -> Result<Vec<u8>> {
    let mut buf = [0u8; 32];

    match field_type {
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::InvalidTypedData("expected string".to_string()))?;
            Ok(keccak256(s.as_bytes()).to_vec())
        }
        "bytes" => {
            let hex_str = value
                .as_str()
                .ok_or_else(|| Error::InvalidTypedData("expected hex string".to_string()))?;
            let bytes = parse_hex_bytes(hex_str)?;
            Ok(keccak256(&bytes).to_vec())
        }
        "bool" => {
            let b = value
                .as_bool()
                .ok_or_else(|| Error::InvalidTypedData("expected bool".to_string()))?;
            buf[31] = u8::from(b);
            Ok(buf.to_vec())
        }
        "address" => {
            let addr_str = value
                .as_str()
                .ok_or_else(|| Error::InvalidTypedData("expected address string".to_string()))?;
            let addr = parse_address(addr_str)
                .map_err(|e| Error::InvalidTypedData(format!("invalid address: {e}")))?;
            buf[12..].copy_from_slice(addr.as_slice());
            Ok(buf.to_vec())
        }
        t if t.starts_with("bytes") => {
            // Fixed-size bytes (bytes1 to bytes32)
            let hex_str = value
                .as_str()
                .ok_or_else(|| Error::InvalidTypedData("expected hex string".to_string()))?;
            let bytes = parse_hex_bytes(hex_str)?;

            let size: usize = t[5..]
                .parse()
                .map_err(|_| Error::InvalidTypedData(format!("invalid bytes type: {t}")))?;

            if bytes.len() > size {
                return Err(Error::InvalidTypedData(format!(
                    "bytes too long for {t}: {} > {size}",
                    bytes.len()
                )));
            }

            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(buf.to_vec())
        }
        t if t.starts_with("uint") || t.starts_with("int") => {
            let uint = parse_uint(value)?;
            Ok(uint.to_be_bytes::<32>().to_vec())
        }
        _ => Err(Error::InvalidTypedData(format!(
            "unsupported type: {field_type}"
        ))),
    }
}

/// Parses an address from a hex string.
fn parse_address(s: &str) -> Result<AlloyAddress> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 20 {
        return Err(Error::InvalidTypedData(format!(
            "invalid address length: {}",
            bytes.len()
        )));
    }
    Ok(AlloyAddress::from_slice(&bytes))
}

/// Parses a bytes32 value from a hex string.
fn parse_bytes32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(Error::InvalidTypedData(format!(
            "invalid bytes32 length: {}",
            bytes.len()
        )));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Parses hex bytes.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

/// Parses a uint value from JSON.
fn parse_uint(value: &Value) -> Result<U256> {
    if let Some(n) = value.as_u64() {
        return Ok(U256::from(n));
    }
    if let Some(s) = value.as_str() {
        // Handle hex strings
        if let Some(hex_str) = s.strip_prefix("0x") {
            return U256::from_str_radix(hex_str, 16)
                .map_err(|_| Error::InvalidTypedData(format!("invalid hex uint: {s}")));
        }
        // Handle decimal strings
        return U256::from_str_radix(s, 10)
            .map_err(|_| Error::InvalidTypedData(format!("invalid uint: {s}")));
    }
    Err(Error::InvalidTypedData("expected uint".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn domain_separator_hash() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(1),
            verifying_contract: None,
            salt: None,
        };

        let hash = domain.separator_hash();
        assert!(!hash.is_zero());
    }

    #[test]
    fn domain_separator_with_all_fields() {
        let domain = Eip712Domain {
            name: Some("Full Domain".to_string()),
            version: Some("2".to_string()),
            chain_id: Some(137),
            verifying_contract: Some("0x0000000000000000000000000000000000000001".to_string()),
            salt: Some(
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
        };

        let hash = domain.separator_hash();
        assert!(!hash.is_zero());
    }

    #[test]
    fn typed_data_signing_hash() {
        let domain = Eip712Domain {
            name: Some("Test DApp".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(1),
            verifying_contract: None,
            salt: None,
        };

        let types = json!({
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ]
        });

        let message = json!({
            "name": "Alice",
            "wallet": "0x0000000000000000000000000000000000000001"
        });

        let typed_data = TypedData::new(domain, types, "Person".to_string(), message);
        let hash = typed_data.signing_hash().unwrap();

        assert!(!hash.is_zero());
    }

    #[test]
    fn typed_data_with_nested_types() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(1),
            verifying_contract: None,
            salt: None,
        };

        let types = json!({
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ]
        });

        let message = json!({
            "from": {
                "name": "Alice",
                "wallet": "0x0000000000000000000000000000000000000001"
            },
            "to": {
                "name": "Bob",
                "wallet": "0x0000000000000000000000000000000000000002"
            },
            "contents": "Hello, Bob!"
        });

        let typed_data = TypedData::new(domain, types, "Mail".to_string(), message);
        let hash = typed_data.signing_hash().unwrap();

        assert!(!hash.is_zero());
    }

    #[test]
    fn typed_data_with_array() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(1),
            verifying_contract: None,
            salt: None,
        };

        let types = json!({
            "Batch": [
                {"name": "recipients", "type": "address[]"},
                {"name": "amounts", "type": "uint256[]"}
            ]
        });

        let message = json!({
            "recipients": [
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"
            ],
            "amounts": ["1000000000000000000", "2000000000000000000"]
        });

        let typed_data = TypedData::new(domain, types, "Batch".to_string(), message);
        let hash = typed_data.signing_hash().unwrap();

        assert!(!hash.is_zero());
    }

    #[test]
    fn typed_data_json_roundtrip() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(1),
            verifying_contract: None,
            salt: None,
        };

        let types = json!({
            "Simple": [
                {"name": "value", "type": "uint256"}
            ]
        });

        let message = json!({
            "value": 42
        });

        let original = TypedData::new(domain, types, "Simple".to_string(), message);
        let json = original.to_json().unwrap();
        let recovered = TypedData::from_json(&json).unwrap();

        // Verify the signing hashes match
        assert_eq!(
            original.signing_hash().unwrap(),
            recovered.signing_hash().unwrap()
        );
    }

    #[test]
    fn encode_primitive_types() {
        // Test string
        let result = encode_primitive("string", &json!("hello")).unwrap();
        assert_eq!(result.len(), 32);

        // Test bool
        let result = encode_primitive("bool", &json!(true)).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[31], 1);

        // Test uint256
        let result = encode_primitive("uint256", &json!(42)).unwrap();
        assert_eq!(result.len(), 32);

        // Test address
        let result = encode_primitive(
            "address",
            &json!("0x0000000000000000000000000000000000000001"),
        )
        .unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn undefined_type_error() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: None,
            chain_id: None,
            verifying_contract: None,
            salt: None,
        };

        let types = json!({});

        let message = json!({"foo": "bar"});

        let typed_data = TypedData::new(domain, types, "NonExistent".to_string(), message);
        let result = typed_data.signing_hash();

        assert!(matches!(result, Err(Error::UndefinedType(_))));
    }
}
