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
//! let typed_data = TypedData::new(domain, types, "Person".to_string(), message).unwrap();
//! let hash = typed_data.signing_hash().unwrap();
//! ```
//!
//! [EIP-712]: https://eips.ethereum.org/EIPS/eip-712

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address as AlloyAddress, B256, I256, Sign, U256, keccak256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Maximum allowed nesting depth for structs and multi-dimensional arrays.
const MAX_RECURSION_DEPTH: usize = 64;

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
    pub chain_id: Option<U256>,

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
    /// A [`Result`] containing the 32-byte domain separator hash.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomainSeparator`] if `verifying_contract` is not a valid
    /// 20-byte address or if `salt` is not a valid 32-byte value.
    pub fn separator_hash(&self) -> Result<B256> {
        let mut type_fields = Vec::with_capacity(5);
        if self.name.is_some() {
            type_fields.push("string name");
        }
        if self.version.is_some() {
            type_fields.push("string version");
        }
        if self.chain_id.is_some() {
            type_fields.push("uint256 chainId");
        }
        if self.verifying_contract.is_some() {
            type_fields.push("address verifyingContract");
        }
        if self.salt.is_some() {
            type_fields.push("bytes32 salt");
        }

        let type_string = format!("EIP712Domain({})", type_fields.join(","));
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
            encoded.extend_from_slice(&chain_id.to_be_bytes::<32>());
        }
        if let Some(ref contract) = self.verifying_contract {
            let addr = parse_address(contract).map_err(|e| {
                Error::InvalidDomainSeparator(format!("invalid verifyingContract: {e}"))
            })?;
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(addr.as_slice());
            encoded.extend_from_slice(&buf);
        }
        if let Some(ref salt) = self.salt {
            let salt_bytes = parse_bytes32(salt)
                .map_err(|e| Error::InvalidDomainSeparator(format!("invalid salt: {e}")))?;
            encoded.extend_from_slice(&salt_bytes);
        }

        Ok(keccak256(&encoded))
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
    /// Creates a new validated typed data instance from a JSON types object.
    ///
    /// # Arguments
    ///
    /// * `domain` - The EIP-712 domain separator parameters
    /// * `types` - JSON object mapping type names to arrays of `{name, type}` field objects
    /// * `primary_type` - The name of the primary type being signed
    /// * `message` - The message data as a JSON value
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the new [`TypedData`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTypedData`] if `types` is not a JSON object or contains
    /// malformed type or field definitions.
    pub fn try_new(
        domain: Eip712Domain,
        types: Value,
        primary_type: String,
        message: Value,
    ) -> Result<Self> {
        let types_map = parse_types(&types)?;
        Ok(Self {
            domain,
            types: types_map,
            primary_type,
            message,
        })
    }

    /// Creates a new validated typed data instance.
    ///
    /// Equivalent to [`Self::try_new`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTypedData`] if `types` is not a JSON object or contains
    /// malformed type or field definitions.
    pub fn new(
        domain: Eip712Domain,
        types: Value,
        primary_type: String,
        message: Value,
    ) -> Result<Self> {
        Self::try_new(domain, types, primary_type, message)
    }

    /// Computes the signing hash for this typed data.
    ///
    /// The hash is computed as:
    /// `keccak256("\x19\x01" || domainSeparator || hashStruct(message))`
    ///
    /// When `types` explicitly defines `EIP712Domain`, the domain is hashed dynamically
    /// using that type definition; otherwise, the standard [`Eip712Domain::separator_hash`]
    /// derivation is used.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the 32-byte hash to sign.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomainSeparator`], [`Error::UndefinedType`], or
    /// [`Error::InvalidTypedData`] if the domain, type definitions, or message are invalid.
    pub fn signing_hash(&self) -> Result<B256> {
        let domain_separator = if self.types.contains_key("EIP712Domain") {
            let domain_value = serde_json::to_value(&self.domain)?;
            self.hash_struct("EIP712Domain", &domain_value, 0)
                .map_err(|e| match e {
                    Error::InvalidDomainSeparator(_) => e,
                    other => Error::InvalidDomainSeparator(other.to_string()),
                })?
        } else {
            self.domain.separator_hash()?
        };

        let struct_hash = self.hash_struct(&self.primary_type, &self.message, 0)?;

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
    fn hash_struct(&self, type_name: &str, data: &Value, depth: usize) -> Result<B256> {
        if depth > MAX_RECURSION_DEPTH {
            return Err(Error::InvalidTypedData(
                "maximum recursion depth exceeded".to_string(),
            ));
        }

        let type_hash = self.type_hash(type_name)?;
        let encoded_data = self.encode_data(type_name, data, depth)?;

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

    /// Encodes the type definition and all transitively referenced struct types.
    fn encode_type(&self, type_name: &str) -> Result<String> {
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| Error::UndefinedType(type_name.to_string()))?;

        let mut visited = HashSet::new();
        self.collect_referenced_types(type_name, &mut visited, 0)?;

        let mut result = format_struct_type(type_name, fields);

        // Sort all transitively referenced types alphabetically, excluding the root type
        let mut referenced_types: Vec<&str> = visited
            .into_iter()
            .filter(|&name| name != type_name)
            .collect();
        referenced_types.sort_unstable();

        for ref_type in referenced_types {
            let ref_fields = self
                .types
                .get(ref_type)
                .ok_or_else(|| Error::UndefinedType(ref_type.to_string()))?;
            result.push_str(&format_struct_type(ref_type, ref_fields));
        }

        Ok(result)
    }

    /// Recursively collects transitively referenced struct types while bounding
    /// type-graph traversal depth.
    ///
    /// Already-encountered struct types are skipped without error because EIP-712
    /// permits recursive struct definitions (for example, `Node { Node[] children }`).
    /// Message encoding enforces [`MAX_RECURSION_DEPTH`] independently.
    fn collect_referenced_types<'a>(
        &'a self,
        type_name: &'a str,
        visited: &mut HashSet<&'a str>,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_RECURSION_DEPTH {
            return Err(Error::InvalidTypedData(
                "maximum type recursion depth exceeded".to_string(),
            ));
        }

        if !visited.insert(type_name) {
            return Ok(());
        }

        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| Error::UndefinedType(type_name.to_string()))?;

        for field in fields {
            let base_type = self.get_referenced_type(&field.field_type)?;
            if let Some(ref_type) = base_type
                && !visited.contains(ref_type)
            {
                self.collect_referenced_types(ref_type, visited, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Strips all array dimensions and returns the referenced struct type name, if any.
    ///
    /// Validates array syntax and rejects undefined non-primitive base types.
    fn get_referenced_type<'a>(&'a self, field_type: &'a str) -> Result<Option<&'a str>> {
        let base_type = strip_all_array_dimensions(field_type)?;

        if let Some((key, _)) = self.types.get_key_value(base_type) {
            Ok(Some(key.as_str()))
        } else if is_primitive_type(base_type) {
            Ok(None)
        } else {
            Err(Error::UndefinedType(base_type.to_string()))
        }
    }

    /// Encodes the data according to the type definition.
    fn encode_data(&self, type_name: &str, data: &Value, depth: usize) -> Result<Vec<u8>> {
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| Error::UndefinedType(type_name.to_string()))?;

        let obj = data
            .as_object()
            .ok_or_else(|| Error::InvalidTypedData("expected object".to_string()))?;

        let mut encoded = Vec::with_capacity(fields.len() * 32);

        for field in fields {
            let value = obj
                .get(&field.name)
                .ok_or_else(|| Error::InvalidTypedData(format!("missing field: {}", field.name)))?;

            let field_encoded = self.encode_field(&field.field_type, value, depth + 1)?;
            encoded.extend_from_slice(&field_encoded);
        }

        Ok(encoded)
    }

    /// Encodes a single field value (arrays, structs, or primitives).
    fn encode_field(&self, field_type: &str, value: &Value, depth: usize) -> Result<Vec<u8>> {
        if depth > MAX_RECURSION_DEPTH {
            return Err(Error::InvalidTypedData(
                "maximum recursion depth exceeded".to_string(),
            ));
        }

        // Peel outermost trailing array dimension (`[]` or `[N]`)
        if let Some((inner_type, fixed_len)) = parse_array_suffix(field_type)? {
            let arr = value
                .as_array()
                .ok_or_else(|| Error::InvalidTypedData("expected array".to_string()))?;

            if let Some(expected_len) = fixed_len
                && arr.len() != expected_len
            {
                return Err(Error::InvalidTypedData(format!(
                    "expected array of length {expected_len} for {field_type}, got {}",
                    arr.len()
                )));
            }

            let mut items_encoded = Vec::with_capacity(arr.len() * 32);
            for item in arr {
                items_encoded.extend_from_slice(&self.encode_field(inner_type, item, depth + 1)?);
            }
            return Ok(keccak256(&items_encoded).to_vec());
        }

        // Handle struct types
        if self.types.contains_key(field_type) {
            let hash = self.hash_struct(field_type, value, depth + 1)?;
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

/// Formats a single struct definition as `Name(type1 field1,type2 field2)`.
fn format_struct_type(type_name: &str, fields: &[TypeField]) -> String {
    let mut result = format!("{type_name}(");
    let field_strings: Vec<String> = fields
        .iter()
        .map(|f| format!("{} {}", f.field_type, f.name))
        .collect();
    result.push_str(&field_strings.join(","));
    result.push(')');
    result
}

/// Peels a single outermost array suffix (`[]` or `[N]`) from a type name.
///
/// Returns `Ok(Some((inner_type, None)))` for dynamic arrays `T[]`,
/// `Ok(Some((inner_type, Some(n))))` for fixed arrays `T[N]`,
/// and `Ok(None)` if `field_type` is not an array type.
fn parse_array_suffix(field_type: &str) -> Result<Option<(&str, Option<usize>)>> {
    if let Some(before_close) = field_type.strip_suffix(']') {
        let open_idx = before_close.rfind('[').ok_or_else(|| {
            Error::InvalidTypedData(format!("malformed array type: {field_type}"))
        })?;

        let inner = &before_close[..open_idx];
        if inner.is_empty() {
            return Err(Error::InvalidTypedData(format!(
                "missing element type in array type: {field_type}"
            )));
        }

        let len_str = &before_close[open_idx + 1..];
        if len_str.is_empty() {
            return Ok(Some((inner, None)));
        }

        if !len_str.bytes().all(|b| b.is_ascii_digit()) || len_str.starts_with('0') {
            return Err(Error::InvalidTypedData(format!(
                "invalid fixed array length in type: {field_type}"
            )));
        }

        let len: usize = len_str.parse().map_err(|_| {
            Error::InvalidTypedData(format!("invalid fixed array length in type: {field_type}"))
        })?;
        if len == 0 {
            return Err(Error::InvalidTypedData(format!(
                "zero-length fixed array not allowed: {field_type}"
            )));
        }

        Ok(Some((inner, Some(len))))
    } else if field_type.contains('[') || field_type.contains(']') {
        Err(Error::InvalidTypedData(format!(
            "malformed array type: {field_type}"
        )))
    } else {
        Ok(None)
    }
}

/// Strips all trailing array dimensions from a type name, enforcing a depth cap.
fn strip_all_array_dimensions(mut field_type: &str) -> Result<&str> {
    let mut dims = 0usize;
    while let Some((inner, _)) = parse_array_suffix(field_type)? {
        dims += 1;
        if dims > MAX_RECURSION_DEPTH {
            return Err(Error::InvalidTypedData(
                "maximum array nesting depth exceeded".to_string(),
            ));
        }
        field_type = inner;
    }
    Ok(field_type)
}

/// Parses a canonical positive integer bit width (`8, 16, ..., 256`).
fn parse_int_bit_width(suffix: &str) -> Option<u16> {
    if suffix.is_empty() || suffix.starts_with('0') || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bits: u16 = suffix.parse().ok()?;
    if (8..=256).contains(&bits) && bits.is_multiple_of(8) {
        Some(bits)
    } else {
        None
    }
}

/// Parses a canonical fixed-bytes size (`1..=32`).
fn parse_fixed_bytes_size(suffix: &str) -> Option<usize> {
    if suffix.is_empty() || suffix.starts_with('0') || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let size: usize = suffix.parse().ok()?;
    if (1..=32).contains(&size) {
        Some(size)
    } else {
        None
    }
}

/// Checks if a base type name is a valid EIP-712 atomic or dynamic primitive type.
fn is_primitive_type(base_type: &str) -> bool {
    match base_type {
        "string" | "bytes" | "bool" | "address" => true,
        t if t.starts_with("bytes") => parse_fixed_bytes_size(&t[5..]).is_some(),
        t if t.starts_with("uint") => parse_int_bit_width(&t[4..]).is_some(),
        t if t.starts_with("int") => parse_int_bit_width(&t[3..]).is_some(),
        _ => false,
    }
}

/// Strictly parses type definitions from JSON without silently dropping malformed fields.
fn parse_types(types: &Value) -> Result<HashMap<String, Vec<TypeField>>> {
    let obj = types.as_object().ok_or_else(|| {
        Error::InvalidTypedData("EIP-712 types must be a JSON object".to_string())
    })?;

    let mut result = HashMap::with_capacity(obj.len());

    for (type_name, fields_val) in obj {
        let arr = fields_val.as_array().ok_or_else(|| {
            Error::InvalidTypedData(format!(
                "fields for type '{type_name}' must be a JSON array"
            ))
        })?;

        let mut type_fields = Vec::with_capacity(arr.len());
        for (idx, field_val) in arr.iter().enumerate() {
            let field: TypeField = serde_json::from_value(field_val.clone()).map_err(|e| {
                Error::InvalidTypedData(format!(
                    "malformed field #{idx} in type '{type_name}': {e}"
                ))
            })?;
            if field.name.is_empty() || field.field_type.is_empty() {
                return Err(Error::InvalidTypedData(format!(
                    "empty field name or type at #{idx} in type '{type_name}'"
                )));
            }
            type_fields.push(field);
        }

        result.insert(type_name.clone(), type_fields);
    }

    Ok(result)
}

/// Encodes a primitive type value into 32 bytes.
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
            let size = parse_fixed_bytes_size(&t[5..])
                .ok_or_else(|| Error::InvalidTypedData(format!("invalid bytes type: {t}")))?;

            let hex_str = value
                .as_str()
                .ok_or_else(|| Error::InvalidTypedData("expected hex string".to_string()))?;
            let bytes = parse_hex_bytes(hex_str)?;

            if bytes.len() > size {
                return Err(Error::InvalidTypedData(format!(
                    "bytes too long for {t}: {} > {size}",
                    bytes.len()
                )));
            }

            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(buf.to_vec())
        }
        t if t.starts_with("uint") => {
            let bits = parse_int_bit_width(&t[4..])
                .ok_or_else(|| Error::InvalidTypedData(format!("invalid uint type: {t}")))?;

            let uint = parse_uint(value)?;
            if bits < 256 {
                let max = (U256::from(1u8) << usize::from(bits)) - U256::from(1u8);
                if uint > max {
                    return Err(Error::InvalidTypedData(format!(
                        "value {uint} exceeds maximum for {t}"
                    )));
                }
            }
            Ok(uint.to_be_bytes::<32>().to_vec())
        }
        t if t.starts_with("int") => {
            let bits = parse_int_bit_width(&t[3..])
                .ok_or_else(|| Error::InvalidTypedData(format!("invalid int type: {t}")))?;

            let signed = parse_int(value)?;
            if bits < 256 {
                let shift = usize::from(bits - 1);
                let min = -(I256::ONE << shift);
                let max = (I256::ONE << shift) - I256::ONE;
                if signed < min || signed > max {
                    return Err(Error::InvalidTypedData(format!(
                        "value {signed} out of range for {t}"
                    )));
                }
            }
            Ok(signed.to_be_bytes::<32>().to_vec())
        }
        _ => Err(Error::InvalidTypedData(format!(
            "unsupported type: {field_type}"
        ))),
    }
}

/// Strips an optional `0x` or `0X` prefix from a hex string.
fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// Parses an address from a hex string.
fn parse_address(s: &str) -> Result<AlloyAddress> {
    let s = strip_hex_prefix(s);
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
    let s = strip_hex_prefix(s);
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

/// Parses hex bytes (accepting `0x`, `0X`, or unprefixed hex).
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = strip_hex_prefix(s);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    Ok(hex::decode(s)?)
}

/// Parses an unsigned 256-bit integer from JSON (number, decimal string, or `0x`/`0X` hex string).
fn parse_uint(value: &Value) -> Result<U256> {
    if let Some(n) = value.as_u64() {
        return Ok(U256::from(n));
    }
    if let Some(s) = value.as_str() {
        if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            if hex_str.is_empty() {
                return Err(Error::InvalidTypedData(format!("invalid hex uint: {s}")));
            }
            return U256::from_str_radix(hex_str, 16)
                .map_err(|_| Error::InvalidTypedData(format!("invalid hex uint: {s}")));
        }
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidTypedData(format!("invalid uint: {s}")));
        }
        return U256::from_str_radix(s, 10)
            .map_err(|_| Error::InvalidTypedData(format!("invalid uint: {s}")));
    }
    Err(Error::InvalidTypedData("expected uint".to_string()))
}

/// Parses a signed 256-bit integer from JSON (integer, decimal string, or signed `0x`/`0X` hex string).
fn parse_int(value: &Value) -> Result<I256> {
    if let Some(n) = value.as_i64() {
        return I256::try_from(n).map_err(|_| Error::InvalidTypedData(format!("invalid int: {n}")));
    }
    if let Some(n) = value.as_u64() {
        return I256::try_from(n).map_err(|_| Error::InvalidTypedData(format!("invalid int: {n}")));
    }
    if let Some(s) = value.as_str() {
        let (sign, rest) = if let Some(r) = s.strip_prefix('-') {
            (Sign::Negative, r)
        } else if let Some(r) = s.strip_prefix('+') {
            (Sign::Positive, r)
        } else {
            (Sign::Positive, s)
        };

        let abs = if let Some(hex_str) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X"))
        {
            if hex_str.is_empty() {
                return Err(Error::InvalidTypedData(format!("invalid hex int: {s}")));
            }
            U256::from_str_radix(hex_str, 16)
                .map_err(|_| Error::InvalidTypedData(format!("invalid hex int: {s}")))?
        } else {
            if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidTypedData(format!("invalid int: {s}")));
            }
            U256::from_str_radix(rest, 10)
                .map_err(|_| Error::InvalidTypedData(format!("invalid int: {s}")))?
        };

        return I256::checked_from_sign_and_abs(sign, abs)
            .ok_or_else(|| Error::InvalidTypedData(format!("signed int overflow: {s}")));
    }
    Err(Error::InvalidTypedData("expected signed int".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn official_eip712_mail_example_vector() {
        let json_str = r#"{
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        }"#;

        let typed_data = TypedData::from_json(json_str).unwrap();

        // Check domain separator
        assert_eq!(
            hex::encode(typed_data.domain.separator_hash().unwrap()),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );

        // Check Mail struct hash
        assert_eq!(
            hex::encode(
                typed_data
                    .hash_struct("Mail", &typed_data.message, 0)
                    .unwrap()
            ),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );

        // Check final EIP-712 signing digest
        assert_eq!(
            hex::encode(typed_data.signing_hash().unwrap()),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn transitive_nested_structs_encode_type_and_hash() {
        let domain = Eip712Domain {
            name: Some("Transitive".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(U256::from(1)),
            verifying_contract: None,
            salt: None,
        };

        // 3-level nesting: Envelope -> Mail -> Person -> Tag
        let types = json!({
            "Envelope": [
                {"name": "mail", "type": "Mail"}
            ],
            "Mail": [
                {"name": "sender", "type": "Person"},
                {"name": "body", "type": "string"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "tag", "type": "Tag"}
            ],
            "Tag": [
                {"name": "label", "type": "string"}
            ]
        });

        let message = json!({
            "mail": {
                "sender": {
                    "name": "Alice",
                    "tag": { "label": "vip" }
                },
                "body": "hi"
            }
        });

        let typed_data = TypedData::new(domain, types, "Envelope".to_string(), message).unwrap();
        let encoded_type = typed_data.encode_type("Envelope").unwrap();

        // All transitive dependencies must be included and sorted alphabetically: Mail, Person, Tag
        assert_eq!(
            encoded_type,
            "Envelope(Mail mail)Mail(Person sender,string body)Person(string name,Tag tag)Tag(string label)"
        );
        assert!(!typed_data.signing_hash().unwrap().is_zero());
    }

    #[test]
    fn fixed_and_multidimensional_arrays() {
        let domain = Eip712Domain {
            name: Some("Arrays".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(U256::from(1)),
            verifying_contract: None,
            salt: None,
        };

        let types = json!({
            "Person": [
                {"name": "name", "type": "string"}
            ],
            "Container": [
                {"name": "pair", "type": "uint256[2]"},
                {"name": "people", "type": "Person[2]"},
                {"name": "matrix", "type": "uint256[][]"},
                {"name": "groups", "type": "Person[2][]"}
            ]
        });

        let message = json!({
            "pair": [1, 2],
            "people": [{"name": "Alice"}, {"name": "Bob"}],
            "matrix": [[1, 2], [3]],
            "groups": [
                [{"name": "A"}, {"name": "B"}],
                [{"name": "C"}, {"name": "D"}]
            ]
        });

        let typed_data =
            TypedData::new(domain, types.clone(), "Container".to_string(), message).unwrap();
        // Person must be discovered through both Person[2] and Person[2][]
        assert_eq!(
            typed_data.encode_type("Container").unwrap(),
            "Container(uint256[2] pair,Person[2] people,uint256[][] matrix,Person[2][] groups)Person(string name)"
        );
        assert!(!typed_data.signing_hash().unwrap().is_zero());

        // Fixed array length mismatch must fail
        let bad_message = json!({
            "pair": [1, 2, 3],
            "people": [{"name": "Alice"}, {"name": "Bob"}],
            "matrix": [],
            "groups": []
        });
        let bad = TypedData::new(
            Eip712Domain {
                name: Some("Arrays".to_string()),
                version: None,
                chain_id: None,
                verifying_contract: None,
                salt: None,
            },
            types,
            "Container".to_string(),
            bad_message,
        )
        .unwrap();
        assert!(matches!(
            bad.signing_hash(),
            Err(Error::InvalidTypedData(_))
        ));
    }

    #[test]
    fn signed_and_unsigned_integers_strict_validation() {
        // int8(-1) sign-extended to 32 bytes = all 0xFF
        let neg_one = encode_primitive("int8", &json!(-1)).unwrap();
        assert_eq!(neg_one, vec![0xFF; 32]);

        // int8(-128) via decimal string
        let min_i8 = encode_primitive("int8", &json!("-128")).unwrap();
        let mut expected_min_i8 = vec![0xFF; 32];
        expected_min_i8[31] = 0x80;
        assert_eq!(min_i8, expected_min_i8);

        // int8(-129) and int8(128) must be rejected
        assert!(encode_primitive("int8", &json!(-129)).is_err());
        assert!(encode_primitive("int8", &json!(128)).is_err());

        // int24 signed hex "-0x100"
        let neg_256 = encode_primitive("int24", &json!("-0x100")).unwrap();
        let mut expected_neg_256 = vec![0xFF; 32];
        expected_neg_256[30] = 0xFF;
        expected_neg_256[31] = 0x00;
        assert_eq!(neg_256, expected_neg_256);

        // int128 and int256 negative values
        assert!(
            encode_primitive("int128", &json!("-170141183460469231731687303715884105728")).is_ok()
        );
        assert!(
            encode_primitive("int128", &json!("-170141183460469231731687303715884105729")).is_err()
        );
        assert!(
            encode_primitive(
                "int256",
                &json!(
                    "-57896044618658097711785492504343953926634992332820282019728792003956564819968"
                )
            )
            .is_ok()
        );
        assert!(
            encode_primitive(
                "int256",
                &json!(
                    "-57896044618658097711785492504343953926634992332820282019728792003956564819969"
                )
            )
            .is_err()
        );

        // uint8 range enforcement + 0X prefix
        assert!(encode_primitive("uint8", &json!(255)).is_ok());
        assert!(encode_primitive("uint8", &json!("0Xff")).is_ok());
        assert!(encode_primitive("uint8", &json!(256)).is_err());
        assert!(encode_primitive("uint8", &json!(-1)).is_err());

        // Invalid integer type names must be rejected
        for bad_type in [
            "integer", "uint7", "uint512", "int0", "uintfoo", "uint", "int", "uint08",
        ] {
            assert!(
                encode_primitive(bad_type, &json!(1)).is_err(),
                "expected {bad_type} to be rejected"
            );
        }
    }

    #[test]
    fn fixed_bytes_bounds_check() {
        assert!(encode_primitive("bytes1", &json!("0xab")).is_ok());
        assert!(encode_primitive("bytes1", &json!("0Xab")).is_ok());
        assert!(encode_primitive("bytes32", &json!(format!("0x{}", "11".repeat(32)))).is_ok());

        // bytes0, bytes33, bytes64 must not panic and must return Err
        assert!(encode_primitive("bytes0", &json!("0x")).is_err());
        assert!(encode_primitive("bytes33", &json!("0x01")).is_err());
        assert!(encode_primitive("bytes64", &json!("0x01")).is_err());
        assert!(encode_primitive("bytesfoo", &json!("0x01")).is_err());
        // Too many bytes for bytes1
        assert!(encode_primitive("bytes1", &json!("0xabcd")).is_err());
    }

    #[test]
    fn allows_finite_recursive_types_and_rejects_excessive_depth() {
        let domain = Eip712Domain {
            name: Some("Recursion".to_string()),
            version: None,
            chain_id: None,
            verifying_contract: None,
            salt: None,
        };

        // Valid self-recursive schema terminating via empty array
        let recursive_tree = json!({
            "Node": [
                {"name": "label", "type": "string"},
                {"name": "children", "type": "Node[]"}
            ]
        });
        let leaf = TypedData::new(
            domain.clone(),
            recursive_tree.clone(),
            "Node".to_string(),
            json!({"label": "root", "children": []}),
        )
        .unwrap();
        assert_eq!(
            leaf.encode_type("Node").unwrap(),
            "Node(string label,Node[] children)"
        );
        let leaf_hash = leaf.signing_hash().unwrap();
        assert!(!leaf_hash.is_zero());

        // Valid nested finite recursive message
        let nested = TypedData::new(
            domain.clone(),
            recursive_tree.clone(),
            "Node".to_string(),
            json!({
                "label": "root",
                "children": [
                    {"label": "child", "children": []}
                ]
            }),
        )
        .unwrap();
        assert_ne!(nested.signing_hash().unwrap(), leaf_hash);

        // Valid mutually recursive schema terminating via empty array
        let mutual_recursive = json!({
            "A": [{"name": "items", "type": "B[]"}],
            "B": [{"name": "owners", "type": "A[]"}]
        });
        let mutual = TypedData::new(
            domain.clone(),
            mutual_recursive,
            "A".to_string(),
            json!({"items": [{"owners": []}]}),
        )
        .unwrap();
        assert_eq!(
            mutual.encode_type("A").unwrap(),
            "A(B[] items)B(A[] owners)"
        );
        assert_eq!(
            mutual.encode_type("B").unwrap(),
            "B(A[] owners)A(B[] items)"
        );
        assert!(!mutual.signing_hash().unwrap().is_zero());

        // Recursive message exceeding MAX_RECURSION_DEPTH must fail cleanly
        let mut deep_node = json!({"label": "leaf", "children": []});
        for _ in 0..=MAX_RECURSION_DEPTH {
            deep_node = json!({"label": "branch", "children": [deep_node]});
        }
        let too_deep = TypedData::new(
            domain.clone(),
            recursive_tree,
            "Node".to_string(),
            deep_node,
        )
        .unwrap();
        assert!(matches!(
            too_deep.signing_hash(),
            Err(Error::InvalidTypedData(_))
        ));

        // Non-terminating direct cycle with incomplete message fails cleanly
        let self_cycle = json!({
            "Node": [
                {"name": "next", "type": "Node"}
            ]
        });
        let td = TypedData::new(
            domain.clone(),
            self_cycle,
            "Node".to_string(),
            json!({"next": {}}),
        )
        .unwrap();
        assert!(matches!(td.signing_hash(), Err(Error::InvalidTypedData(_))));

        // Deeply nested array > MAX_RECURSION_DEPTH
        let deep_array_type = format!("uint256{}", "[]".repeat(MAX_RECURSION_DEPTH + 2));
        let deep_types = json!({
            "Deep": [{"name": "x", "type": deep_array_type}]
        });
        let td3 = TypedData::new(domain, deep_types, "Deep".to_string(), json!({"x": []})).unwrap();
        assert!(matches!(
            td3.signing_hash(),
            Err(Error::InvalidTypedData(_))
        ));
    }

    #[test]
    fn domain_chain_id_string_hex_and_custom_domain() {
        // Decimal string chainId
        let json_dec = r#"{
            "domain": { "name": "D", "chainId": "137" },
            "types": { "Msg": [{"name": "v", "type": "uint256"}] },
            "primaryType": "Msg",
            "message": { "v": 1 }
        }"#;
        let td_dec = TypedData::from_json(json_dec).unwrap();
        assert_eq!(td_dec.domain.chain_id, Some(U256::from(137)));

        // Hex string chainId
        let json_hex = r#"{
            "domain": { "name": "D", "chainId": "0x89" },
            "types": { "Msg": [{"name": "v", "type": "uint256"}] },
            "primaryType": "Msg",
            "message": { "v": 1 }
        }"#;
        let td_hex = TypedData::from_json(json_hex).unwrap();
        assert_eq!(td_hex.domain.chain_id, Some(U256::from(137)));
        assert_eq!(
            td_dec.signing_hash().unwrap(),
            td_hex.signing_hash().unwrap()
        );

        // Custom EIP712Domain field ordering in `types` changes domain separator dynamically
        let custom_domain_json = r#"{
            "domain": { "name": "Custom", "version": "1", "chainId": 1 },
            "types": {
                "EIP712Domain": [
                    {"name": "chainId", "type": "uint256"},
                    {"name": "name", "type": "string"}
                ],
                "Msg": [{"name": "v", "type": "uint256"}]
            },
            "primaryType": "Msg",
            "message": { "v": 1 }
        }"#;
        let td_custom = TypedData::from_json(custom_domain_json).unwrap();
        // Manually compute expected domain separator for EIP712Domain(uint256 chainId,string name)
        let type_hash = keccak256(b"EIP712Domain(uint256 chainId,string name)");
        let mut expected_dom = type_hash.to_vec();
        expected_dom.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        expected_dom.extend_from_slice(keccak256(b"Custom").as_slice());
        let dom_sep = keccak256(&expected_dom);

        let struct_hash = td_custom.hash_struct("Msg", &td_custom.message, 0).unwrap();
        let mut expected_final = vec![0x19, 0x01];
        expected_final.extend_from_slice(dom_sep.as_slice());
        expected_final.extend_from_slice(struct_hash.as_slice());
        assert_eq!(
            td_custom.signing_hash().unwrap(),
            keccak256(&expected_final)
        );
    }

    #[test]
    fn domain_separator_rejects_invalid_fields() {
        let bad_contract = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(U256::from(1)),
            verifying_contract: Some("0xdeadbeef".to_string()),
            salt: None,
        };
        assert!(matches!(
            bad_contract.separator_hash(),
            Err(Error::InvalidDomainSeparator(_))
        ));

        let bad_salt = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(U256::from(1)),
            verifying_contract: None,
            salt: Some("0x01".to_string()),
        };
        assert!(matches!(
            bad_salt.separator_hash(),
            Err(Error::InvalidDomainSeparator(_))
        ));
    }

    #[test]
    fn try_new_rejects_malformed_types() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: None,
            chain_id: None,
            verifying_contract: None,
            salt: None,
        };

        // Malformed field missing "type" must NOT be silently dropped
        let malformed = json!({
            "Bad": [
                {"name": "ok", "type": "string"},
                {"name": "missing_type"}
            ]
        });
        assert!(matches!(
            TypedData::try_new(domain.clone(), malformed, "Bad".to_string(), json!({})),
            Err(Error::InvalidTypedData(_))
        ));

        // Non-object types must be rejected
        assert!(matches!(
            TypedData::new(domain, json!([]), "Bad".to_string(), json!({})),
            Err(Error::InvalidTypedData(_))
        ));
    }

    #[test]
    fn typed_data_json_roundtrip() {
        let domain = Eip712Domain {
            name: Some("Test".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(U256::from(1)),
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

        let original = TypedData::new(domain, types, "Simple".to_string(), message).unwrap();
        let json = original.to_json().unwrap();
        let recovered = TypedData::from_json(&json).unwrap();

        assert_eq!(
            original.signing_hash().unwrap(),
            recovered.signing_hash().unwrap()
        );
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

        let typed_data = TypedData::new(
            domain,
            json!({}),
            "NonExistent".to_string(),
            json!({"foo": "bar"}),
        )
        .unwrap();
        assert!(matches!(
            typed_data.signing_hash(),
            Err(Error::UndefinedType(_))
        ));
    }
}
