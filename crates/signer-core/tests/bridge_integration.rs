//! End-to-end integration tests for the hardened local PC/SC loopback bridge.
//!
//! Spawns a real [`BridgeServer`] bound to `127.0.0.1:0` backed by a mock PIV
//! YubiKey (using a real P-256 signing key, real DER X.509 certificate split
//! across multi-chunk `61 XX` responses, PIN verification, AES-192 management
//! key mutual auth, and real P-256 prehash signing) and exercises both security
//! boundaries and the full Ethereum signing flow over real loopback TCP HTTP.
//!
//! Tests never use fixed ports or sleeps for synchronization: events that happen
//! on a background thread (idle expiry) are awaited on a channel with a generous
//! upper bound, and timeouts under test are configured to be short.

// Silence unused crate dependency warnings for this integration test binary
use aes as _;
use alloy_primitives as _;
use alloy_rlp as _;
use ctrlc as _;
use des as _;
use flate2 as _;
use getrandom as _;
#[cfg(feature = "pcsc")]
use pcsc as _;
use rpassword as _;
use subtle as _;
use thiserror as _;
use zeroize as _;

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use p256::FieldBytes;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use serde_json::Value;

use yubikey_evm_signer_core::bridge::{
    BridgeConfig, BridgeHandle, BridgeServer, MAX_BODY_BYTES, MAX_CONCURRENT_CONNECTIONS,
    MAX_HEADER_BYTES, MIN_TOKEN_LEN,
};
use yubikey_evm_signer_core::crypto::{
    create_ethereum_signature, try_recover_public_key, verify_signature,
};
use yubikey_evm_signer_core::yubikey::piv::{
    ManagementKeyAlgorithm, PIV_AID, build_delete_certificate_apdu, build_generate_key_apdu,
    build_get_certificate_apdu, build_get_metadata_apdu, build_get_response_apdu,
    build_mgmt_auth_request_witness_apdu, build_mgmt_auth_verify_apdu, build_select_piv_apdu,
    build_sign_apdu, build_verify_pin_apdu, decrypt_mgmt_witness, encrypt_mgmt_challenge,
    parse_certificate_public_key, parse_challenge_response, parse_public_key_response,
    parse_signature_response, parse_witness_response, verify_mgmt_challenge_response,
};
use yubikey_evm_signer_core::yubikey::{Apdu, ApduResponse, Slot, Transport};
use yubikey_evm_signer_core::{Address, Eip1559Transaction, Error, Result, Transaction, U256};

const ALLOWED_ORIGIN: &str = "http://localhost:8000";
const TEST_PIN: &str = "123456";
const TEST_MGMT_KEY: [u8; 24] = [0x22; 24];
const TEST_KEY_HEX: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const NO_SESSION: &str = "no active session or session_id mismatch";
const SLOTS: [Slot; 4] = [
    Slot::Authentication,
    Slot::Signature,
    Slot::KeyManagement,
    Slot::CardAuthentication,
];

/// Upper bound when waiting for an event that must happen (never a fixed sleep).
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

/// DER-encodes a TLV element with canonical length.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push((value.len() & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

/// Builds a valid X.509 DER certificate for `verifying_key` wrapped in a PIV `0x53` object.
fn build_piv_certificate_object(verifying_key: &VerifyingKey) -> Vec<u8> {
    let oid_ec_public_key = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let oid_secp256r1 = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let pubkey_point = verifying_key.to_sec1_point(false);

    let version = der_tlv(0xA0, &der_tlv(0x02, &[0x02]));
    let serial = der_tlv(0x02, &[0x01]);
    let sig_alg = der_tlv(
        0x30,
        &der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
    );
    let issuer = der_tlv(0x30, &[]);
    let validity = der_tlv(0x30, &[]);
    let subject = der_tlv(0x30, &der_tlv(0x0C, b"CN=Bridge Integration Test"));

    let mut spki_alg = Vec::new();
    spki_alg.extend_from_slice(&der_tlv(0x06, oid_ec_public_key));
    spki_alg.extend_from_slice(&der_tlv(0x06, oid_secp256r1));
    let spki_alg_seq = der_tlv(0x30, &spki_alg);

    let mut bit_string_val = vec![0x00];
    bit_string_val.extend_from_slice(pubkey_point.as_bytes());
    let spki_pk = der_tlv(0x03, &bit_string_val);

    let mut spki_inner = Vec::new();
    spki_inner.extend_from_slice(&spki_alg_seq);
    spki_inner.extend_from_slice(&spki_pk);
    let spki = der_tlv(0x30, &spki_inner);

    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&version);
    tbs_inner.extend_from_slice(&serial);
    tbs_inner.extend_from_slice(&sig_alg);
    tbs_inner.extend_from_slice(&issuer);
    tbs_inner.extend_from_slice(&validity);
    tbs_inner.extend_from_slice(&subject);
    tbs_inner.extend_from_slice(&spki);
    let tbs = der_tlv(0x30, &tbs_inner);

    let mut cert_inner = Vec::new();
    cert_inner.extend_from_slice(&tbs);
    cert_inner.extend_from_slice(&sig_alg);
    cert_inner.extend_from_slice(&der_tlv(0x03, &[0x00, 0x30, 0x00]));
    let der_cert = der_tlv(0x30, &cert_inner);

    let mut piv_inner = Vec::new();
    piv_inner.extend_from_slice(&der_tlv(0x70, &der_cert));
    piv_inner.extend_from_slice(&der_tlv(0x71, &[0x00]));
    piv_inner.extend_from_slice(&der_tlv(0xFE, &[]));
    der_tlv(0x53, &piv_inner)
}

fn test_signing_key() -> SigningKey {
    let key_bytes = hex::decode(TEST_KEY_HEX).unwrap();
    SigningKey::from_bytes(&FieldBytes::try_from(key_bytes.as_slice()).unwrap()).unwrap()
}

/// Transport failure injected by a test for one `(INS, P2)` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    CardReset,
    Disconnected,
    Other,
}

/// Observations shared between a test and every mock card the bridge opens.
#[derive(Default)]
struct Probe {
    /// Every APDU a card received, and whether it arrived inside an exclusive scope.
    transmitted: Mutex<Vec<(Vec<u8>, bool)>>,
    /// Number of exclusive scopes opened.
    scopes: AtomicUsize,
    /// Injected transport failures keyed by `(INS, P2)`.
    faults: Mutex<HashMap<(u8, u8), Fault>>,
}

impl Probe {
    fn transmitted(&self) -> Vec<(Vec<u8>, bool)> {
        self.transmitted.lock().unwrap().clone()
    }

    fn transmitted_count(&self) -> usize {
        self.transmitted.lock().unwrap().len()
    }

    fn set_fault(&self, ins: u8, p2: u8, fault: Option<Fault>) {
        let mut faults = self.faults.lock().unwrap();
        match fault {
            Some(fault) => faults.insert((ins, p2), fault),
            None => faults.remove(&(ins, p2)),
        };
    }
}

/// Realistic mock PIV smart card implementing [`Transport`].
struct MockPivCard {
    signing_key: SigningKey,
    piv_cert_obj: Vec<u8>,
    pending_chunks: Vec<Vec<u8>>,
    pin_verified: bool,
    pin_retries: u8,
    mgmt_witness: [u8; 16],
    mgmt_authenticated: bool,
    in_scope: bool,
    probe: Arc<Probe>,
    /// Signalled when the card handle is dropped (the bridge released the card).
    dropped: Sender<()>,
}

impl MockPivCard {
    fn new(signing_key: SigningKey, probe: Arc<Probe>, dropped: Sender<()>) -> Self {
        let piv_cert_obj = build_piv_certificate_object(signing_key.verifying_key());
        Self {
            signing_key,
            piv_cert_obj,
            pending_chunks: Vec::new(),
            pin_verified: false,
            pin_retries: 3,
            mgmt_witness: [0xA5; 16],
            mgmt_authenticated: false,
            in_scope: false,
            probe,
            dropped,
        }
    }

    fn next_chunk_response(&mut self) -> ApduResponse {
        if self.pending_chunks.is_empty() {
            return ApduResponse::new(vec![0x6A, 0x86]);
        }
        let mut chunk = self.pending_chunks.remove(0);
        if let Some(next) = self.pending_chunks.first() {
            let rem = if next.len() >= 256 {
                0
            } else {
                next.len() as u8
            };
            chunk.extend_from_slice(&[0x61, rem]);
        } else {
            chunk.extend_from_slice(&[0x90, 0x00]);
        }
        ApduResponse::new(chunk)
    }
}

impl Drop for MockPivCard {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}

impl Transport for MockPivCard {
    fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
        self.probe
            .transmitted
            .lock()
            .unwrap()
            .push((apdu.to_bytes()?, self.in_scope));

        let fault = self
            .probe
            .faults
            .lock()
            .unwrap()
            .get(&(apdu.ins(), apdu.p2()))
            .copied();
        match fault {
            Some(Fault::CardReset) => return Err(Error::CardReset),
            Some(Fault::Disconnected) => return Err(Error::DeviceDisconnected),
            Some(Fault::Other) => {
                return Err(Error::ApduError("mock transport failure".to_string()));
            }
            None => {}
        }

        // A real card answers "class not supported" for chaining / logical channels.
        if apdu.cla() != 0x00 {
            return Ok(ApduResponse::new(vec![0x6E, 0x00]));
        }

        match apdu.ins() {
            // SELECT PIV AID
            0xA4 => {
                if apdu.p1() == 0x04 && apdu.p2() == 0x00 && apdu.data() == PIV_AID.as_slice() {
                    Ok(ApduResponse::new(vec![0x90, 0x00]))
                } else {
                    Ok(ApduResponse::new(vec![0x6A, 0x82]))
                }
            }
            // VERIFY PIN
            0x20 => {
                let mut expected = [0xFFu8; 8];
                expected[..TEST_PIN.len()].copy_from_slice(TEST_PIN.as_bytes());
                if apdu.data() == expected.as_slice() {
                    self.pin_verified = true;
                    self.pin_retries = 3;
                    Ok(ApduResponse::new(vec![0x90, 0x00]))
                } else {
                    self.pin_verified = false;
                    self.pin_retries = self.pin_retries.saturating_sub(1);
                    Ok(ApduResponse::new(vec![0x63, 0xC0 | self.pin_retries]))
                }
            }
            // GET DATA (split certificate into 64-byte chunks to exercise 61 XX GET RESPONSE)
            0xCB => {
                let oid_9a = Slot::Authentication.object_id();
                let expected = [0x5C, 0x03, oid_9a[0], oid_9a[1], oid_9a[2]];
                if apdu.data() == expected.as_slice() {
                    self.pending_chunks =
                        self.piv_cert_obj.chunks(64).map(|c| c.to_vec()).collect();
                    Ok(self.next_chunk_response())
                } else {
                    Ok(ApduResponse::new(vec![0x6A, 0x82]))
                }
            }
            // GET RESPONSE
            0xC0 => Ok(self.next_chunk_response()),
            // GENERATE ASYMMETRIC (returns the existing test key's public point)
            0x47 => {
                if !self.mgmt_authenticated {
                    return Ok(ApduResponse::new(vec![0x69, 0x82]));
                }
                let point = self.signing_key.verifying_key().to_sec1_point(false);
                let inner = der_tlv(0x86, point.as_bytes());
                let mut resp = vec![0x7F, 0x49, inner.len() as u8];
                resp.extend_from_slice(&inner);
                resp.extend_from_slice(&[0x90, 0x00]);
                Ok(ApduResponse::new(resp))
            }
            // PUT DATA (certificate deletion)
            0xDB => {
                if self.mgmt_authenticated {
                    Ok(ApduResponse::new(vec![0x90, 0x00]))
                } else {
                    Ok(ApduResponse::new(vec![0x69, 0x82]))
                }
            }
            // GENERAL AUTHENTICATE
            0x87 => {
                if apdu.p2() == 0x9B && apdu.p1() == ManagementKeyAlgorithm::Aes192.id() {
                    // Management key mutual auth
                    let data = apdu.data();
                    if data == [0x7C, 0x02, 0x80, 0x00] {
                        let enc_witness = encrypt_mgmt_challenge(
                            ManagementKeyAlgorithm::Aes192,
                            &TEST_MGMT_KEY,
                            &self.mgmt_witness,
                        )?;
                        let mut resp = der_tlv(0x7C, &der_tlv(0x80, &enc_witness));
                        resp.extend_from_slice(&[0x90, 0x00]);
                        return Ok(ApduResponse::new(resp));
                    }
                    // Step 2: 7C <len> 80 10 <witness> 81 10 <challenge>
                    if data.len() == 2 + 2 + 16 + 2 + 16
                        && data[0] == 0x7C
                        && data[2] == 0x80
                        && data[3] == 16
                        && data[20] == 0x81
                        && data[21] == 16
                    {
                        let got_witness = &data[4..20];
                        let host_challenge = &data[22..38];
                        if got_witness != self.mgmt_witness.as_slice() {
                            self.mgmt_authenticated = false;
                            return Ok(ApduResponse::new(vec![0x69, 0x82]));
                        }
                        self.mgmt_authenticated = true;
                        let card_resp = encrypt_mgmt_challenge(
                            ManagementKeyAlgorithm::Aes192,
                            &TEST_MGMT_KEY,
                            host_challenge,
                        )?;
                        let mut resp = der_tlv(0x7C, &der_tlv(0x82, &card_resp));
                        resp.extend_from_slice(&[0x90, 0x00]);
                        return Ok(ApduResponse::new(resp));
                    }
                    return Ok(ApduResponse::new(vec![0x6A, 0x80]));
                }

                // P-256 signing in slot 9a
                if apdu.p1() == 0x11 && apdu.p2() == Slot::Authentication.id() {
                    if !self.pin_verified {
                        return Ok(ApduResponse::new(vec![0x69, 0x82]));
                    }
                    let data = apdu.data();
                    if data.len() != 38 || data[0] != 0x7C || data[4] != 0x81 || data[5] != 0x20 {
                        return Ok(ApduResponse::new(vec![0x6A, 0x80]));
                    }
                    let digest = &data[6..38];
                    let sig: P256Signature = self
                        .signing_key
                        .sign_prehash(digest)
                        .map_err(|e| Error::ApduError(e.to_string()))?;
                    let der = sig.to_der();
                    let mut resp = der_tlv(0x7C, &der_tlv(0x82, der.as_bytes()));
                    resp.extend_from_slice(&[0x90, 0x00]);
                    return Ok(ApduResponse::new(resp));
                }

                Ok(ApduResponse::new(vec![0x6A, 0x82]))
            }
            _ => Ok(ApduResponse::new(vec![0x6D, 0x00])),
        }
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn exclusive(&mut self, f: &mut dyn FnMut(&mut dyn Transport) -> Result<()>) -> Result<()> {
        self.probe.scopes.fetch_add(1, Ordering::SeqCst);
        let outer = std::mem::replace(&mut self.in_scope, true);
        let result = f(self);
        self.in_scope = outer;
        result
    }
}

struct RawHttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

impl RawHttpResponse {
    fn has_cors(&self) -> bool {
        self.headers.contains_key("access-control-allow-origin")
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }

    fn error(&self) -> String {
        self.json()["error"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn apdu(&self) -> ApduResponse {
        assert_eq!(self.status, 200, "unexpected HTTP status: {}", self.body);
        let hex_resp = self.json()["response"].as_str().unwrap().to_string();
        ApduResponse::try_from_bytes(hex::decode(hex_resp).unwrap()).unwrap()
    }
}

fn parse_http_response(response_bytes: Vec<u8>) -> RawHttpResponse {
    let raw = String::from_utf8(response_bytes).expect("UTF-8 HTTP response");
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("HTTP response header/body split: {raw:?}"));

    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status code");

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    RawHttpResponse {
        status,
        headers,
        body: body.to_string(),
    }
}

fn send_raw_http(addr: SocketAddr, request_bytes: &[u8]) -> RawHttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect to bridge");
    stream
        .set_read_timeout(Some(EVENT_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(EVENT_TIMEOUT))
        .expect("set write timeout");

    stream.write_all(request_bytes).expect("write HTTP request");
    stream.flush().expect("flush HTTP request");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .expect("read HTTP response");
    parse_http_response(response_bytes)
}

/// HTTP client for one bridge instance (cloneable across threads).
#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    token: String,
}

/// A running bridge backed by mock cards, plus the test's view of those cards.
struct Harness {
    handle: BridgeHandle,
    client: Client,
    probe: Arc<Probe>,
    drops: Receiver<()>,
}

impl std::ops::Deref for Harness {
    type Target = Client;

    fn deref(&self) -> &Client {
        &self.client
    }
}

fn start_bridge(config: BridgeConfig) -> Harness {
    let probe = Arc::new(Probe::default());
    let (drop_tx, drops) = mpsc::channel();
    let card_probe = Arc::clone(&probe);
    let handle = BridgeServer::start(config.with_backend_name("mock"), move || {
        let card: Box<dyn Transport + Send> = Box::new(MockPivCard::new(
            test_signing_key(),
            Arc::clone(&card_probe),
            drop_tx.clone(),
        ));
        Ok(card)
    })
    .expect("start bridge server");
    let addr = handle.local_addr();
    let token = handle.token().to_string();
    Harness {
        handle,
        client: Client { addr, token },
        probe,
        drops,
    }
}

fn default_config() -> BridgeConfig {
    BridgeConfig::loopback(0).unwrap()
}

impl Client {
    const fn port(&self) -> u16 {
        self.addr.port()
    }

    fn send(&self, request: &str) -> RawHttpResponse {
        send_raw_http(self.addr, request.as_bytes())
    }

    /// Sends a request with a valid Host, allowed Origin and bearer token.
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> RawHttpResponse {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {}\r\n",
            self.port(),
            self.token
        );
        if let Some(body) = body {
            req.push_str(&format!(
                "Content-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ));
        } else {
            req.push_str("\r\n");
        }
        self.send(&req)
    }

    fn health(&self) -> RawHttpResponse {
        self.request("GET", "/v1/health", None)
    }

    fn try_connect(&self) -> RawHttpResponse {
        self.request("POST", "/v1/connect", Some("{}"))
    }

    fn connect(&self) -> String {
        let resp = self.try_connect();
        assert_eq!(resp.status, 200, "connect failed: {}", resp.body);
        let session_id = resp.json()["session_id"].as_str().unwrap().to_string();
        assert_eq!(session_id.len(), 32);
        session_id
    }

    fn transmit(&self, session_id: &str, apdu_bytes: &[u8]) -> RawHttpResponse {
        let body = serde_json::json!({
            "session_id": session_id,
            "apdu": hex::encode(apdu_bytes),
        })
        .to_string();
        self.request("POST", "/v1/transmit", Some(&body))
    }

    fn transmit_apdu(&self, session_id: &str, apdu: &Apdu) -> RawHttpResponse {
        self.transmit(session_id, &apdu.to_bytes().unwrap())
    }

    fn disconnect(&self, session_id: &str) -> RawHttpResponse {
        let body = serde_json::json!({ "session_id": session_id }).to_string();
        self.request("POST", "/v1/disconnect", Some(&body))
    }
}

impl Harness {
    /// Asserts a card handle was released before the last response was sent.
    fn assert_card_released(&self) {
        self.drops
            .try_recv()
            .expect("the bridge must have released the card handle");
    }

    fn assert_card_held(&self) {
        assert!(
            self.drops.try_recv().is_err(),
            "the bridge must still hold the card handle"
        );
    }
}

fn assert_no_session(resp: &RawHttpResponse) {
    assert_eq!(resp.status, 409, "{}", resp.body);
    assert_eq!(resp.error(), NO_SESSION);
    assert!(resp.has_cors());
}

#[test]
fn bridge_security_boundaries_and_end_to_end_signing() {
    // 0. Non-loopback bind address is rejected upfront
    let non_loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    assert!(
        BridgeConfig::new(non_loopback, vec![ALLOWED_ORIGIN.to_string()], None, "mock").is_err()
    );

    let signing_key = test_signing_key();
    let expected_vk = *signing_key.verifying_key();
    let expected_address = Address::from_public_key(&expected_vk);

    let h = start_bridge(default_config());
    let port = h.port();
    let token = h.token.clone();
    assert_eq!(h.handle.url(), format!("http://127.0.0.1:{port}"));

    // 1. Security: missing Origin -> 403 (both OPTIONS and GET)
    let resp = h.send(&format!(
        "OPTIONS /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());

    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\n\r\n"
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());

    // 2. Security: disallowed Origin -> 403 (both OPTIONS and POST)
    let resp = h.send(&format!(
        "OPTIONS /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\n\r\n"
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());

    let resp = h.send(&format!(
        "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());

    // 3. Security: DNS rebinding Host header -> 403
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost: attacker.example:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());

    // 4. Security: missing or wrong Bearer token -> 401
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\n\r\n"
    ));
    assert_eq!(resp.status, 401);
    assert!(resp.has_cors());

    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer wrongtoken\r\n\r\n"
    ));
    assert_eq!(resp.status, 401);

    // 5. Security: Transfer-Encoding rejected -> 400 (readable by the allowed page)
    let resp = h.send(&format!(
        "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    ));
    assert_eq!(resp.status, 400);
    assert!(resp.has_cors());

    // 6. Security: Non-JSON Content-Type on POST -> 415
    let resp = h.send(&format!(
        "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"
    ));
    assert_eq!(resp.status, 415);

    // 7. Happy path: OPTIONS preflight (no Private Network Access request header)
    let preflight = h.send(&format!(
        "OPTIONS /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\n\r\n"
    ));
    assert_eq!(preflight.status, 204);
    assert_eq!(
        preflight
            .headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some(ALLOWED_ORIGIN)
    );
    assert_eq!(
        preflight.headers.get("vary").map(String::as_str),
        Some("Origin")
    );
    assert!(
        !preflight
            .headers
            .contains_key("access-control-allow-private-network")
    );

    // 8. Happy path: GET /v1/health
    let health = h.health();
    assert_eq!(health.status, 200);
    let health_json = health.json();
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["transport"], "mock");

    // 9. Happy path: POST /v1/connect (PIV SELECT inside one exclusive scope)
    let session_id = h.connect();
    assert_eq!(h.probe.scopes.load(Ordering::SeqCst), 1);

    // 10. Security: Disallowed APDUs rejected with 403
    let select_fido2 = Apdu::new(
        0x00,
        0xA4,
        0x04,
        0x00,
        vec![0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01],
    )
    .to_bytes()
    .unwrap();
    assert_eq!(h.transmit(&session_id, &select_fido2).status, 403);

    let put_data = Apdu::new(0x00, 0xDB, 0x3F, 0xFF, vec![0x5C, 0x03, 0x5F, 0xC1, 0x05])
        .to_bytes()
        .unwrap();
    assert_eq!(h.transmit(&session_id, &put_data).status, 403);

    let reset_piv = Apdu::new(0x00, 0xFB, 0x00, 0x00, vec![])
        .to_bytes()
        .unwrap();
    assert_eq!(h.transmit(&session_id, &reset_piv).status, 403);

    // 11. Happy path: GET DATA -> the bridge completes the 61 XX chain itself in
    //     one exclusive scope and returns the whole certificate with 90 00.
    let scopes_before = h.probe.scopes.load(Ordering::SeqCst);
    let sent_before = h.probe.transmitted_count();
    let cert_resp = h
        .transmit_apdu(
            &session_id,
            &build_get_certificate_apdu(Slot::Authentication),
        )
        .apdu();
    assert!(cert_resp.is_success());
    assert_eq!(cert_resp.remaining_bytes(), None);
    assert_eq!(h.probe.scopes.load(Ordering::SeqCst), scopes_before + 1);
    let chain = h.probe.transmitted()[sent_before..].to_vec();
    assert!(chain.len() > 2, "certificate must span several chunks");
    assert!(chain.iter().all(|(_, in_scope)| *in_scope));
    assert!(chain[1..].iter().all(|(apdu, _)| apdu[1] == 0xC0));

    let parsed_vk = parse_certificate_public_key(cert_resp.data()).expect("valid P-256 cert");
    assert_eq!(Address::from_public_key(&parsed_vk), expected_address);

    // 12. Happy path: VERIFY PIN (wrong -> 63 C2, then correct -> 90 00)
    let bad_pin = build_verify_pin_apdu("000000").unwrap();
    let bad_resp = h.transmit_apdu(&session_id, &bad_pin).apdu();
    assert_eq!(bad_resp.status_word(), 0x63C2);

    let good_pin = build_verify_pin_apdu(TEST_PIN).unwrap();
    assert!(h.transmit_apdu(&session_id, &good_pin).apdu().is_success());

    // 13. Happy path: GENERAL AUTHENTICATE sign EIP-1559 transaction hash & verify recovery
    let tx = Transaction::Eip1559(Eip1559Transaction {
        chain_id: 1,
        nonce: 7,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        max_fee_per_gas: U256::from(20_000_000_000u64),
        gas_limit: 21_000,
        to: Some(Address::zero()),
        value: U256::from(1_000_000_000_000_000u64),
        data: vec![],
        access_list: vec![],
    });
    let tx_hash: [u8; 32] = tx.signing_hash().unwrap().into();
    let sign_apdu = build_sign_apdu(Slot::Authentication, &tx_hash);
    let sign_resp = h.transmit_apdu(&session_id, &sign_apdu).apdu();
    assert!(sign_resp.is_success());

    let der_sig = parse_signature_response(sign_resp.data()).expect("valid DER sig TLV");
    let eth_sig = create_ethereum_signature(&der_sig, &tx_hash, &parsed_vk).unwrap();
    assert!(verify_signature(&tx_hash, &eth_sig, &expected_vk));
    let recovered =
        try_recover_public_key(&tx_hash, eth_sig.r(), eth_sig.s(), eth_sig.v()).unwrap();
    assert_eq!(
        recovered.to_sec1_point(false),
        expected_vk.to_sec1_point(false)
    );

    // Every APDU reached the card inside an exclusive scope.
    assert!(h.probe.transmitted().iter().all(|(_, in_scope)| *in_scope));

    // 14. Happy path: POST /v1/disconnect releases the card; later transmit -> 409
    h.assert_card_held();
    let disc_http = h.disconnect(&session_id);
    assert_eq!(disc_http.status, 200);
    assert_eq!(disc_http.json()["disconnected"], true);
    h.assert_card_released();

    assert_no_session(&h.transmit_apdu(&session_id, &sign_apdu));

    // Clean deterministic shutdown
    h.handle.shutdown();
}

#[test]
fn bridge_connect_handles_select_wrong_le_and_get_response_chaining() {
    struct ChainedSelectTransport {
        step: usize,
    }

    impl Transport for ChainedSelectTransport {
        fn transmit(&mut self, apdu: &Apdu) -> yubikey_evm_signer_core::Result<ApduResponse> {
            self.step += 1;
            match self.step {
                // Initial SELECT -> 6C 10 (wrong Le, retry with Le=16)
                1 => {
                    assert_eq!(apdu.ins(), 0xA4);
                    Ok(ApduResponse::try_from_bytes(vec![0x6C, 0x10]).unwrap())
                }
                // Retried SELECT with Le=16 -> partial data + 61 04
                2 => {
                    assert_eq!(apdu.ins(), 0xA4);
                    assert_eq!(apdu.le(), Some(0x10));
                    let mut raw = vec![0x61, 0x05, 0x4F, 0x03];
                    raw.extend_from_slice(&[0x61, 0x04]);
                    Ok(ApduResponse::try_from_bytes(raw).unwrap())
                }
                // GET RESPONSE with Le=4 -> final bytes + 90 00
                3 => {
                    assert_eq!(apdu.ins(), 0xC0);
                    assert_eq!(apdu.le(), Some(0x04));
                    Ok(
                        ApduResponse::try_from_bytes(vec![0x01, 0x02, 0x03, 0x04, 0x90, 0x00])
                            .unwrap(),
                    )
                }
                _ => Ok(ApduResponse::try_from_bytes(vec![0x6D, 0x00]).unwrap()),
            }
        }

        fn is_connected(&self) -> bool {
            true
        }
    }

    let config = BridgeConfig::loopback(0).unwrap().with_backend_name("mock");
    let handle = BridgeServer::start(config, || {
        let card: Box<dyn Transport + Send> = Box::new(ChainedSelectTransport { step: 0 });
        Ok(card)
    })
    .expect("bridge start");
    let addr = handle.local_addr();
    let port = addr.port();
    let token = handle.token().to_string();

    let resp = send_raw_http(
        addr,
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        )
        .as_bytes(),
    );
    assert_eq!(
        resp.status, 200,
        "unexpected connect response: {}",
        resp.body
    );
    let json: Value = serde_json::from_str(&resp.body).unwrap();
    assert!(json["session_id"].as_str().is_some_and(|s| !s.is_empty()));

    handle.shutdown();
}

#[test]
fn host_header_must_equal_bound_address() {
    let h = start_bridge(default_config());
    let port = h.port();
    let token = &h.token;

    let rejected = [
        format!("localhost:{port}"),
        format!("LOCALHOST:{port}"),
        format!("[::1]:{port}"),
        format!("127.0.0.1.:{port}"),
        format!("127.0.0.2:{port}"),
        format!("127.000.000.001:{port}"),
        format!("2130706433:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        format!("127.0.0.1:0{port}"),
        format!("127.0.0.1:{port}:"),
        "127.0.0.1".to_string(),
        String::new(),
    ];
    for host in rejected {
        let resp = h.send(&format!(
            "GET /v1/health HTTP/1.1\r\nHost: {host}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
        ));
        assert_eq!(resp.status, 403, "Host {host:?} must be rejected");
        assert!(!resp.has_cors(), "no CORS headers for Host {host:?}");
    }

    // Missing Host -> 400 (RFC 9112 §3.2), no CORS
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
    ));
    assert_eq!(resp.status, 400);
    assert!(!resp.has_cors());

    // Optional whitespace around the value is not part of the field value.
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost:\t 127.0.0.1:{port} \r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
    ));
    assert_eq!(resp.status, 200);
}

#[test]
fn strict_header_syntax_and_duplicates() {
    let h = start_bridge(default_config());
    let port = h.port();
    let token = &h.token;
    let base = format!(
        "Host: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}"
    );

    // Structural errors: 400 without CORS headers.
    let structural = [
        // whitespace between field name and colon
        format!(
            "GET /v1/health HTTP/1.1\r\nHost : 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\n\r\n"
        ),
        // obs-fold continuation line
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nX-Folded: a\r\n  b\r\n\r\n"),
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nX-Folded: a\r\n\tb\r\n\r\n"),
        // invalid field names
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nX Y: z\r\n\r\n"),
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\n: z\r\n\r\n"),
        // bare LF line endings and bare CR
        format!("GET /v1/health HTTP/1.1\nHost: 127.0.0.1:{port}\n\n"),
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nX-A: b\rc\r\n\r\n"),
        // control character in a value
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nX-A: b\x01c\r\n\r\n"),
        // duplicate Host / Origin / Authorization / Content-Type
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nOrigin: {ALLOWED_ORIGIN}\r\n\r\n"),
        format!("GET /v1/health HTTP/1.1\r\n{base}\r\nAuthorization: Bearer {token}\r\n\r\n"),
        format!(
            "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        ),
        // malformed request line
        format!("GET  /v1/health HTTP/1.1\r\n{base}\r\n\r\n"),
        format!("GET /v1/health HTTP/2.0\r\n{base}\r\n\r\n"),
    ];
    for req in &structural {
        let resp = h.send(req);
        assert_eq!(resp.status, 400, "{req:?} -> {}", resp.body);
        assert!(!resp.has_cors(), "{req:?} must not get CORS headers");
    }

    // Oversized header block -> 431 without CORS headers.
    let padding = "a".repeat(MAX_HEADER_BYTES);
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\n{base}\r\nX-Pad: {padding}\r\n\r\n"
    ));
    assert_eq!(resp.status, 431);
    assert!(!resp.has_cors());

    // Framing errors after a valid Host and allowed Origin: CORS headers present.
    let framing = [
        (
            format!(
                "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}"
            ),
            400,
        ),
        (
            format!(
                "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Length: two\r\n\r\n{{}}"
            ),
            400,
        ),
        (
            format!(
                "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Length: +2\r\n\r\n{{}}"
            ),
            400,
        ),
        (
            format!(
                "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Length: 2, 2\r\n\r\n{{}}"
            ),
            400,
        ),
        (
            format!(
                "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Length: 99999999999999999999999999\r\n\r\n{{}}"
            ),
            413,
        ),
        // A body longer than Content-Length (pipelined bytes in the same segment)
        (
            format!(
                "POST /v1/connect HTTP/1.1\r\n{base}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}GET /v1/health HTTP/1.1\r\n\r\n"
            ),
            400,
        ),
    ];
    for (req, status) in &framing {
        let resp = h.send(req);
        assert_eq!(resp.status, *status, "{req:?} -> {}", resp.body);
        assert!(resp.has_cors(), "{req:?} must get CORS headers");
    }

    // The card was never touched.
    assert_eq!(h.probe.transmitted_count(), 0);
}

#[test]
fn oversized_body_is_rejected_and_response_is_readable() {
    let h = start_bridge(default_config());
    let port = h.port();
    let token = &h.token;
    let body = "a".repeat(MAX_BODY_BYTES + 1);
    let resp = h.send(&format!(
        "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    assert_eq!(resp.status, 413);
    assert!(resp.has_cors());
    assert_eq!(h.probe.transmitted_count(), 0);

    // A disallowed Origin with an oversized body: 403 without CORS, still readable.
    let resp = h.send(&format!(
        "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());
}

#[test]
fn preflight_private_network_access() {
    let h = start_bridge(default_config());
    let port = h.port();

    let resp = h.send(&format!(
        "OPTIONS /v1/transmit HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: authorization,content-type\r\nAccess-Control-Request-Private-Network: true\r\n\r\n"
    ));
    assert_eq!(resp.status, 204);
    assert_eq!(
        resp.headers
            .get("access-control-allow-private-network")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        resp.headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some(ALLOWED_ORIGIN)
    );

    // Disallowed origin: 403 and neither CORS nor PNA headers.
    let resp = h.send(&format!(
        "OPTIONS /v1/transmit HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nAccess-Control-Request-Private-Network: true\r\n\r\n"
    ));
    assert_eq!(resp.status, 403);
    assert!(!resp.has_cors());
    assert!(
        !resp
            .headers
            .contains_key("access-control-allow-private-network")
    );

    // PNA header only on preflight, never on normal responses.
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {}\r\nAccess-Control-Request-Private-Network: true\r\n\r\n",
        h.token
    ));
    assert_eq!(resp.status, 200);
    assert!(
        !resp
            .headers
            .contains_key("access-control-allow-private-network")
    );
}

#[test]
fn slow_clients_hit_the_total_request_deadline() {
    let h = start_bridge(
        default_config()
            .with_request_timeout(Duration::from_millis(300))
            .unwrap(),
    );
    let port = h.port();
    let token = &h.token;

    // Incomplete header block, then silence -> 408 without CORS.
    let resp = h.send(&format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
    ));
    assert_eq!(resp.status, 408);
    assert!(!resp.has_cors());

    // Complete headers, incomplete body -> 408 with CORS (Host/Origin already valid).
    let resp = h.send(&format!(
        "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{{}}"
    ));
    assert_eq!(resp.status, 408);
    assert!(resp.has_cors());

    // A client trickling one byte at a time still hits the total deadline: the
    // per-read wait is paced by a short client read timeout, not a sleep.
    let mut stream = TcpStream::connect(h.addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    stream
        .write_all(
            format!("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Pad: ").as_bytes(),
        )
        .unwrap();
    let started = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        assert!(
            started.elapsed() < EVENT_TIMEOUT,
            "server never enforced the request deadline"
        );
        if response.is_empty() {
            let _ = stream.write_all(b"a");
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }
    let resp = parse_http_response(response);
    assert_eq!(resp.status, 408);

    // A client that connects and sends nothing is closed without a response.
    let mut idle = TcpStream::connect(h.addr).unwrap();
    idle.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
    let mut out = Vec::new();
    idle.read_to_end(&mut out).unwrap();
    assert!(out.is_empty());
}

#[test]
fn connection_limit_answers_503() {
    let h = start_bridge(default_config());
    let port = h.port();

    // Hold every connection slot with an incomplete request.
    let mut holders: Vec<TcpStream> = (0..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| {
            let mut stream = TcpStream::connect(h.addr).unwrap();
            stream
                .write_all(
                    format!("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n").as_bytes(),
                )
                .unwrap();
            stream
        })
        .collect();

    // Connections are accepted in order, so the next one finds every slot taken.
    let mut extra = TcpStream::connect(h.addr).unwrap();
    extra.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
    let mut out = Vec::new();
    extra.read_to_end(&mut out).unwrap();
    let resp = parse_http_response(out);
    assert_eq!(resp.status, 503);
    assert!(!resp.has_cors());

    // The held connections are still served once they finish their request.
    let mut first = holders.remove(0);
    first
        .write_all(
            format!(
                "Origin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {}\r\n\r\n",
                h.token
            )
            .as_bytes(),
        )
        .unwrap();
    first.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
    let mut out = Vec::new();
    first.read_to_end(&mut out).unwrap();
    assert_eq!(parse_http_response(out).status, 200);
    drop(holders);
}

#[test]
fn concurrent_clients_are_served_and_exchanges_stay_atomic() {
    let h = start_bridge(default_config());
    let session_id = h.connect();
    let expected_cert = h
        .transmit_apdu(
            &session_id,
            &build_get_certificate_apdu(Slot::Authentication),
        )
        .apdu()
        .data()
        .to_vec();

    let workers: Vec<_> = (0..8)
        .map(|i| {
            let h = h.client.clone();
            let session_id = session_id.clone();
            let expected_cert = expected_cert.clone();
            thread::spawn(move || {
                for _ in 0..5 {
                    if i % 2 == 0 {
                        assert_eq!(h.health().status, 200);
                    } else {
                        let resp = h
                            .transmit_apdu(
                                &session_id,
                                &build_get_certificate_apdu(Slot::Authentication),
                            )
                            .apdu();
                        assert!(resp.is_success());
                        assert_eq!(resp.data(), expected_cert.as_slice());
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(h.probe.transmitted().iter().all(|(_, in_scope)| *in_scope));
}

#[test]
fn session_ids_are_checked_and_replaced() {
    let h = start_bridge(default_config());
    let get_cert = build_get_certificate_apdu(Slot::Authentication);

    let first = h.connect();
    h.assert_card_held();

    // Wrong session_id while a session is active: rejected, session unaffected.
    assert_no_session(&h.transmit_apdu(&"0".repeat(32), &get_cert));
    assert_no_session(&h.transmit_apdu(&first[..31], &get_cert));
    assert_no_session(&h.disconnect("not-the-session"));
    assert!(h.transmit_apdu(&first, &get_cert).apdu().is_success());
    h.assert_card_held();

    // A second connect replaces the first: the old card handle is released.
    let second = h.connect();
    assert_ne!(first, second);
    h.assert_card_released();
    assert_no_session(&h.transmit_apdu(&first, &get_cert));
    assert_no_session(&h.disconnect(&first));
    assert!(h.transmit_apdu(&second, &get_cert).apdu().is_success());

    assert_eq!(h.disconnect(&second).status, 200);
    h.assert_card_released();
    assert_no_session(&h.transmit_apdu(&second, &get_cert));
}

#[test]
fn idle_session_expires_and_releases_the_card() {
    let h = start_bridge(
        default_config()
            .with_idle_timeout(Duration::from_millis(200))
            .unwrap(),
    );
    let session_id = h.connect();

    // No further request: the watchdog alone must release the card.
    h.drops
        .recv_timeout(EVENT_TIMEOUT)
        .expect("idle watchdog must release the card handle");

    // The expired id gets exactly the same answer as an unknown one.
    let expired = h.transmit_apdu(
        &session_id,
        &build_get_certificate_apdu(Slot::Authentication),
    );
    let unknown = h.transmit_apdu(
        &"f".repeat(32),
        &build_get_certificate_apdu(Slot::Authentication),
    );
    assert_no_session(&expired);
    assert_no_session(&unknown);
    assert_eq!(expired.body, unknown.body);

    // The bridge keeps working: a new session can be opened and expires again.
    assert_eq!(h.health().status, 200);
    let _again = h.connect();
    h.drops
        .recv_timeout(EVENT_TIMEOUT)
        .expect("idle watchdog must release the second card handle");
}

#[test]
fn shutdown_and_drop_release_the_card() {
    let h = start_bridge(default_config());
    let _session = h.connect();
    h.assert_card_held();
    let Harness { handle, drops, .. } = h;
    handle.shutdown();
    drops
        .try_recv()
        .expect("shutdown must release the card handle before returning");

    let h = start_bridge(default_config());
    let _session = h.connect();
    let Harness { handle, drops, .. } = h;
    drop(handle);
    drops
        .try_recv()
        .expect("dropping the handle must release the card handle");
}

#[test]
fn card_reset_and_device_loss_end_the_session() {
    let h = start_bridge(default_config());
    let sign = build_sign_apdu(Slot::Authentication, &[0x11; 32]);
    let get_cert = build_get_certificate_apdu(Slot::Authentication);

    // Card reset by another PC/SC client -> 409, session dropped.
    let session = h.connect();
    assert!(
        h.transmit_apdu(&session, &build_verify_pin_apdu(TEST_PIN).unwrap())
            .apdu()
            .is_success()
    );
    h.probe.set_fault(0x87, 0x9A, Some(Fault::CardReset));
    let resp = h.transmit_apdu(&session, &sign);
    assert_eq!(resp.status, 409, "{}", resp.body);
    assert!(resp.has_cors());
    assert!(resp.error().contains("reset by another PC/SC client"));
    h.assert_card_released();
    assert_no_session(&h.transmit_apdu(&session, &get_cert));
    h.probe.set_fault(0x87, 0x9A, None);

    // Device or reader lost -> 503, session dropped.
    let session = h.connect();
    h.probe.set_fault(0xCB, 0xFF, Some(Fault::Disconnected));
    let resp = h.transmit_apdu(&session, &get_cert);
    assert_eq!(resp.status, 503, "{}", resp.body);
    assert!(resp.has_cors());
    h.assert_card_released();
    assert_no_session(&h.transmit_apdu(&session, &get_cert));
    h.probe.set_fault(0xCB, 0xFF, None);

    // Any other transport error -> 502, session kept.
    let session = h.connect();
    h.probe.set_fault(0x20, 0x80, Some(Fault::Other));
    let resp = h.transmit_apdu(&session, &build_verify_pin_apdu(TEST_PIN).unwrap());
    assert_eq!(resp.status, 502, "{}", resp.body);
    assert!(resp.has_cors());
    h.assert_card_held();
    assert!(h.transmit_apdu(&session, &get_cert).apdu().is_success());
    h.probe.set_fault(0x20, 0x80, None);

    // Card reset / device loss during the connect-time PIV SELECT.
    h.probe.set_fault(0xA4, 0x00, Some(Fault::CardReset));
    let resp = h.try_connect();
    assert_eq!(resp.status, 409, "{}", resp.body);
    h.probe.set_fault(0xA4, 0x00, Some(Fault::Disconnected));
    assert_eq!(h.try_connect().status, 503);
    h.probe.set_fault(0xA4, 0x00, None);
    assert_no_session(&h.transmit_apdu(&session, &get_cert));
}

#[test]
fn apdu_policy_over_http_without_key_generation() {
    let h = start_bridge(default_config());
    let session = h.connect();

    // Rejected before reaching the card.
    let mut select_chained = build_select_piv_apdu().to_bytes().unwrap();
    select_chained[0] = 0x10;
    let mut get_cert_channel = build_get_certificate_apdu(Slot::Authentication)
        .to_bytes()
        .unwrap();
    get_cert_channel[0] = 0x01;
    let rejected: Vec<Vec<u8>> = vec![
        select_chained,
        get_cert_channel,
        build_get_response_apdu(0x20).to_bytes().unwrap(),
        Apdu::new(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C, 0x03, 0x5F, 0xC1, 0x02])
            .to_bytes()
            .unwrap(),
        vec![0x00, 0xF7, 0x00, 0x9B, 0x00],
        Apdu::new(0x00, 0x87, 0x07, 0x9A, vec![0x7C, 0x00])
            .to_bytes()
            .unwrap(),
        Apdu::new(0x00, 0xFB, 0x00, 0x00, vec![])
            .to_bytes()
            .unwrap(),
    ];
    let gated: Vec<Vec<u8>> = vec![
        build_generate_key_apdu(Slot::Authentication)
            .to_bytes()
            .unwrap(),
        build_mgmt_auth_request_witness_apdu(ManagementKeyAlgorithm::Aes192)
            .to_bytes()
            .unwrap(),
        build_delete_certificate_apdu(Slot::Authentication)
            .to_bytes()
            .unwrap(),
    ];

    let before = h.probe.transmitted_count();
    for raw in &rejected {
        let resp = h.transmit(&session, raw);
        assert_eq!(resp.status, 403, "{} -> {}", hex::encode(raw), resp.body);
        assert!(resp.has_cors());
    }
    for raw in &gated {
        let resp = h.transmit(&session, raw);
        assert_eq!(resp.status, 403, "{} -> {}", hex::encode(raw), resp.body);
        assert!(resp.error().contains("--allow-generate"), "{}", resp.body);
    }
    assert_eq!(h.probe.transmitted_count(), before);

    // Allowed for every bridge slot; the parsed APDU is forwarded byte-for-byte.
    let mut allowed = vec![
        build_select_piv_apdu(),
        build_verify_pin_apdu(TEST_PIN).unwrap(),
        Apdu::new(0x00, 0x20, 0x00, 0x80, vec![]),
    ];
    for slot in SLOTS {
        allowed.push(build_get_metadata_apdu(slot));
        allowed.push(build_get_certificate_apdu(slot));
        allowed.push(build_sign_apdu(slot, &[0x42; 32]));
    }
    for apdu in &allowed {
        let raw = apdu.to_bytes().unwrap();
        let sent_before = h.probe.transmitted_count();
        let resp = h.transmit(&session, &raw);
        assert_eq!(resp.status, 200, "{} -> {}", hex::encode(&raw), resp.body);
        assert_eq!(h.probe.transmitted()[sent_before].0, raw);
    }
}

#[test]
fn apdu_policy_over_http_with_key_generation() {
    let h = start_bridge(default_config().with_allow_key_generation(true));
    assert!(h.handle.allow_key_generation());
    let session = h.connect();

    // Management key mutual auth (AES-192)
    let alg = ManagementKeyAlgorithm::Aes192;
    let w_resp = h
        .transmit_apdu(&session, &build_mgmt_auth_request_witness_apdu(alg))
        .apdu();
    assert!(w_resp.is_success());
    let witness = parse_witness_response(w_resp.data(), alg.block_size()).unwrap();
    let decrypted_witness = decrypt_mgmt_witness(alg, &TEST_MGMT_KEY, &witness).unwrap();
    let host_challenge = [0x5Au8; 16];
    let verify_mgmt =
        build_mgmt_auth_verify_apdu(alg, &decrypted_witness, &host_challenge).unwrap();
    let m_resp = h.transmit_apdu(&session, &verify_mgmt).apdu();
    assert!(m_resp.is_success());
    let card_resp = parse_challenge_response(m_resp.data(), alg.block_size()).unwrap();
    let expected_card_resp = encrypt_mgmt_challenge(alg, &TEST_MGMT_KEY, &host_challenge).unwrap();
    assert!(verify_mgmt_challenge_response(
        &expected_card_resp,
        &card_resp
    ));

    // GENERATE then delete the stale certificate
    let gen_resp = h
        .transmit_apdu(&session, &build_generate_key_apdu(Slot::Authentication))
        .apdu();
    assert!(gen_resp.is_success());
    let public_key = parse_public_key_response(gen_resp.data()).expect("generated public key");
    assert_eq!(public_key, *test_signing_key().verifying_key());
    assert!(
        h.transmit_apdu(
            &session,
            &build_delete_certificate_apdu(Slot::Authentication)
        )
        .apdu()
        .is_success()
    );

    for slot in SLOTS {
        for apdu in [
            build_generate_key_apdu(slot),
            build_delete_certificate_apdu(slot),
        ] {
            assert_eq!(h.transmit_apdu(&session, &apdu).status, 200);
        }
    }
    for alg in [
        ManagementKeyAlgorithm::Tdes,
        ManagementKeyAlgorithm::Aes128,
        ManagementKeyAlgorithm::Aes256,
    ] {
        assert_eq!(
            h.transmit_apdu(&session, &build_mgmt_auth_request_witness_apdu(alg))
                .status,
            200
        );
    }

    // Still rejected with key generation enabled.
    let still_rejected: Vec<Vec<u8>> = vec![
        Apdu::new(0x00, 0x47, 0x00, 0x9B, vec![0xAC, 0x03, 0x80, 0x01, 0x11])
            .to_bytes()
            .unwrap(),
        Apdu::new(0x00, 0x47, 0x00, 0x9A, vec![0xAC, 0x03, 0x80, 0x01, 0x07])
            .to_bytes()
            .unwrap(),
        Apdu::new(
            0x00,
            0xDB,
            0x3F,
            0xFF,
            vec![0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0x00],
        )
        .to_bytes()
        .unwrap(),
        Apdu::new(0x00, 0x24, 0x00, 0x80, vec![0xFF; 16])
            .to_bytes()
            .unwrap(),
        {
            let mut generate = build_generate_key_apdu(Slot::Authentication)
                .to_bytes()
                .unwrap();
            generate[0] = 0x10;
            generate
        },
    ];
    let before = h.probe.transmitted_count();
    for raw in &still_rejected {
        assert_eq!(
            h.transmit(&session, raw).status,
            403,
            "{} must be rejected",
            hex::encode(raw)
        );
    }
    assert_eq!(h.probe.transmitted_count(), before);
}

#[test]
fn weak_explicit_tokens_are_rejected() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let origins = vec![ALLOWED_ORIGIN.to_string()];
    for token in [
        "wrongtoken".to_string(),
        "x".repeat(MIN_TOKEN_LEN - 1),
        format!("{} {}", "x".repeat(16), "y".repeat(16)),
    ] {
        assert!(BridgeConfig::new(addr, origins.clone(), Some(token), "mock").is_err());
    }
    let ipv6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
    assert!(BridgeConfig::new(ipv6, origins.clone(), None, "mock").is_err());

    let token = "x".repeat(MIN_TOKEN_LEN);
    let config = BridgeConfig::new(addr, origins, Some(token.clone()), "mock").unwrap();
    let h = start_bridge(config);
    assert_eq!(h.token, token);
    assert_eq!(h.health().status, 200);
}

#[test]
fn non_exclusive_transport_is_rejected_at_connect() {
    struct SharedTransport(MockPivCard);

    impl Transport for SharedTransport {
        fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
            self.0.transmit(apdu)
        }

        fn is_connected(&self) -> bool {
            self.0.is_connected()
        }

        fn is_exclusive_session(&self) -> bool {
            false
        }

        fn exclusive(&mut self, f: &mut dyn FnMut(&mut dyn Transport) -> Result<()>) -> Result<()> {
            self.0.exclusive(f)
        }
    }

    let probe = Arc::new(Probe::default());
    let (drop_tx, drops) = mpsc::channel();
    let card_probe = Arc::clone(&probe);
    let handle = BridgeServer::start(default_config().with_backend_name("mock"), move || {
        let card: Box<dyn Transport + Send> = Box::new(SharedTransport(MockPivCard::new(
            test_signing_key(),
            Arc::clone(&card_probe),
            drop_tx.clone(),
        )));
        Ok(card)
    })
    .expect("start bridge server");
    let client = Client {
        addr: handle.local_addr(),
        token: handle.token().to_string(),
    };

    let resp = client.try_connect();
    assert_eq!(resp.status, 500, "{}", resp.body);
    assert!(resp.has_cors());
    assert!(resp.error().contains("exclusive card session"));
    assert!(resp.error().contains("connect_exclusive"));
    assert_eq!(
        probe.transmitted_count(),
        0,
        "bridge must reject non-exclusive transport before sending any APDU"
    );
    drops
        .try_recv()
        .expect("bridge must drop the rejected shared transport immediately");

    handle.shutdown();
}

#[test]
fn exclusive_bridge_session_blocks_second_pcsc_client_and_resets_auth_on_end() {
    /// Models a single smart card behind PC/SC with `ShareMode::Shared` vs
    /// `ShareMode::Exclusive` handles and `SCardDisconnect(Disposition::ResetCard)`
    /// on drop.
    struct SimulatedPcscReader {
        card: MockPivCard,
        shared_handles: usize,
        exclusive_held: bool,
        resets: usize,
    }

    impl SimulatedPcscReader {
        fn new(probe: Arc<Probe>, dummy_drop: Sender<()>) -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(Self {
                card: MockPivCard::new(test_signing_key(), probe, dummy_drop),
                shared_handles: 0,
                exclusive_held: false,
                resets: 0,
            }))
        }

        fn connect(
            reader: &Arc<Mutex<Self>>,
            exclusive: bool,
            on_drop: Option<Sender<()>>,
        ) -> Result<SimulatedPcscHandle> {
            let mut guard = reader.lock().unwrap();
            if guard.exclusive_held || (exclusive && guard.shared_handles > 0) {
                return Err(Error::ConnectionFailed(
                    "another PC/SC client is currently using the card".to_string(),
                ));
            }
            if exclusive {
                guard.exclusive_held = true;
            } else {
                guard.shared_handles += 1;
            }
            Ok(SimulatedPcscHandle {
                reader: Arc::clone(reader),
                exclusive,
                on_drop,
            })
        }
    }

    struct SimulatedPcscHandle {
        reader: Arc<Mutex<SimulatedPcscReader>>,
        exclusive: bool,
        on_drop: Option<Sender<()>>,
    }

    impl Drop for SimulatedPcscHandle {
        fn drop(&mut self) {
            {
                let mut guard = self.reader.lock().unwrap();
                // pcsc::Card::drop calls SCardDisconnect(Disposition::ResetCard),
                // clearing card-side PIN and management-key authentication before
                // releasing ownership.
                guard.card.pin_verified = false;
                guard.card.mgmt_authenticated = false;
                guard.card.pending_chunks.clear();
                guard.resets += 1;
                if self.exclusive {
                    guard.exclusive_held = false;
                } else {
                    guard.shared_handles -= 1;
                }
            }
            if let Some(tx) = self.on_drop.take() {
                let _ = tx.send(());
            }
        }
    }

    impl Transport for SimulatedPcscHandle {
        fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
            let mut guard = self.reader.lock().unwrap();
            guard.card.transmit(apdu)
        }

        fn is_connected(&self) -> bool {
            true
        }

        fn is_exclusive_session(&self) -> bool {
            self.exclusive
        }

        fn exclusive(&mut self, f: &mut dyn FnMut(&mut dyn Transport) -> Result<()>) -> Result<()> {
            f(self)
        }
    }

    let authenticate_bridge_session = |client: &Client, session_id: &str| {
        assert!(
            client
                .transmit_apdu(session_id, &build_verify_pin_apdu(TEST_PIN).unwrap())
                .apdu()
                .is_success()
        );
        let alg = ManagementKeyAlgorithm::Aes192;
        let witness_resp = client
            .transmit_apdu(session_id, &build_mgmt_auth_request_witness_apdu(alg))
            .apdu();
        assert!(witness_resp.is_success());
        let witness = parse_witness_response(witness_resp.data(), alg.block_size()).unwrap();
        let decrypted_witness = decrypt_mgmt_witness(alg, &TEST_MGMT_KEY, &witness).unwrap();
        let host_challenge = [0x42u8; 16];
        let verify_mgmt =
            build_mgmt_auth_verify_apdu(alg, &decrypted_witness, &host_challenge).unwrap();
        assert!(
            client
                .transmit_apdu(session_id, &verify_mgmt)
                .apdu()
                .is_success()
        );
    };

    let assert_second_client_unauthenticated = |reader: &Arc<Mutex<SimulatedPcscReader>>| {
        let mut peer = SimulatedPcscReader::connect(reader, false, None)
            .expect("second PC/SC client should be able to connect after session ends");
        let sign_resp = peer
            .transmit(&build_sign_apdu(Slot::Authentication, &[0x99; 32]))
            .unwrap();
        assert_eq!(
            sign_resp.status_word(),
            0x6982,
            "second client must not inherit verified PIN state"
        );
        let gen_resp = peer
            .transmit(&build_generate_key_apdu(Slot::Authentication))
            .unwrap();
        assert_eq!(
            gen_resp.status_word(),
            0x6982,
            "second client must not inherit management-key auth state"
        );
    };

    let probe = Arc::new(Probe::default());
    let (dummy_tx, _dummy_rx) = mpsc::channel();
    let reader = SimulatedPcscReader::new(Arc::clone(&probe), dummy_tx);
    let (release_tx, releases) = mpsc::channel();

    let connector_reader = Arc::clone(&reader);
    let connector_release = release_tx.clone();
    let config = default_config()
        .with_allow_key_generation(true)
        .with_idle_timeout(Duration::from_millis(200))
        .unwrap()
        .with_backend_name("mock");
    let handle = BridgeServer::start(config, move || {
        let h =
            SimulatedPcscReader::connect(&connector_reader, true, Some(connector_release.clone()))?;
        Ok(Box::new(h) as Box<dyn Transport + Send>)
    })
    .expect("start bridge");
    let client = Client {
        addr: handle.local_addr(),
        token: handle.token().to_string(),
    };

    // 1. If another local PC/SC client already holds a shared handle, bridge
    //    /v1/connect must fail closed instead of sharing card state with it.
    let pre_existing_peer = SimulatedPcscReader::connect(&reader, false, None).unwrap();
    let blocked = client.try_connect();
    assert_eq!(blocked.status, 502, "{}", blocked.body);
    assert!(blocked.error().contains("another PC/SC client"));
    drop(pre_existing_peer);

    // 2. Open an exclusive bridge session and authenticate both PIN and
    //    management key. Between requests, no second PC/SC client can connect
    //    to sign or generate a key, while the bridge itself works normally.
    let session = client.connect();
    authenticate_bridge_session(&client, &session);

    assert!(
        SimulatedPcscReader::connect(&reader, false, None).is_err(),
        "second shared PC/SC client must be blocked during authenticated bridge session"
    );
    assert!(
        SimulatedPcscReader::connect(&reader, true, None).is_err(),
        "second exclusive PC/SC client must be blocked during authenticated bridge session"
    );

    // Bridge signing and key generation continue to work in the exclusive session.
    let sign_resp = client
        .transmit_apdu(
            &session,
            &build_sign_apdu(Slot::Authentication, &[0x11; 32]),
        )
        .apdu();
    assert!(sign_resp.is_success());
    let gen_resp = client
        .transmit_apdu(&session, &build_generate_key_apdu(Slot::Authentication))
        .apdu();
    assert!(gen_resp.is_success());

    // 3. Explicit /v1/disconnect resets card auth before releasing exclusive access.
    assert_eq!(client.disconnect(&session).status, 200);
    releases
        .try_recv()
        .expect("disconnect must release exclusive card handle");
    assert_second_client_unauthenticated(&reader);

    // 4. Idle timeout expiry resets card auth before releasing exclusive access.
    let session = client.connect();
    authenticate_bridge_session(&client, &session);
    assert!(SimulatedPcscReader::connect(&reader, false, None).is_err());
    releases
        .recv_timeout(EVENT_TIMEOUT)
        .expect("idle watchdog must release exclusive card handle");
    assert_second_client_unauthenticated(&reader);

    // 5. Bridge shutdown resets card auth before releasing exclusive access.
    let session = client.connect();
    authenticate_bridge_session(&client, &session);
    assert!(SimulatedPcscReader::connect(&reader, false, None).is_err());
    handle.shutdown();
    releases
        .try_recv()
        .expect("shutdown must release exclusive card handle");
    assert_second_client_unauthenticated(&reader);
}
