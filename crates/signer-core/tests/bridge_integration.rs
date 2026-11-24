//! End-to-end integration tests for the hardened local PC/SC loopback bridge.
//!
//! Spawns a real [`BridgeServer`] bound to `127.0.0.1:0` backed by a mock PIV
//! YubiKey (using a real P-256 signing key, real DER X.509 certificate split
//! across multi-chunk `61 XX` responses, PIN verification, AES-192 management
//! key mutual auth, and real P-256 prehash signing) and exercises both security
//! boundaries and the full Ethereum signing flow over real loopback TCP HTTP.

// Silence unused crate dependency warnings for this integration test binary
use aes as _;
use alloy_primitives as _;
use alloy_rlp as _;
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
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use p256::FieldBytes;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use serde_json::Value;

use yubikey_evm_signer_core::bridge::{BridgeConfig, BridgeServer, MAX_BODY_BYTES};
use yubikey_evm_signer_core::crypto::{
    create_ethereum_signature, try_recover_public_key, verify_signature,
};
use yubikey_evm_signer_core::yubikey::piv::{
    ManagementKeyAlgorithm, PIV_AID, build_get_certificate_apdu, build_get_response_apdu,
    build_mgmt_auth_request_witness_apdu, build_mgmt_auth_verify_apdu, build_sign_apdu,
    build_verify_pin_apdu, decrypt_mgmt_witness, encrypt_mgmt_challenge,
    parse_certificate_public_key, parse_challenge_response, parse_signature_response,
    parse_witness_response, verify_mgmt_challenge_response,
};
use yubikey_evm_signer_core::yubikey::{Apdu, ApduResponse, Slot, Transport};
use yubikey_evm_signer_core::{Address, Eip1559Transaction, Error, Result, Transaction, U256};

const ALLOWED_ORIGIN: &str = "http://localhost:8000";
const TEST_PIN: &str = "123456";
const TEST_MGMT_KEY: [u8; 24] = [0x22; 24];

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

/// Realistic mock PIV smart card implementing [`Transport`].
struct MockPivCard {
    signing_key: SigningKey,
    piv_cert_obj: Vec<u8>,
    pending_chunks: Vec<Vec<u8>>,
    pin_verified: bool,
    pin_retries: u8,
    mgmt_witness: [u8; 16],
    mgmt_authenticated: bool,
}

impl MockPivCard {
    fn new(signing_key: SigningKey) -> Self {
        let piv_cert_obj = build_piv_certificate_object(signing_key.verifying_key());
        Self {
            signing_key,
            piv_cert_obj,
            pending_chunks: Vec::new(),
            pin_verified: false,
            pin_retries: 3,
            mgmt_witness: [0xA5; 16],
            mgmt_authenticated: false,
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

impl Transport for MockPivCard {
    fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
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
}

struct RawHttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

fn send_raw_http(addr: SocketAddr, request_bytes: &[u8]) -> RawHttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect to bridge");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");

    stream.write_all(request_bytes).expect("write HTTP request");
    stream.flush().expect("flush HTTP request");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .expect("read HTTP response");

    let raw = String::from_utf8(response_bytes).expect("UTF-8 HTTP response");
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .expect("HTTP response header/body split");

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

fn post_transmit(
    addr: SocketAddr,
    token: &str,
    session_id: &str,
    apdu_bytes: &[u8],
) -> RawHttpResponse {
    let body = serde_json::json!({
        "session_id": session_id,
        "apdu": hex::encode(apdu_bytes),
    })
    .to_string();

    let req = format!(
        "POST /v1/transmit HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Origin: {ALLOWED_ORIGIN}\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        addr.port(),
        body.len()
    );
    send_raw_http(addr, req.as_bytes())
}

#[test]
fn bridge_security_boundaries_and_end_to_end_signing() {
    // 0. Non-loopback bind address is rejected upfront
    let non_loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    assert!(
        BridgeConfig::new(non_loopback, vec![ALLOWED_ORIGIN.to_string()], None, "mock").is_err()
    );

    // Deterministic P-256 test key
    let key_bytes =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let signing_key =
        SigningKey::from_bytes(&FieldBytes::try_from(key_bytes.as_slice()).unwrap()).unwrap();
    let expected_vk = *signing_key.verifying_key();
    let expected_address = Address::from_public_key(&expected_vk);

    let config = BridgeConfig::loopback(0).unwrap().with_backend_name("mock");

    let card_key_bytes = key_bytes.clone();
    let handle = BridgeServer::start(config, move || {
        let sk = SigningKey::from_bytes(&FieldBytes::try_from(card_key_bytes.as_slice()).unwrap())
            .unwrap();
        let card: Box<dyn Transport + Send> = Box::new(MockPivCard::new(sk));
        Ok(card)
    })
    .expect("start bridge server");

    let addr = handle.local_addr();
    let port = addr.port();
    let token = handle.token().to_string();

    // 1. Security: missing Origin -> 403 (both OPTIONS and GET)
    let resp = send_raw_http(
        addr,
        format!("OPTIONS /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
    );
    assert_eq!(resp.status, 403);
    assert!(!resp.headers.contains_key("access-control-allow-origin"));

    let resp = send_raw_http(
        addr,
        format!(
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 403);

    // 2. Security: disallowed Origin -> 403 (both OPTIONS and POST)
    let resp = send_raw_http(
        addr,
        format!(
            "OPTIONS /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 403);
    assert!(!resp.headers.contains_key("access-control-allow-origin"));

    let resp = send_raw_http(
        addr,
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 403);

    // 3. Security: DNS rebinding Host header -> 403
    let resp = send_raw_http(
        addr,
        format!(
            "GET /v1/health HTTP/1.1\r\nHost: attacker.example:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 403);

    let resp = send_raw_http(
        addr,
        format!(
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:1\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 403);

    // 4. Security: missing or wrong Bearer token -> 401
    let resp = send_raw_http(
        addr,
        format!(
            "GET /v1/health HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 401);

    let resp = send_raw_http(
        addr,
        format!(
            "GET /v1/health HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer wrongtoken\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 401);

    // 5. Security: Transfer-Encoding rejected -> 400
    let resp = send_raw_http(
        addr,
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 400);

    // 6. Security: Non-JSON Content-Type on POST -> 415
    let resp = send_raw_http(
        addr,
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 415);

    // 7. Security: Oversized body -> 413
    let huge_len = MAX_BODY_BYTES + 1;
    let resp = send_raw_http(
        addr,
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {huge_len}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 413);

    // 8. Happy path: OPTIONS preflight
    let preflight = send_raw_http(
        addr,
        format!(
            "OPTIONS /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\n\r\n"
        )
        .as_bytes(),
    );
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

    // 9. Happy path: GET /v1/health
    let health = send_raw_http(
        addr,
        format!(
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(health.status, 200);
    let health_json: Value = serde_json::from_str(&health.body).unwrap();
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["transport"], "mock");

    // 10. Happy path: POST /v1/connect
    let connect = send_raw_http(
        addr,
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        )
        .as_bytes(),
    );
    assert_eq!(connect.status, 200);
    let connect_json: Value = serde_json::from_str(&connect.body).unwrap();
    let session_id = connect_json["session_id"].as_str().unwrap().to_string();
    assert_eq!(session_id.len(), 32);

    // 11. Security: Disallowed APDUs rejected with 403
    let select_fido2 = Apdu::new(
        0x00,
        0xA4,
        0x04,
        0x00,
        vec![0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01],
    )
    .to_bytes()
    .unwrap();
    assert_eq!(
        post_transmit(addr, &token, &session_id, &select_fido2).status,
        403
    );

    let put_data = Apdu::new(0x00, 0xDB, 0x3F, 0xFF, vec![0x5C, 0x03, 0x5F, 0xC1, 0x05])
        .to_bytes()
        .unwrap();
    assert_eq!(
        post_transmit(addr, &token, &session_id, &put_data).status,
        403
    );

    let reset_piv = Apdu::new(0x00, 0xFB, 0x00, 0x00, vec![])
        .to_bytes()
        .unwrap();
    assert_eq!(
        post_transmit(addr, &token, &session_id, &reset_piv).status,
        403
    );

    // 12. Happy path: GET DATA + 61 XX GET RESPONSE -> parse cert -> derive Ethereum address
    let get_cert_bytes = build_get_certificate_apdu(Slot::Authentication)
        .to_bytes()
        .unwrap();
    let mut cert_data = Vec::new();
    let mut resp_http = post_transmit(addr, &token, &session_id, &get_cert_bytes);
    assert_eq!(resp_http.status, 200);

    loop {
        let json: Value = serde_json::from_str(&resp_http.body).unwrap();
        let raw_resp = hex::decode(json["response"].as_str().unwrap()).unwrap();
        let apdu_resp = ApduResponse::try_from_bytes(raw_resp).unwrap();
        apdu_resp.check().unwrap();
        cert_data.extend_from_slice(apdu_resp.data());
        if let Some(rem) = apdu_resp.remaining_bytes() {
            let get_resp_bytes = build_get_response_apdu(rem).to_bytes().unwrap();
            resp_http = post_transmit(addr, &token, &session_id, &get_resp_bytes);
            assert_eq!(resp_http.status, 200);
        } else {
            break;
        }
    }

    let parsed_vk = parse_certificate_public_key(&cert_data).expect("valid P-256 cert");
    assert_eq!(Address::from_public_key(&parsed_vk), expected_address);

    // 13. Happy path: Management key mutual auth (AES-192) over bridge
    let alg = ManagementKeyAlgorithm::Aes192;
    let w_apdu = build_mgmt_auth_request_witness_apdu(alg)
        .to_bytes()
        .unwrap();
    let w_http = post_transmit(addr, &token, &session_id, &w_apdu);
    assert_eq!(w_http.status, 200);
    let w_resp = ApduResponse::try_from_bytes(
        hex::decode(
            serde_json::from_str::<Value>(&w_http.body).unwrap()["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(w_resp.is_success());
    let witness = parse_witness_response(w_resp.data(), alg.block_size()).unwrap();
    let decrypted_witness = decrypt_mgmt_witness(alg, &TEST_MGMT_KEY, &witness).unwrap();
    let host_challenge = [0x5Au8; 16];
    let verify_mgmt_apdu = build_mgmt_auth_verify_apdu(alg, &decrypted_witness, &host_challenge)
        .unwrap()
        .to_bytes()
        .unwrap();
    let m_http = post_transmit(addr, &token, &session_id, &verify_mgmt_apdu);
    assert_eq!(m_http.status, 200);
    let m_resp = ApduResponse::try_from_bytes(
        hex::decode(
            serde_json::from_str::<Value>(&m_http.body).unwrap()["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(m_resp.is_success());
    let card_resp = parse_challenge_response(m_resp.data(), alg.block_size()).unwrap();
    let expected_card_resp = encrypt_mgmt_challenge(alg, &TEST_MGMT_KEY, &host_challenge).unwrap();
    assert!(verify_mgmt_challenge_response(
        &expected_card_resp,
        &card_resp
    ));

    // 14. Happy path: VERIFY PIN (wrong -> 63 C2, then correct -> 90 00)
    let bad_pin = build_verify_pin_apdu("000000").unwrap().to_bytes().unwrap();
    let bad_http = post_transmit(addr, &token, &session_id, &bad_pin);
    assert_eq!(bad_http.status, 200);
    let bad_resp = ApduResponse::try_from_bytes(
        hex::decode(
            serde_json::from_str::<Value>(&bad_http.body).unwrap()["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(bad_resp.status_word(), 0x63C2);

    let good_pin = build_verify_pin_apdu(TEST_PIN).unwrap().to_bytes().unwrap();
    let good_http = post_transmit(addr, &token, &session_id, &good_pin);
    assert_eq!(good_http.status, 200);
    let good_resp = ApduResponse::try_from_bytes(
        hex::decode(
            serde_json::from_str::<Value>(&good_http.body).unwrap()["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(good_resp.is_success());

    // 15. Happy path: GENERAL AUTHENTICATE sign EIP-1559 transaction hash & verify recovery
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
    let sign_apdu = build_sign_apdu(Slot::Authentication, &tx_hash)
        .to_bytes()
        .unwrap();
    let sign_http = post_transmit(addr, &token, &session_id, &sign_apdu);
    assert_eq!(sign_http.status, 200);
    let sign_resp = ApduResponse::try_from_bytes(
        hex::decode(
            serde_json::from_str::<Value>(&sign_http.body).unwrap()["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
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

    // 16. Happy path: POST /v1/disconnect -> subsequent transmit rejected with 409
    let disc_body = serde_json::json!({ "session_id": session_id }).to_string();
    let disc_http = send_raw_http(
        addr,
        format!(
            "POST /v1/disconnect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ALLOWED_ORIGIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{disc_body}",
            disc_body.len()
        )
        .as_bytes(),
    );
    assert_eq!(disc_http.status, 200);
    let disc_json: Value = serde_json::from_str(&disc_http.body).unwrap();
    assert_eq!(disc_json["disconnected"], true);

    assert_eq!(
        post_transmit(addr, &token, &session_id, &sign_apdu).status,
        409
    );

    // Clean deterministic shutdown
    handle.shutdown();
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
