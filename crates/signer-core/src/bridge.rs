//! Hardened local loopback HTTP bridge for YubiKey PIV communication.
//!
//! Modern Chromium browsers block raw WebUSB access to YubiKey PIV applets
//! twice on standard web pages (via Yubico VID `0x1050` in `usb_blocklist.cc`
//! and the WICG Smart Card CCID class `0x0B` protected interface check). This
//! module provides a std-only, transport-agnostic HTTP/1.1 loopback bridge that
//! lets browser applications communicate with a local PC/SC (or mock) YubiKey
//! across macOS, Linux, and Windows in any browser.
//!
//! # Security Controls
//!
//! - **Loopback-only binding**: rejects any non-loopback [`SocketAddr`].
//! - **DNS rebinding protection**: requires a `Host` header matching
//!   `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`.
//! - **Strict origin allowlist**: requires an exact `Origin` match on every
//!   request (including `OPTIONS` preflight); wildcard `"*"` is rejected.
//! - **Constant-time Bearer auth**: requires `Authorization: Bearer <token>`
//!   on all non-`OPTIONS` routes, verified with [`subtle::ConstantTimeEq`].
//! - **PIV-only APDU allowlist**: [`validate_bridge_apdu`] permits only
//!   `SELECT PIV_AID`, `VERIFY` (PIV PIN), `GENERAL AUTHENTICATE`,
//!   `GENERATE ASYMMETRIC`, `GET DATA`, and `GET RESPONSE`.
//! - **Request framing limits**: rejects `Transfer-Encoding`, enforces
//!   `Content-Type: application/json` on `POST`, and caps header (8 KiB) and
//!   body (16 KiB) sizes.

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::yubikey::Transport;
use crate::yubikey::apdu::Apdu;
use crate::yubikey::piv::{PIV_AID, build_get_response_apdu, build_select_piv_apdu};

/// Default loopback TCP port for the local PC/SC bridge.
pub const DEFAULT_BRIDGE_PORT: u16 = 8765;

/// Default allowed browser origins for the local PC/SC bridge.
pub const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://storopoli.github.io",
];

/// Maximum HTTP request header block size in bytes (8 KiB).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Maximum HTTP request body size in bytes (16 KiB).
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Maximum number of concurrent TCP connections handled by the bridge.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Per-connection socket read timeout.
const SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-connection socket write timeout (accommodates hardware touch prompts).
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Factory closure producing a fresh [`Transport`] when `/v1/connect` is called.
pub type TransportConnector = Box<dyn FnMut() -> Result<Box<dyn Transport + Send>> + Send>;

/// Configuration for [`BridgeServer`].
#[derive(Clone)]
pub struct BridgeConfig {
    /// Loopback socket address to bind.
    bind_addr: SocketAddr,
    /// Exact allowed browser `Origin` header values.
    allowed_origins: Vec<String>,
    /// Per-session bearer authentication token.
    auth_token: Zeroizing<String>,
    /// Human-readable backend name reported by `/v1/health` (e.g. `"pcsc"` or `"mock"`).
    backend_name: String,
}

impl fmt::Debug for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeConfig")
            .field("bind_addr", &self.bind_addr)
            .field("allowed_origins", &self.allowed_origins)
            .field("auth_token", &"<redacted>")
            .field("backend_name", &self.backend_name)
            .finish()
    }
}

impl BridgeConfig {
    /// Creates a loopback configuration bound to `127.0.0.1:<port>` with default
    /// allowed origins and a freshly generated 256-bit random bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if the OS CSPRNG fails.
    pub fn loopback(port: u16) -> Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let origins = DEFAULT_ALLOWED_ORIGINS
            .iter()
            .map(|origin| (*origin).to_string())
            .collect();
        Self::new(addr, origins, None, "pcsc")
    }

    /// Creates a validated bridge configuration.
    ///
    /// When `auth_token` is `None`, a fresh 32-byte (64-hex-character) token is
    /// generated via [`getrandom::fill`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if:
    /// - `bind_addr` is not a loopback address
    /// - `allowed_origins` is empty, contains `"*"`, or contains invalid origins
    /// - an explicit `auth_token` is empty or contains whitespace/control characters
    /// - CSPRNG token generation fails
    pub fn new(
        bind_addr: SocketAddr,
        allowed_origins: Vec<String>,
        auth_token: Option<String>,
        backend_name: impl Into<String>,
    ) -> Result<Self> {
        let token = match auth_token {
            Some(tok) => Zeroizing::new(tok),
            None => generate_random_hex(32)?,
        };

        let config = Self {
            bind_addr,
            allowed_origins,
            auth_token: token,
            backend_name: backend_name.into(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Appends an additional allowed `Origin` after validating it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if `origin` is invalid or `"*"`.
    pub fn add_allowed_origin(&mut self, origin: impl Into<String>) -> Result<()> {
        let origin = origin.into();
        validate_origin_entry(&origin)?;
        if !self
            .allowed_origins
            .iter()
            .any(|existing| existing == &origin)
        {
            self.allowed_origins.push(origin);
        }
        Ok(())
    }

    /// Replaces the backend name reported by `/v1/health`.
    #[must_use]
    pub fn with_backend_name(mut self, backend_name: impl Into<String>) -> Self {
        self.backend_name = backend_name.into();
        self
    }

    /// Validates all security invariants of this configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if any security invariant is violated.
    pub fn validate(&self) -> Result<()> {
        if !self.bind_addr.ip().is_loopback() {
            return Err(Error::ConnectionFailed(format!(
                "bridge must bind to a loopback address, got {}",
                self.bind_addr
            )));
        }

        if self.allowed_origins.is_empty() {
            return Err(Error::ConnectionFailed(
                "bridge requires at least one allowed Origin".to_string(),
            ));
        }

        for origin in &self.allowed_origins {
            validate_origin_entry(origin)?;
        }

        if self.auth_token.is_empty()
            || self
                .auth_token
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(Error::ConnectionFailed(
                "bridge auth token must be non-empty and contain no whitespace or control characters"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Returns the configured bind address.
    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Returns the configured exact-match `Origin` allowlist.
    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Returns the bearer authentication token.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.auth_token
    }

    /// Returns the backend transport name reported by `/v1/health`.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }
}

/// Validates a single configured `Origin` entry.
fn validate_origin_entry(origin: &str) -> Result<()> {
    if origin.is_empty() || origin == "*" || origin.contains('*') {
        return Err(Error::ConnectionFailed(format!(
            "invalid or wildcard bridge origin rejected: '{origin}'"
        )));
    }
    if !(origin.starts_with("http://") || origin.starts_with("https://")) {
        return Err(Error::ConnectionFailed(format!(
            "bridge origin must start with http:// or https://: '{origin}'"
        )));
    }
    if origin.ends_with('/')
        || origin
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(Error::ConnectionFailed(format!(
            "bridge origin must not have a trailing slash or whitespace: '{origin}'"
        )));
    }
    Ok(())
}

/// Generates `byte_len` cryptographically random bytes encoded as lowercase hex.
fn generate_random_hex(byte_len: usize) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new(vec![0u8; byte_len]);
    getrandom::fill(&mut raw)
        .map_err(|e| Error::ConnectionFailed(format!("CSPRNG failed: {e}")))?;
    Ok(Zeroizing::new(hex::encode(&*raw)))
}

/// Active hardware session protected by a single-slot mutex.
struct ActiveSession {
    session_id: Zeroizing<String>,
    transport: Box<dyn Transport + Send>,
}

/// Shared mutable state for the bridge server.
struct BridgeState {
    connector: TransportConnector,
    active_session: Option<ActiveSession>,
}

/// Immutable configuration and shared state passed to connection handlers.
struct SharedContext {
    port: u16,
    allowed_origins: Vec<String>,
    auth_token: Zeroizing<String>,
    backend_name: String,
    state: Mutex<BridgeState>,
    active_connections: AtomicUsize,
}

/// RAII guard that decrements the active connection counter on drop.
struct ConnectionGuard {
    ctx: Arc<SharedContext>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.ctx.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Local HTTP/1.1 loopback bridge server for YubiKey PIV communication.
#[derive(Debug)]
pub struct BridgeServer;

impl BridgeServer {
    /// Starts the loopback bridge server in a background thread.
    ///
    /// # Arguments
    ///
    /// * `config` - Validated [`BridgeConfig`] (loopback address, origins, token)
    /// * `connector` - Closure called on `POST /v1/connect` to open a [`Transport`]
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if configuration validation fails or
    /// binding the TCP listener fails.
    pub fn start<F>(config: BridgeConfig, connector: F) -> Result<BridgeHandle>
    where
        F: FnMut() -> Result<Box<dyn Transport + Send>> + Send + 'static,
    {
        config.validate()?;

        let listener = TcpListener::bind(config.bind_addr).map_err(|e| {
            Error::ConnectionFailed(format!(
                "failed to bind bridge listener on {}: {e}",
                config.bind_addr
            ))
        })?;

        let local_addr = listener.local_addr().map_err(|e| {
            Error::ConnectionFailed(format!("failed to read bridge local address: {e}"))
        })?;

        if !local_addr.ip().is_loopback() {
            return Err(Error::ConnectionFailed(format!(
                "bound bridge address is not loopback: {local_addr}"
            )));
        }

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let token = config.auth_token.clone();
        let allowed_origins = config.allowed_origins.clone();

        let ctx = Arc::new(SharedContext {
            port: local_addr.port(),
            allowed_origins: config.allowed_origins,
            auth_token: config.auth_token,
            backend_name: config.backend_name,
            state: Mutex::new(BridgeState {
                connector: Box::new(connector),
                active_session: None,
            }),
            active_connections: AtomicUsize::new(0),
        });

        let accept_shutdown = Arc::clone(&shutdown_flag);
        let accept_ctx = Arc::clone(&ctx);

        let thread = thread::Builder::new()
            .name("yubikey-bridge".to_string())
            .spawn(move || {
                accept_loop(listener, accept_shutdown, accept_ctx);
            })
            .map_err(|e| Error::ConnectionFailed(format!("failed to spawn bridge thread: {e}")))?;

        Ok(BridgeHandle {
            local_addr,
            token,
            allowed_origins,
            shutdown_flag,
            thread: Some(thread),
        })
    }
}

/// Handle to a running [`BridgeServer`].
///
/// Automatically shuts down the server thread cleanly when dropped.
pub struct BridgeHandle {
    local_addr: SocketAddr,
    token: Zeroizing<String>,
    allowed_origins: Vec<String>,
    shutdown_flag: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for BridgeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeHandle")
            .field("local_addr", &self.local_addr)
            .field("allowed_origins", &self.allowed_origins)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BridgeHandle {
    /// Returns the actual bound loopback [`SocketAddr`].
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the base HTTP URL for this bridge instance.
    #[must_use]
    pub fn url(&self) -> String {
        match self.local_addr.ip() {
            IpAddr::V4(ip) => format!("http://{ip}:{}", self.local_addr.port()),
            IpAddr::V6(ip) => format!("http://[{ip}]:{}", self.local_addr.port()),
        }
    }

    /// Returns the per-session bearer authentication token.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the exact allowed `Origin` list.
    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Gracefully stops the bridge server and joins its listener thread.
    pub fn shutdown(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        if !self.shutdown_flag.swap(true, Ordering::SeqCst) {
            // Wake the blocking `TcpListener::accept` immediately.
            let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

/// Validates and parses a raw ISO 7816-4 APDU against the bridge's PIV-only allowlist.
///
/// Only `CLA = 0x00` and the following PIV instructions are permitted:
/// - `0xA4` (`SELECT`): **only** when `P1 = 0x04`, `P2 = 0x00`, and `data == PIV_AID`
/// - `0x20` (`VERIFY`): **only** when `P1 = 0x00`, `P2 = 0x80`, and `data.len()` is `0` or `8`
/// - `0x87` (`GENERAL AUTHENTICATE`)
/// - `0x47` (`GENERATE ASYMMETRIC`)
/// - `0xCB` (`GET DATA`)
/// - `0xC0` (`GET RESPONSE`)
///
/// Every other instruction (including `PUT DATA 0xDB`, `CHANGE REFERENCE DATA 0x24`,
/// `RESET RETRY COUNTER 0x2C`, `SET MANAGEMENT KEY 0xFF`, `RESET 0xFB`, or `SELECT`
/// for any non-PIV applet AID) is rejected.
///
/// # Errors
///
/// Returns [`Error::ApduError`] if the raw APDU is malformed or not on the allowlist.
pub fn validate_bridge_apdu(raw: &[u8]) -> Result<Apdu> {
    let apdu = parse_raw_apdu(raw)?;

    if apdu.cla() != 0x00 {
        return Err(Error::ApduError(format!(
            "APDU CLA 0x{:02X} is not allowed by bridge",
            apdu.cla()
        )));
    }

    match apdu.ins() {
        // SELECT: strictly PIV applet AID only
        0xA4 => {
            if apdu.p1() != 0x04 || apdu.p2() != 0x00 || apdu.data() != PIV_AID.as_slice() {
                return Err(Error::ApduError(
                    "bridge only permits SELECT for the PIV applet AID".to_string(),
                ));
            }
        }
        // VERIFY: strictly PIV PIN (P1=0x00, P2=0x80) with 0 (retry query) or 8-byte padded PIN
        0x20 => {
            if apdu.p1() != 0x00
                || apdu.p2() != 0x80
                || !(apdu.data().is_empty() || apdu.data().len() == 8)
            {
                return Err(Error::ApduError(
                    "bridge only permits VERIFY for PIV PIN (P1=0x00, P2=0x80, len 0 or 8)"
                        .to_string(),
                ));
            }
        }
        // GENERAL AUTHENTICATE, GENERATE ASYMMETRIC, GET DATA, GET RESPONSE
        0x87 | 0x47 | 0xCB | 0xC0 => {}
        other => {
            return Err(Error::ApduError(format!(
                "APDU instruction 0x{other:02X} is not allowed by bridge"
            )));
        }
    }

    Ok(apdu)
}

/// Parses raw ISO 7816-4 short or extended APDU bytes into an [`Apdu`].
fn parse_raw_apdu(raw: &[u8]) -> Result<Apdu> {
    if raw.len() < 4 {
        return Err(Error::ApduError(format!(
            "APDU too short: expected at least 4 bytes, got {}",
            raw.len()
        )));
    }

    let cla = raw[0];
    let ins = raw[1];
    let p1 = raw[2];
    let p2 = raw[3];
    let body = &raw[4..];

    let (data, le) = if body.is_empty() {
        // Case 1: no data, no Le
        (Vec::new(), None)
    } else if body.len() == 1 {
        // Case 2S: no data, short Le
        let le = if body[0] == 0 {
            Apdu::MAX_SHORT_LE
        } else {
            u32::from(body[0])
        };
        (Vec::new(), Some(le))
    } else if body[0] != 0 {
        // Case 3S / 4S: short Lc
        let lc = usize::from(body[0]);
        if body.len() == 1 + lc {
            (body[1..1 + lc].to_vec(), None)
        } else if body.len() == 1 + lc + 1 {
            let le_byte = body[1 + lc];
            let le = if le_byte == 0 {
                Apdu::MAX_SHORT_LE
            } else {
                u32::from(le_byte)
            };
            (body[1..1 + lc].to_vec(), Some(le))
        } else {
            return Err(Error::ApduError(
                "malformed short APDU Lc/Le framing".to_string(),
            ));
        }
    } else if body.len() == 3 {
        // Case 2E: extended Le with no data
        let le16 = u16::from_be_bytes([body[1], body[2]]);
        let le = if le16 == 0 {
            Apdu::MAX_EXTENDED_LE
        } else {
            u32::from(le16)
        };
        (Vec::new(), Some(le))
    } else if body.len() > 3 {
        // Case 3E / 4E: extended Lc
        let lc = usize::from(u16::from_be_bytes([body[1], body[2]]));
        if lc == 0 {
            return Err(Error::ApduError(
                "extended APDU Lc must be non-zero".to_string(),
            ));
        }
        if body.len() == 3 + lc {
            (body[3..3 + lc].to_vec(), None)
        } else if body.len() == 3 + lc + 2 {
            let le16 = u16::from_be_bytes([body[3 + lc], body[3 + lc + 1]]);
            let le = if le16 == 0 {
                Apdu::MAX_EXTENDED_LE
            } else {
                u32::from(le16)
            };
            (body[3..3 + lc].to_vec(), Some(le))
        } else {
            return Err(Error::ApduError(
                "malformed extended APDU Lc/Le framing".to_string(),
            ));
        }
    } else {
        return Err(Error::ApduError(
            "malformed extended APDU header".to_string(),
        ));
    };

    Ok(Apdu::with_optional_le(cla, ins, p1, p2, data, le))
}

/// Main TCP listener loop.
fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, ctx: Arc<SharedContext>) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let (stream, _peer) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };

        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let prev = ctx.active_connections.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_CONCURRENT_CONNECTIONS {
            ctx.active_connections.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = write_json_response(
                &mut stream,
                503,
                "Service Unavailable",
                None,
                &ErrorBody {
                    error: "too many concurrent bridge connections",
                },
            );
            continue;
        }

        let worker_ctx = Arc::clone(&ctx);
        let spawn_result = thread::Builder::new()
            .name("yubikey-bridge-conn".to_string())
            .spawn(move || {
                let _guard = ConnectionGuard {
                    ctx: Arc::clone(&worker_ctx),
                };
                handle_connection(stream, &worker_ctx);
            });

        if spawn_result.is_err() {
            ctx.active_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Parsed HTTP/1.1 request.
struct HttpRequest {
    method: String,
    path: String,
    host: Option<String>,
    origin: Option<String>,
    authorization: Option<Zeroizing<String>>,
    content_type: Option<String>,
    body: Zeroizing<Vec<u8>>,
}

/// Error produced while reading or parsing an HTTP request.
struct HttpParseError {
    status: u16,
    reason: &'static str,
    message: &'static str,
}

/// Handles a single HTTP/1.1 connection.
fn handle_connection(mut stream: TcpStream, ctx: &SharedContext) {
    let _ = stream.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_WRITE_TIMEOUT));

    let req = match read_http_request(&mut stream) {
        Ok(Some(req)) => req,
        Ok(None) => return, // Client closed without sending data (e.g. wakeup/preconnect)
        Err(err) => {
            let _ = write_json_response(
                &mut stream,
                err.status,
                err.reason,
                None,
                &ErrorBody { error: err.message },
            );
            return;
        }
    };

    // 1. Validate Host header (DNS rebinding defense)
    if !req
        .host
        .as_deref()
        .is_some_and(|h| is_valid_loopback_host(h, ctx.port))
    {
        let _ = write_json_response(
            &mut stream,
            403,
            "Forbidden",
            None,
            &ErrorBody {
                error: "invalid or missing Host header",
            },
        );
        return;
    }

    // 2. Validate Origin header (exact match against allowlist; never wildcard)
    let matched_origin = match req.origin.as_deref() {
        Some(origin) if ctx.allowed_origins.iter().any(|allowed| allowed == origin) => origin,
        _ => {
            let _ = write_json_response(
                &mut stream,
                403,
                "Forbidden",
                None,
                &ErrorBody {
                    error: "origin is missing or not allowed",
                },
            );
            return;
        }
    };

    // 3. Handle CORS preflight
    if req.method == "OPTIONS" {
        let _ = write_empty_response(&mut stream, 204, "No Content", Some(matched_origin));
        return;
    }

    // 4. Constant-time Bearer token authentication on all non-OPTIONS routes
    let token_valid = req
        .authorization
        .as_deref()
        .and_then(|val| val.strip_prefix("Bearer "))
        .is_some_and(|presented| ct_str_eq(presented, &ctx.auth_token));

    if !token_valid {
        let _ = write_json_response(
            &mut stream,
            401,
            "Unauthorized",
            Some(matched_origin),
            &ErrorBody {
                error: "missing or invalid bearer token",
            },
        );
        return;
    }

    // 5. Require Content-Type: application/json on POST requests
    if req.method == "POST"
        && !req
            .content_type
            .as_deref()
            .is_some_and(is_json_content_type)
    {
        let _ = write_json_response(
            &mut stream,
            415,
            "Unsupported Media Type",
            Some(matched_origin),
            &ErrorBody {
                error: "POST requests require Content-Type: application/json",
            },
        );
        return;
    }

    // 6. Dispatch routes
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/health") => {
            let _ = write_json_response(
                &mut stream,
                200,
                "OK",
                Some(matched_origin),
                &HealthResponse {
                    status: "ok",
                    version: env!("CARGO_PKG_VERSION"),
                    transport: &ctx.backend_name,
                },
            );
        }
        ("POST", "/v1/connect") => handle_connect(&mut stream, ctx, matched_origin, &req.body),
        ("POST", "/v1/transmit") => handle_transmit(&mut stream, ctx, matched_origin, &req.body),
        ("POST", "/v1/disconnect") => {
            handle_disconnect(&mut stream, ctx, matched_origin, &req.body)
        }
        (_, "/v1/health" | "/v1/connect" | "/v1/transmit" | "/v1/disconnect") => {
            let _ = write_json_response(
                &mut stream,
                405,
                "Method Not Allowed",
                Some(matched_origin),
                &ErrorBody {
                    error: "method not allowed",
                },
            );
        }
        _ => {
            let _ = write_json_response(
                &mut stream,
                404,
                "Not Found",
                Some(matched_origin),
                &ErrorBody {
                    error: "endpoint not found",
                },
            );
        }
    }
}

/// Reads and strictly parses a single HTTP/1.1 request from `stream`.
fn read_http_request(
    stream: &mut TcpStream,
) -> std::result::Result<Option<HttpRequest>, HttpParseError> {
    let mut raw = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let header_end = loop {
        if let Some(pos) = find_header_end(&raw) {
            break pos;
        }
        if raw.len() > MAX_HEADER_BYTES {
            return Err(HttpParseError {
                status: 431,
                reason: "Request Header Fields Too Large",
                message: "request headers exceed maximum allowed size",
            });
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                if raw.is_empty() {
                    return Ok(None);
                }
                return Err(HttpParseError {
                    status: 400,
                    reason: "Bad Request",
                    message: "incomplete HTTP request headers",
                });
            }
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_HEADER_BYTES && find_header_end(&raw).is_none() {
                    return Err(HttpParseError {
                        status: 431,
                        reason: "Request Header Fields Too Large",
                        message: "request headers exceed maximum allowed size",
                    });
                }
            }
            Err(_) => {
                return Err(HttpParseError {
                    status: 400,
                    reason: "Bad Request",
                    message: "failed to read HTTP request",
                });
            }
        }
    };

    if header_end > MAX_HEADER_BYTES {
        return Err(HttpParseError {
            status: 431,
            reason: "Request Header Fields Too Large",
            message: "request headers exceed maximum allowed size",
        });
    }

    let header_str = std::str::from_utf8(&raw[..header_end]).map_err(|_| HttpParseError {
        status: 400,
        reason: "Bad Request",
        message: "HTTP headers must be valid UTF-8",
    })?;

    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().ok_or(HttpParseError {
        status: 400,
        reason: "Bad Request",
        message: "missing HTTP request line",
    })?;

    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(HttpParseError {
        status: 400,
        reason: "Bad Request",
        message: "missing HTTP method",
    })?;
    let target = parts.next().ok_or(HttpParseError {
        status: 400,
        reason: "Bad Request",
        message: "missing HTTP request target",
    })?;
    let version = parts.next().ok_or(HttpParseError {
        status: 400,
        reason: "Bad Request",
        message: "missing HTTP version",
    })?;

    if parts.next().is_some() || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Err(HttpParseError {
            status: 400,
            reason: "Bad Request",
            message: "unsupported HTTP request line",
        });
    }

    let mut host: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut authorization: Option<Zeroizing<String>> = None;
    let mut content_type: Option<String> = None;
    let mut content_length: Option<usize> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(HttpParseError {
            status: 400,
            reason: "Bad Request",
            message: "malformed HTTP header line",
        })?;

        let name_lower = name.trim().to_ascii_lowercase();
        let value = value.trim();

        match name_lower.as_str() {
            "transfer-encoding" => {
                return Err(HttpParseError {
                    status: 400,
                    reason: "Bad Request",
                    message: "Transfer-Encoding is not supported",
                });
            }
            "host" => {
                if host.is_some() {
                    return Err(HttpParseError {
                        status: 400,
                        reason: "Bad Request",
                        message: "duplicate Host header",
                    });
                }
                host = Some(value.to_string());
            }
            "origin" => {
                if origin.is_some() {
                    return Err(HttpParseError {
                        status: 400,
                        reason: "Bad Request",
                        message: "duplicate Origin header",
                    });
                }
                origin = Some(value.to_string());
            }
            "authorization" => {
                if authorization.is_some() {
                    return Err(HttpParseError {
                        status: 400,
                        reason: "Bad Request",
                        message: "duplicate Authorization header",
                    });
                }
                authorization = Some(Zeroizing::new(value.to_string()));
            }
            "content-type" => {
                if content_type.is_some() {
                    return Err(HttpParseError {
                        status: 400,
                        reason: "Bad Request",
                        message: "duplicate Content-Type header",
                    });
                }
                content_type = Some(value.to_string());
            }
            "content-length" => {
                if content_length.is_some() {
                    return Err(HttpParseError {
                        status: 400,
                        reason: "Bad Request",
                        message: "duplicate Content-Length header",
                    });
                }
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(HttpParseError {
                        status: 400,
                        reason: "Bad Request",
                        message: "invalid Content-Length header",
                    });
                }
                let parsed = value.parse::<usize>().map_err(|_| HttpParseError {
                    status: 413,
                    reason: "Payload Too Large",
                    message: "Content-Length exceeds maximum body size",
                })?;
                if parsed > MAX_BODY_BYTES {
                    return Err(HttpParseError {
                        status: 413,
                        reason: "Payload Too Large",
                        message: "request body exceeds maximum allowed size",
                    });
                }
                content_length = Some(parsed);
            }
            _ => {}
        }
    }

    let expected_len = content_length.unwrap_or(0);
    let body_start = header_end + 4;
    let already_read = &raw[body_start..];
    if already_read.len() > expected_len {
        return Err(HttpParseError {
            status: 400,
            reason: "Bad Request",
            message: "request body larger than Content-Length",
        });
    }

    let mut body = Zeroizing::new(vec![0u8; expected_len]);
    body[..already_read.len()].copy_from_slice(already_read);
    if already_read.len() < expected_len {
        stream
            .read_exact(&mut body[already_read.len()..])
            .map_err(|_| HttpParseError {
                status: 400,
                reason: "Bad Request",
                message: "incomplete HTTP request body",
            })?;
    }

    Ok(Some(HttpRequest {
        method: method.to_string(),
        path: target.to_string(),
        host,
        origin,
        authorization,
        content_type,
        body,
    }))
}

/// Finds the byte index of `\r\n\r\n` terminating HTTP headers.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Validates that the HTTP `Host` header matches a loopback host and exact port.
fn is_valid_loopback_host(host: &str, port: u16) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    lower == format!("127.0.0.1:{port}")
        || lower == format!("localhost:{port}")
        || lower == format!("[::1]:{port}")
}

/// Validates that `Content-Type` has media type `application/json`.
fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    media_type.eq_ignore_ascii_case("application/json")
}

/// Compares two strings in constant time using [`subtle::ConstantTimeEq`].
fn ct_str_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Handles `POST /v1/connect`.
fn handle_connect(stream: &mut TcpStream, ctx: &SharedContext, origin: &str, body: &[u8]) {
    if !body.is_empty() {
        let parsed: std::result::Result<serde_json::Value, _> = serde_json::from_slice(body);
        match parsed {
            Ok(serde_json::Value::Object(_)) => {}
            _ => {
                let _ = write_json_response(
                    stream,
                    400,
                    "Bad Request",
                    Some(origin),
                    &ErrorBody {
                        error: "connect body must be an empty JSON object",
                    },
                );
                return;
            }
        }
    }

    let mut state = match ctx.state.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let _ = write_json_response(
                stream,
                500,
                "Internal Server Error",
                Some(origin),
                &ErrorBody {
                    error: "bridge state lock poisoned",
                },
            );
            return;
        }
    };

    // Close any previous session before opening a fresh transport
    state.active_session = None;

    let mut transport = match (state.connector)() {
        Ok(t) => t,
        Err(Error::DeviceNotFound) => {
            let _ = write_json_response(
                stream,
                404,
                "Not Found",
                Some(origin),
                &ErrorBody {
                    error: "no YubiKey device found",
                },
            );
            return;
        }
        Err(e) => {
            let msg = format!("failed to connect to YubiKey: {e}");
            let _ = write_json_response(
                stream,
                502,
                "Bad Gateway",
                Some(origin),
                &OwnedErrorBody { error: msg },
            );
            return;
        }
    };

    // Immediately select the PIV applet, completing any 0x6C wrong-Le retries
    // or 0x61 GET RESPONSE chaining before issuing a session ID.
    if let Err(msg) = select_piv_full(transport.as_mut()) {
        let _ = write_json_response(
            stream,
            502,
            "Bad Gateway",
            Some(origin),
            &OwnedErrorBody { error: msg },
        );
        return;
    }

    let session_id = match generate_random_hex(16) {
        Ok(id) => id,
        Err(_) => {
            let _ = write_json_response(
                stream,
                500,
                "Internal Server Error",
                Some(origin),
                &ErrorBody {
                    error: "failed to generate session ID",
                },
            );
            return;
        }
    };

    let response = ConnectResponse {
        session_id: session_id.as_str(),
    };
    let send_res = write_json_response(stream, 200, "OK", Some(origin), &response);
    if send_res.is_ok() {
        state.active_session = Some(ActiveSession {
            session_id,
            transport,
        });
    }
}

/// Selects the PIV applet, handling `0x6C XX` wrong-`Le` retries and `0x61 XX`
/// `GET RESPONSE` chaining up to bounded limits.
fn select_piv_full(transport: &mut dyn Transport) -> std::result::Result<(), String> {
    const MAX_SELECT_CHUNKS: usize = 32;

    let select_apdu = build_select_piv_apdu();
    let mut resp = transport
        .transmit(&select_apdu)
        .map_err(|e| format!("PIV SELECT transmit failed: {e}"))?;

    if let Some(correct_le) = resp.wrong_le() {
        let retry = select_apdu.with_le_override(Some(u32::from(correct_le)));
        resp = transport
            .transmit(&retry)
            .map_err(|e| format!("PIV SELECT retry transmit failed: {e}"))?;
    }

    let mut total_bytes = resp.data().len();
    let mut chunks = 0usize;

    while let Some(sw2) = resp.remaining_bytes() {
        chunks += 1;
        if chunks > MAX_SELECT_CHUNKS {
            return Err("PIV SELECT exceeded maximum GET RESPONSE chunk limit".to_string());
        }

        let get_resp = build_get_response_apdu(sw2);
        resp = transport
            .transmit(&get_resp)
            .map_err(|e| format!("PIV SELECT GET RESPONSE transmit failed: {e}"))?;

        if let Some(correct_le) = resp.wrong_le() {
            let retry = get_resp.with_le_override(Some(u32::from(correct_le)));
            resp = transport
                .transmit(&retry)
                .map_err(|e| format!("PIV SELECT GET RESPONSE retry transmit failed: {e}"))?;
        }

        total_bytes = total_bytes.saturating_add(resp.data().len());
        if total_bytes > MAX_BODY_BYTES {
            return Err("PIV SELECT response exceeded maximum size".to_string());
        }
    }

    if resp.is_success() {
        Ok(())
    } else {
        Err(format!(
            "PIV SELECT failed with status word {:02X}{:02X}",
            resp.sw1(),
            resp.sw2()
        ))
    }
}

/// Handles `POST /v1/transmit`.
fn handle_transmit(stream: &mut TcpStream, ctx: &SharedContext, origin: &str, body: &[u8]) {
    let req: TransmitRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(_) => {
            let _ = write_json_response(
                stream,
                400,
                "Bad Request",
                Some(origin),
                &ErrorBody {
                    error: "invalid JSON body for /v1/transmit",
                },
            );
            return;
        }
    };

    let apdu_hex = req
        .apdu
        .trim()
        .strip_prefix("0x")
        .or_else(|| req.apdu.trim().strip_prefix("0X"))
        .unwrap_or_else(|| req.apdu.trim());

    let raw_apdu = match hex::decode(apdu_hex) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(_) => {
            let _ = write_json_response(
                stream,
                400,
                "Bad Request",
                Some(origin),
                &ErrorBody {
                    error: "APDU field must be valid hex",
                },
            );
            return;
        }
    };

    let mut apdu = match validate_bridge_apdu(&raw_apdu) {
        Ok(apdu) => apdu,
        Err(e) => {
            let msg = format!("APDU rejected by bridge policy: {e}");
            let _ = write_json_response(
                stream,
                403,
                "Forbidden",
                Some(origin),
                &OwnedErrorBody { error: msg },
            );
            return;
        }
    };

    let mut state = match ctx.state.lock() {
        Ok(guard) => guard,
        Err(_) => {
            apdu.zeroize_data();
            let _ = write_json_response(
                stream,
                500,
                "Internal Server Error",
                Some(origin),
                &ErrorBody {
                    error: "bridge state lock poisoned",
                },
            );
            return;
        }
    };

    let session_matches = state
        .active_session
        .as_ref()
        .is_some_and(|session| ct_str_eq(&req.session_id, &session.session_id));

    if !session_matches {
        apdu.zeroize_data();
        let _ = write_json_response(
            stream,
            409,
            "Conflict",
            Some(origin),
            &ErrorBody {
                error: "no active session or session_id mismatch",
            },
        );
        return;
    }

    let transmit_result = state
        .active_session
        .as_mut()
        .expect("verified active session")
        .transport
        .transmit(&apdu);

    // Always scrub APDU payload (PINs / management auth blocks) immediately after transmit
    apdu.zeroize_data();

    match transmit_result {
        Ok(resp) => {
            let mut full = Vec::with_capacity(resp.data().len() + 2);
            full.extend_from_slice(resp.data());
            full.push(resp.sw1());
            full.push(resp.sw2());

            let _ = write_json_response(
                stream,
                200,
                "OK",
                Some(origin),
                &TransmitResponse {
                    response: hex::encode(&full),
                },
            );
        }
        Err(Error::DeviceDisconnected) => {
            state.active_session = None;
            let _ = write_json_response(
                stream,
                503,
                "Service Unavailable",
                Some(origin),
                &ErrorBody {
                    error: "YubiKey device disconnected",
                },
            );
        }
        Err(e) => {
            let msg = format!("APDU transmit failed: {e}");
            let _ = write_json_response(
                stream,
                502,
                "Bad Gateway",
                Some(origin),
                &OwnedErrorBody { error: msg },
            );
        }
    }
}

/// Handles `POST /v1/disconnect`.
fn handle_disconnect(stream: &mut TcpStream, ctx: &SharedContext, origin: &str, body: &[u8]) {
    let req: DisconnectRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(_) => {
            let _ = write_json_response(
                stream,
                400,
                "Bad Request",
                Some(origin),
                &ErrorBody {
                    error: "invalid JSON body for /v1/disconnect",
                },
            );
            return;
        }
    };

    let mut state = match ctx.state.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let _ = write_json_response(
                stream,
                500,
                "Internal Server Error",
                Some(origin),
                &ErrorBody {
                    error: "bridge state lock poisoned",
                },
            );
            return;
        }
    };

    let session_matches = state
        .active_session
        .as_ref()
        .is_some_and(|session| ct_str_eq(&req.session_id, &session.session_id));

    if !session_matches {
        let _ = write_json_response(
            stream,
            409,
            "Conflict",
            Some(origin),
            &ErrorBody {
                error: "no active session or session_id mismatch",
            },
        );
        return;
    }

    state.active_session = None;
    let _ = write_json_response(
        stream,
        200,
        "OK",
        Some(origin),
        &DisconnectResponse { disconnected: true },
    );
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
    version: &'a str,
    transport: &'a str,
}

#[derive(Serialize)]
struct ConnectResponse<'a> {
    session_id: &'a str,
}

#[derive(Deserialize)]
struct TransmitRequest {
    session_id: String,
    apdu: String,
}

impl Drop for TransmitRequest {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.apdu.zeroize();
    }
}

#[derive(Serialize)]
struct TransmitResponse {
    response: String,
}

#[derive(Deserialize)]
struct DisconnectRequest {
    session_id: String,
}

impl Drop for DisconnectRequest {
    fn drop(&mut self) {
        self.session_id.zeroize();
    }
}

#[derive(Serialize)]
struct DisconnectResponse {
    disconnected: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct OwnedErrorBody {
    error: String,
}

/// Writes an HTTP/1.1 JSON response with strict security and optional CORS headers.
fn write_json_response<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    allowed_origin: Option<&str>,
    payload: &T,
) -> std::io::Result<()> {
    let body =
        serde_json::to_vec(payload).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n",
        body.len()
    );
    if let Some(origin) = allowed_origin {
        header.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\n\
             Vary: Origin\r\n\
             Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Max-Age: 600\r\n"
        ));
    }
    header.push_str("\r\n");

    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

/// Writes an empty HTTP/1.1 response (e.g. `204 No Content` for CORS preflight).
fn write_empty_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    allowed_origin: Option<&str>,
) -> std::io::Result<()> {
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n"
    );
    if let Some(origin) = allowed_origin {
        header.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\n\
             Vary: Origin\r\n\
             Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Max-Age: 600\r\n"
        ));
    }
    header.push_str("\r\n");

    stream.write_all(header.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yubikey::Slot;
    use crate::yubikey::piv::{
        build_generate_key_apdu, build_get_certificate_apdu, build_get_response_apdu,
        build_sign_apdu, build_verify_pin_apdu,
    };

    #[test]
    fn config_rejects_non_loopback_and_wildcard_origin() {
        let non_loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8765);
        assert!(
            BridgeConfig::new(
                non_loopback,
                vec!["http://localhost:8000".to_string()],
                None,
                "mock",
            )
            .is_err()
        );

        let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8765);
        assert!(
            BridgeConfig::new(lan, vec!["http://localhost:8000".to_string()], None, "mock")
                .is_err()
        );

        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert!(BridgeConfig::new(loopback, vec!["*".to_string()], None, "mock").is_err());
        assert!(
            BridgeConfig::new(
                loopback,
                vec!["https://*.example.com".to_string()],
                None,
                "mock",
            )
            .is_err()
        );
        assert!(BridgeConfig::new(loopback, vec![], None, "mock").is_err());

        let valid = BridgeConfig::loopback(0).unwrap();
        assert_eq!(valid.token().len(), 64);
        assert!(format!("{valid:?}").contains("<redacted>"));
        assert!(!format!("{valid:?}").contains(valid.token()));
    }

    #[test]
    fn apdu_allowlist_permits_piv_and_rejects_dangerous_commands() {
        // Allowed PIV commands
        let select_piv = build_select_piv_apdu().to_bytes().unwrap();
        assert!(validate_bridge_apdu(&select_piv).is_ok());

        let verify_pin = build_verify_pin_apdu("123456").unwrap().to_bytes().unwrap();
        assert!(validate_bridge_apdu(&verify_pin).is_ok());

        // VERIFY retry query (empty data)
        assert!(validate_bridge_apdu(&[0x00, 0x20, 0x00, 0x80]).is_ok());

        let get_cert = build_get_certificate_apdu(Slot::Authentication)
            .to_bytes()
            .unwrap();
        assert!(validate_bridge_apdu(&get_cert).is_ok());

        let get_resp = build_get_response_apdu(0x20).to_bytes().unwrap();
        assert!(validate_bridge_apdu(&get_resp).is_ok());

        let sign = build_sign_apdu(Slot::Authentication, &[0xAB; 32])
            .to_bytes()
            .unwrap();
        assert!(validate_bridge_apdu(&sign).is_ok());

        let generate_apdu = build_generate_key_apdu(Slot::Authentication)
            .to_bytes()
            .unwrap();
        assert!(validate_bridge_apdu(&generate_apdu).is_ok());

        // Rejected: SELECT FIDO2 AID (A0 00 00 06 47 2F 00 01)
        let select_fido2 = Apdu::new(
            0x00,
            0xA4,
            0x04,
            0x00,
            vec![0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01],
        )
        .to_bytes()
        .unwrap();
        assert!(validate_bridge_apdu(&select_fido2).is_err());

        // Rejected: PUT DATA (0xDB), CHANGE PIN (0x24), RESET RETRY (0x2C), SET MGMT KEY (0xFF), RESET (0xFB)
        for &ins in &[0xDBu8, 0x24, 0x2C, 0xFF, 0xFB] {
            let forbidden = Apdu::new(0x00, ins, 0x00, 0x00, vec![0x01])
                .to_bytes()
                .unwrap();
            assert!(
                validate_bridge_apdu(&forbidden).is_err(),
                "INS 0x{ins:02X} must be rejected"
            );
        }

        // Rejected: non-zero CLA
        assert!(validate_bridge_apdu(&[0x80, 0xCB, 0x3F, 0xFF]).is_err());

        // Rejected: VERIFY with wrong P2 or wrong data length
        assert!(validate_bridge_apdu(&[0x00, 0x20, 0x00, 0x81]).is_err());
        assert!(validate_bridge_apdu(&[0x00, 0x20, 0x00, 0x80, 0x04, 1, 2, 3, 4]).is_err());

        // Rejected: truncated / malformed
        assert!(validate_bridge_apdu(&[0x00, 0xA4, 0x04]).is_err());
        assert!(validate_bridge_apdu(&[0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x01]).is_err());
    }
}
