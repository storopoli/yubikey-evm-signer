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
//! - **`127.0.0.1`-only binding**: [`BridgeConfig`] rejects every bind address
//!   other than `127.0.0.1` (including `::1` and the rest of `127.0.0.0/8`).
//! - **DNS rebinding protection**: the `Host` header must equal exactly
//!   `127.0.0.1:<port>` of the bound listener; `localhost` and `[::1]` are
//!   never accepted, so a browser cannot be pointed at a squatter on another
//!   loopback address that shares the name. Port `80` is refused, because
//!   browsers omit the default HTTP port from `Host`.
//! - **Strict origin allowlist**: requires an exact `Origin` match on every
//!   request (including `OPTIONS` preflight); wildcard `"*"` is rejected.
//! - **Constant-time Bearer auth**: requires `Authorization: Bearer <token>`
//!   on all non-`OPTIONS` routes, verified with [`subtle::ConstantTimeEq`]. The
//!   token lives for the whole bridge process (not one session) and must be at
//!   least [`MIN_TOKEN_LEN`] visible ASCII characters.
//! - **PIV-only APDU allowlist**: [`validate_bridge_apdu`] permits only PIV
//!   `SELECT`, PIN `VERIFY`, P-256 signing, slot `GET METADATA`, and slot
//!   certificate `GET DATA`; key generation (`GENERATE ASYMMETRIC`,
//!   management-key `GENERAL AUTHENTICATE`, and certificate deletion) is
//!   opt-in via [`BridgeConfig::with_allow_key_generation`].
//! - **Atomic exchanges**: every forwarded APDU, including its `0x6C XX` retry
//!   and `0x61 XX` `GET RESPONSE` chain, runs as one exclusive PC/SC scope.
//! - **Session lifetime**: an idle session is closed (resetting the card) after
//!   [`BridgeConfig::idle_timeout`], and on shutdown; a card reset by another
//!   PC/SC client closes the session (`409`).
//! - **Request framing limits**: strict header syntax (no obs-fold, no bare CR
//!   or LF, `token` field names), rejects `Transfer-Encoding`, enforces
//!   `Content-Type: application/json` on `POST`, caps header (8 KiB) and body
//!   (16 KiB) sizes, and enforces a total per-request read deadline (`408`).

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::yubikey::apdu::Apdu;
use crate::yubikey::piv::{
    ManagementKeyAlgorithm, PIV_AID, build_delete_certificate_apdu, build_select_piv_apdu,
    transmit_chained,
};
use crate::yubikey::{Slot, Transport};

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
///
/// Further connections are answered with `503 Service Unavailable` and closed.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Minimum length of an explicitly configured bearer token, in characters.
///
/// Generated tokens are 64 hexadecimal characters (256 bits).
pub const MIN_TOKEN_LEN: usize = 32;

/// Default idle timeout after which an inactive hardware session is closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest accepted idle timeout.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Default total time allowed from accepting a connection to the end of the request body.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest accepted per-request read deadline.
pub const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-connection socket write timeout (accommodates hardware touch prompts).
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest time spent discarding unread request bytes after an early error response.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Most unread request bytes discarded after an early error response.
const MAX_DRAIN_BYTES: usize = 64 * 1024;

/// PIV slots the bridge operates on.
const BRIDGE_SLOTS: [Slot; 4] = [
    Slot::Authentication,
    Slot::Signature,
    Slot::KeyManagement,
    Slot::CardAuthentication,
];

/// Management key algorithms accepted for management-key `GENERAL AUTHENTICATE`.
const BRIDGE_MGMT_ALGORITHMS: [ManagementKeyAlgorithm; 4] = [
    ManagementKeyAlgorithm::Tdes,
    ManagementKeyAlgorithm::Aes128,
    ManagementKeyAlgorithm::Aes192,
    ManagementKeyAlgorithm::Aes256,
];

/// PIV key reference of the management key (`P2` of management `GENERAL AUTHENTICATE`).
const MANAGEMENT_KEY_REF: u8 = 0x9B;

/// PIV algorithm identifier for ECC P-256.
const ALG_ECCP256: u8 = 0x11;

/// `GENERATE ASYMMETRIC` control template requesting a P-256 key (`AC 03 80 01 11`).
const GENERATE_P256_TEMPLATE: [u8; 5] = [0xAC, 0x03, 0x80, 0x01, ALG_ECCP256];

/// Prefix of the P-256 signing dynamic authentication template (`7C 24 82 00 81 20`).
const SIGN_TEMPLATE_PREFIX: [u8; 6] = [0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];

/// Message returned when a key generation command is sent while it is disabled.
const KEY_GENERATION_DISABLED: &str = "key generation is disabled on this bridge \
     (GENERATE ASYMMETRIC, management-key GENERAL AUTHENTICATE and certificate deletion); \
     restart the bridge with --allow-generate to permit it";

/// Message returned when another PC/SC client reset the card under an active session.
const CARD_RESET_MESSAGE: &str = "the YubiKey was reset by another PC/SC client and the bridge \
     session was closed; reconnect (PIV selection, PIN and management key authentication \
     must be repeated)";

/// Message returned for an unknown, replaced, closed, or expired session ID.
const NO_SESSION_MESSAGE: &str = "no active session or session_id mismatch";

/// Default HTTP port, which the bridge refuses to use (see [`PORT_80_MESSAGE`]).
const DEFAULT_HTTP_PORT: u16 = 80;

/// Message returned when the bridge is configured for, or bound to, port 80.
const PORT_80_MESSAGE: &str = "bridge port 80 is not supported: browsers omit the default \
     HTTP port from the Host header (sending 127.0.0.1 instead of 127.0.0.1:80), so the \
     bridge's exact Host check would refuse every request; choose another port";

/// Factory closure producing a fresh [`Transport`] when `/v1/connect` is called.
pub type TransportConnector = Box<dyn FnMut() -> Result<Box<dyn Transport + Send>> + Send>;

/// Configuration for [`BridgeServer`].
#[derive(Clone)]
pub struct BridgeConfig {
    /// Socket address to bind (always `127.0.0.1:<port>`).
    bind_addr: SocketAddr,
    /// Exact allowed browser `Origin` header values.
    allowed_origins: Vec<String>,
    /// Bearer authentication token, valid for the lifetime of the bridge process.
    auth_token: Zeroizing<String>,
    /// Human-readable backend name reported by `/v1/health` (e.g. `"pcsc"` or `"mock"`).
    backend_name: String,
    /// Whether key generation commands are forwarded (see [`validate_bridge_apdu`]).
    allow_key_generation: bool,
    /// Inactivity period after which the hardware session is closed.
    idle_timeout: Duration,
    /// Total time allowed from accepting a connection to the end of the request body.
    request_timeout: Duration,
}

impl fmt::Debug for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeConfig")
            .field("bind_addr", &self.bind_addr)
            .field("allowed_origins", &self.allowed_origins)
            .field("auth_token", &"<redacted>")
            .field("backend_name", &self.backend_name)
            .field("allow_key_generation", &self.allow_key_generation)
            .field("idle_timeout", &self.idle_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl BridgeConfig {
    /// Creates a configuration bound to `127.0.0.1:<port>` with default allowed
    /// origins, a freshly generated 256-bit random bearer token, key generation
    /// disabled, and the default idle and request timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if `port` is `80` (see [`Self::new`])
    /// or the OS CSPRNG fails.
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
    /// The only supported bind address is `127.0.0.1` (any port except `80`,
    /// `0` for an ephemeral one); every other address, including other loopback
    /// addresses such as `::1` or `127.0.0.2`, is rejected. Browsers must reach
    /// the bridge as `http://127.0.0.1:<port>`, and the `Host` header must match
    /// exactly. Port `80` is refused because browsers omit the default HTTP port
    /// from `Host`, so that check could never pass.
    ///
    /// When `auth_token` is `None`, a fresh 32-byte (64-hex-character) token is
    /// generated via [`getrandom::fill`]. Key generation starts disabled and the
    /// timeouts start at [`DEFAULT_IDLE_TIMEOUT`] and [`DEFAULT_REQUEST_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if:
    /// - `bind_addr` is not `127.0.0.1`, or its port is `80`
    /// - `allowed_origins` is empty, contains `"*"`, or contains invalid origins
    /// - an explicit `auth_token` is shorter than [`MIN_TOKEN_LEN`] characters or
    ///   contains anything but visible ASCII (no whitespace or control characters)
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
            allow_key_generation: false,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
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

    /// Enables or disables forwarding of key generation commands.
    ///
    /// When enabled, [`validate_bridge_apdu`] additionally accepts
    /// `GENERATE ASYMMETRIC` (P-256, slots `9A`/`9C`/`9D`/`9E`), management-key
    /// `GENERAL AUTHENTICATE`, and the exact `PUT DATA` that deletes one of those
    /// slots' certificates. Anyone holding the bearer token can then overwrite
    /// keys if they also know the management key. Disabled by default.
    #[must_use]
    pub const fn with_allow_key_generation(mut self, allow: bool) -> Self {
        self.allow_key_generation = allow;
        self
    }

    /// Sets the idle timeout after which an inactive hardware session is closed
    /// and the card handle released (resetting the card).
    ///
    /// Every authenticated request for the session (`/v1/connect`, a
    /// `/v1/transmit` naming it) counts as activity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if `timeout` is zero or exceeds
    /// [`MAX_IDLE_TIMEOUT`].
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.idle_timeout = timeout;
        self.validate()?;
        Ok(self)
    }

    /// Sets the total time allowed from accepting a connection to receiving the
    /// end of the request body; slower requests are answered with `408`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if `timeout` is zero or exceeds
    /// [`MAX_REQUEST_TIMEOUT`].
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.request_timeout = timeout;
        self.validate()?;
        Ok(self)
    }

    /// Validates all security invariants of this configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if any security invariant is violated.
    pub fn validate(&self) -> Result<()> {
        if self.bind_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(Error::ConnectionFailed(format!(
                "bridge must bind to 127.0.0.1, got {}",
                self.bind_addr
            )));
        }

        if self.bind_addr.port() == DEFAULT_HTTP_PORT {
            return Err(Error::ConnectionFailed(PORT_80_MESSAGE.to_string()));
        }

        if self.allowed_origins.is_empty() {
            return Err(Error::ConnectionFailed(
                "bridge requires at least one allowed Origin".to_string(),
            ));
        }

        for origin in &self.allowed_origins {
            validate_origin_entry(origin)?;
        }

        if self.auth_token.len() < MIN_TOKEN_LEN
            || !self.auth_token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::ConnectionFailed(format!(
                "bridge auth token must be at least {MIN_TOKEN_LEN} visible ASCII characters \
                 with no whitespace or control characters"
            )));
        }

        if self.idle_timeout.is_zero() || self.idle_timeout > MAX_IDLE_TIMEOUT {
            return Err(Error::ConnectionFailed(format!(
                "bridge idle timeout must be greater than zero and at most {} seconds",
                MAX_IDLE_TIMEOUT.as_secs()
            )));
        }

        if self.request_timeout.is_zero() || self.request_timeout > MAX_REQUEST_TIMEOUT {
            return Err(Error::ConnectionFailed(format!(
                "bridge request timeout must be greater than zero and at most {} seconds",
                MAX_REQUEST_TIMEOUT.as_secs()
            )));
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

    /// Returns the bearer authentication token (valid for the bridge process lifetime).
    #[must_use]
    pub fn token(&self) -> &str {
        &self.auth_token
    }

    /// Returns the backend transport name reported by `/v1/health`.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// Returns whether key generation commands are forwarded.
    #[must_use]
    pub const fn allow_key_generation(&self) -> bool {
        self.allow_key_generation
    }

    /// Returns the idle timeout after which an inactive session is closed.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Returns the total per-request read deadline.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
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
    // Browsers serialize `Origin` without the scheme's default port and without
    // leading zeros, so such an entry could never match.
    let (default_port, authority) = match origin.strip_prefix("https://") {
        Some(authority) => ("443", authority),
        None => ("80", &origin["http://".len()..]),
    };
    if let Some((_, port)) = authority.rsplit_once(':')
        && port.bytes().all(|b| b.is_ascii_digit())
        && (port.is_empty() || port.starts_with('0') || port == default_port)
    {
        return Err(Error::ConnectionFailed(format!(
            "bridge origin must not spell out an empty, default ({default_port}) or \
             zero-padded port, because browsers omit or normalize it in the Origin header: \
             '{origin}'"
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
    /// Time of the last authenticated request for this session.
    last_activity: Instant,
}

/// Shared mutable state for the bridge server.
struct BridgeState {
    connector: TransportConnector,
    active_session: Option<ActiveSession>,
}

/// Immutable configuration and shared state passed to connection handlers.
struct SharedContext {
    /// Exact `Host` header value accepted (`<bound ip>:<bound port>`).
    expected_host: String,
    allowed_origins: Vec<String>,
    auth_token: Zeroizing<String>,
    backend_name: String,
    allow_key_generation: bool,
    idle_timeout: Duration,
    request_timeout: Duration,
    state: Mutex<BridgeState>,
    /// Signalled when a session is created and on shutdown (wakes the idle watchdog).
    session_changed: Condvar,
    active_connections: AtomicUsize,
    shutdown: AtomicBool,
}

impl SharedContext {
    /// Locks the bridge state, recovering it if a previous holder panicked.
    ///
    /// Used by cleanup paths (idle watchdog, shutdown) that must close the
    /// session even after a panic poisoned the mutex.
    fn lock_state_for_cleanup(&self) -> MutexGuard<'_, BridgeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
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
    /// Starts the loopback bridge server and its idle-session watchdog in
    /// background threads.
    ///
    /// # Arguments
    ///
    /// * `config` - Validated [`BridgeConfig`] (`127.0.0.1` address, origins, token)
    /// * `connector` - Closure called on `POST /v1/connect` to open a [`Transport`]
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if configuration validation fails,
    /// binding the TCP listener fails, the listener is not bound to `127.0.0.1`
    /// on a port other than `80`, or a thread cannot be spawned.
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

        if local_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(Error::ConnectionFailed(format!(
                "bound bridge address is not 127.0.0.1: {local_addr}"
            )));
        }

        if local_addr.port() == DEFAULT_HTTP_PORT {
            return Err(Error::ConnectionFailed(PORT_80_MESSAGE.to_string()));
        }

        let ctx = Arc::new(SharedContext {
            expected_host: format!("{}:{}", local_addr.ip(), local_addr.port()),
            allowed_origins: config.allowed_origins,
            auth_token: config.auth_token,
            backend_name: config.backend_name,
            allow_key_generation: config.allow_key_generation,
            idle_timeout: config.idle_timeout,
            request_timeout: config.request_timeout,
            state: Mutex::new(BridgeState {
                connector: Box::new(connector),
                active_session: None,
            }),
            session_changed: Condvar::new(),
            active_connections: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
        });

        let watchdog_ctx = Arc::clone(&ctx);
        let watchdog = thread::Builder::new()
            .name("yubikey-bridge-idle".to_string())
            .spawn(move || session_watchdog(&watchdog_ctx))
            .map_err(|e| {
                Error::ConnectionFailed(format!("failed to spawn bridge watchdog thread: {e}"))
            })?;

        let accept_ctx = Arc::clone(&ctx);
        let thread = match thread::Builder::new()
            .name("yubikey-bridge".to_string())
            .spawn(move || accept_loop(listener, accept_ctx))
        {
            Ok(thread) => thread,
            Err(e) => {
                ctx.shutdown.store(true, Ordering::SeqCst);
                ctx.session_changed.notify_all();
                let _ = watchdog.join();
                return Err(Error::ConnectionFailed(format!(
                    "failed to spawn bridge thread: {e}"
                )));
            }
        };

        Ok(BridgeHandle {
            local_addr,
            ctx,
            thread: Some(thread),
            watchdog: Some(watchdog),
        })
    }
}

/// Handle to a running [`BridgeServer`].
///
/// [`BridgeHandle::shutdown`] (or dropping the handle) stops the listener,
/// closes the active hardware session (releasing the card handle, which resets
/// the card for PC/SC transports), and joins the bridge threads.
pub struct BridgeHandle {
    local_addr: SocketAddr,
    ctx: Arc<SharedContext>,
    thread: Option<JoinHandle<()>>,
    watchdog: Option<JoinHandle<()>>,
}

impl fmt::Debug for BridgeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeHandle")
            .field("local_addr", &self.local_addr)
            .field("allowed_origins", &self.ctx.allowed_origins)
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

    /// Returns the base HTTP URL for this bridge instance (`http://127.0.0.1:<port>`).
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.ctx.expected_host)
    }

    /// Returns the bearer authentication token.
    ///
    /// The token is valid for the lifetime of the bridge process, across all
    /// hardware sessions.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.ctx.auth_token
    }

    /// Returns the exact allowed `Origin` list.
    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.ctx.allowed_origins
    }

    /// Returns whether key generation commands are forwarded.
    #[must_use]
    pub fn allow_key_generation(&self) -> bool {
        self.ctx.allow_key_generation
    }

    /// Returns the idle timeout after which an inactive session is closed.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        self.ctx.idle_timeout
    }

    /// Gracefully stops the bridge server, closes the active hardware session,
    /// and joins the bridge threads.
    pub fn shutdown(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        if !self.ctx.shutdown.swap(true, Ordering::SeqCst) {
            // Wake the blocking `TcpListener::accept` immediately.
            let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }

        // Close the session explicitly: dropping its transport ends the PC/SC
        // handle and resets the card, discarding PIN and management key state.
        // `/v1/connect` refuses to open a new session once `shutdown` is set.
        let closed = self.ctx.lock_state_for_cleanup().active_session.take();
        drop(closed);
        self.ctx.session_changed.notify_all();

        if let Some(handle) = self.watchdog.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

/// Closes the active session once it has been idle for `ctx.idle_timeout`, even
/// if no further request arrives. Sleeps on [`SharedContext::session_changed`]
/// (no polling) and exits on shutdown.
fn session_watchdog(ctx: &SharedContext) {
    let mut state = ctx.lock_state_for_cleanup();
    loop {
        if ctx.shutdown.load(Ordering::SeqCst) {
            state.active_session = None;
            return;
        }

        let wait = match state.active_session.as_ref() {
            None => None,
            Some(session) => {
                let idle = session.last_activity.elapsed();
                if idle >= ctx.idle_timeout {
                    // Dropping the transport releases the card handle (and resets the card).
                    state.active_session = None;
                    continue;
                }
                Some(ctx.idle_timeout - idle)
            }
        };

        state = match wait {
            None => ctx
                .session_changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner),
            Some(remaining) => {
                ctx.session_changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
        };
    }
}

/// Returns the active session if `session_id` names it and it has not idled out.
///
/// An expired session is closed here (so a request racing the watchdog sees the
/// same result as for an unknown session ID).
fn live_session<'a>(
    state: &'a mut BridgeState,
    session_id: &str,
    idle_timeout: Duration,
) -> Option<&'a mut ActiveSession> {
    if state
        .active_session
        .as_ref()
        .is_some_and(|session| session.last_activity.elapsed() >= idle_timeout)
    {
        state.active_session = None;
    }
    state
        .active_session
        .as_mut()
        .filter(|session| ct_str_eq(session_id, &session.session_id))
}

/// Validates and parses a raw ISO 7816-4 APDU against the bridge's PIV-only allowlist.
///
/// Only `CLA = 0x00` (no chaining, logical channel 0) and the following commands
/// are permitted; slots are limited to `9A`, `9C`, `9D`, and `9E`:
///
/// | Command | INS | Constraint |
/// |---|---|---|
/// | `SELECT` | `A4` | `P1=04 P2=00`, data = PIV AID |
/// | `VERIFY` | `20` | `P1=00 P2=80`, data empty (retry query) or 8 bytes |
/// | `GENERAL AUTHENTICATE` (sign) | `87` | `P1=11` (P-256), `P2` = slot, data = `7C 24 82 00 81 20` + 32-byte digest |
/// | `GET METADATA` | `F7` | `P1=00`, `P2` = slot, no data |
/// | `GET DATA` | `CB` | `P1=3F P2=FF`, data = `5C 03` + a slot certificate object ID |
///
/// When `allow_key_generation` is `true`, these are also permitted:
///
/// | Command | INS | Constraint |
/// |---|---|---|
/// | `GENERAL AUTHENTICATE` (management key) | `87` | `P2=9B`, `P1` ∈ {`03`, `08`, `0A`, `0C`} |
/// | `GENERATE ASYMMETRIC` | `47` | `P1=00`, `P2` = slot, data = `AC 03 80 01 11` (P-256) |
/// | `PUT DATA` (delete certificate) | `DB` | exactly `00 DB 3F FF 07 5C 03 <slot object ID> 53 00` |
///
/// When it is `false`, those commands are rejected with a message naming the
/// `--allow-generate` flag. Everything else (including `GET RESPONSE`, which the
/// bridge issues itself, `CHANGE REFERENCE DATA`, `RESET RETRY COUNTER`,
/// `SET MANAGEMENT KEY`, `RESET`, any other `PUT DATA` or `GET DATA`, and
/// `SELECT` of another applet) is rejected.
///
/// # Errors
///
/// Returns [`Error::ApduError`] if the raw APDU is malformed or not on the allowlist.
pub fn validate_bridge_apdu(raw: &[u8], allow_key_generation: bool) -> Result<Apdu> {
    let apdu = parse_raw_apdu(raw)?;

    if apdu.cla() != 0x00 {
        return Err(Error::ApduError(format!(
            "APDU CLA 0x{:02X} is not allowed by bridge",
            apdu.cla()
        )));
    }

    let is_slot = |p2: u8| BRIDGE_SLOTS.iter().any(|slot| slot.id() == p2);

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
        // GENERAL AUTHENTICATE with the management key (key generation only)
        0x87 if apdu.p2() == MANAGEMENT_KEY_REF => {
            require_key_generation(allow_key_generation)?;
            if !BRIDGE_MGMT_ALGORITHMS
                .iter()
                .any(|alg| alg.id() == apdu.p1())
            {
                return Err(Error::ApduError(
                    "bridge only permits management key GENERAL AUTHENTICATE with \
                     3DES, AES-128, AES-192, or AES-256"
                        .to_string(),
                ));
            }
        }
        // GENERAL AUTHENTICATE: P-256 signature of a 32-byte digest in a bridge slot
        0x87 => {
            let data = apdu.data();
            if apdu.p1() != ALG_ECCP256
                || !is_slot(apdu.p2())
                || data.len() != SIGN_TEMPLATE_PREFIX.len() + 32
                || !data.starts_with(&SIGN_TEMPLATE_PREFIX)
            {
                return Err(Error::ApduError(
                    "bridge only permits GENERAL AUTHENTICATE for P-256 signing of a 32-byte \
                     digest in slots 9A, 9C, 9D, or 9E"
                        .to_string(),
                ));
            }
        }
        // GET METADATA (Yubico): read-only slot metadata
        0xF7 => {
            if apdu.p1() != 0x00 || !is_slot(apdu.p2()) || !apdu.data().is_empty() {
                return Err(Error::ApduError(
                    "bridge only permits GET METADATA for slots 9A, 9C, 9D, or 9E".to_string(),
                ));
            }
        }
        // GET DATA: only the four slot certificate objects
        0xCB => {
            let is_slot_certificate = BRIDGE_SLOTS.iter().any(|slot| {
                let oid = slot.object_id();
                apdu.data() == [0x5C, 0x03, oid[0], oid[1], oid[2]].as_slice()
            });
            if apdu.p1() != 0x3F || apdu.p2() != 0xFF || !is_slot_certificate {
                return Err(Error::ApduError(
                    "bridge only permits GET DATA for the certificate objects of slots \
                     9A, 9C, 9D, or 9E"
                        .to_string(),
                ));
            }
        }
        // GENERATE ASYMMETRIC: P-256 in a bridge slot (key generation only)
        0x47 => {
            require_key_generation(allow_key_generation)?;
            if apdu.p1() != 0x00
                || !is_slot(apdu.p2())
                || apdu.data() != GENERATE_P256_TEMPLATE.as_slice()
            {
                return Err(Error::ApduError(
                    "bridge only permits GENERATE ASYMMETRIC for P-256 in slots 9A, 9C, 9D, or 9E"
                        .to_string(),
                ));
            }
        }
        // PUT DATA: only deleting a bridge slot's certificate (key generation only)
        0xDB => {
            require_key_generation(allow_key_generation)?;
            if !BRIDGE_SLOTS
                .iter()
                .any(|slot| apdu == build_delete_certificate_apdu(*slot))
            {
                return Err(Error::ApduError(
                    "bridge only permits PUT DATA that deletes the certificate of slot \
                     9A, 9C, 9D, or 9E"
                        .to_string(),
                ));
            }
        }
        other => {
            return Err(Error::ApduError(format!(
                "APDU instruction 0x{other:02X} is not allowed by bridge"
            )));
        }
    }

    Ok(apdu)
}

/// Rejects a key generation command unless key generation is enabled.
fn require_key_generation(allow_key_generation: bool) -> Result<()> {
    if allow_key_generation {
        Ok(())
    } else {
        Err(Error::ApduError(KEY_GENERATION_DISABLED.to_string()))
    }
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
fn accept_loop(listener: TcpListener, ctx: Arc<SharedContext>) {
    loop {
        if ctx.shutdown.load(Ordering::SeqCst) {
            break;
        }

        let (stream, _peer) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                if ctx.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let accepted_at = Instant::now();

        if ctx.shutdown.load(Ordering::SeqCst) {
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
                handle_connection(stream, &worker_ctx, accepted_at);
            });

        if spawn_result.is_err() {
            ctx.active_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Parsed HTTP/1.1 request line and header block.
struct HttpRequestHead {
    method: String,
    path: String,
    host: Option<String>,
    origin: Option<String>,
    authorization: Option<Zeroizing<String>>,
    content_type: Option<String>,
    /// `Access-Control-Request-Private-Network: true` was sent (PNA preflight).
    request_private_network: bool,
    /// Declared body length (`0` when absent or invalid).
    content_length: usize,
    /// First message-framing error (`Content-Length` / `Transfer-Encoding`).
    ///
    /// Reported only after `Host` and `Origin` are validated, so the response
    /// can carry CORS headers for an allowed page.
    framing_error: Option<HttpParseError>,
}

/// A parsed request head and the bytes already read past the header block.
type ParsedHead = (HttpRequestHead, Zeroizing<Vec<u8>>);

/// Error produced while reading or parsing an HTTP request.
#[derive(Clone, Copy)]
struct HttpParseError {
    status: u16,
    reason: &'static str,
    message: &'static str,
}

impl HttpParseError {
    /// Builds a `400 Bad Request` error.
    const fn bad_request(message: &'static str) -> Self {
        Self {
            status: 400,
            reason: "Bad Request",
            message,
        }
    }

    /// Builds a `413 Payload Too Large` error.
    const fn payload_too_large(message: &'static str) -> Self {
        Self {
            status: 413,
            reason: "Payload Too Large",
            message,
        }
    }

    /// Builds a `431 Request Header Fields Too Large` error.
    const fn headers_too_large() -> Self {
        Self {
            status: 431,
            reason: "Request Header Fields Too Large",
            message: "request headers exceed maximum allowed size",
        }
    }

    /// Builds a `408 Request Timeout` error.
    const fn timeout() -> Self {
        Self {
            status: 408,
            reason: "Request Timeout",
            message: "request was not received within the bridge request deadline",
        }
    }
}

/// Handles a single HTTP/1.1 connection (one request, then `Connection: close`).
fn handle_connection(mut stream: TcpStream, ctx: &SharedContext, accepted_at: Instant) {
    let _ = stream.set_write_timeout(Some(SOCKET_WRITE_TIMEOUT));
    let deadline = accepted_at + ctx.request_timeout;

    let (head, leftover) = match read_request_head(&mut stream, deadline) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return, // Client sent nothing (e.g. wakeup/preconnect)
        Err(err) => {
            respond_early_error(&mut stream, err, None);
            return;
        }
    };

    // 1. Validate Host header (DNS rebinding defense): exactly the bound address.
    match head.host.as_deref() {
        None => {
            respond_early_error(
                &mut stream,
                HttpParseError::bad_request("missing Host header"),
                None,
            );
            return;
        }
        Some(host) if host != ctx.expected_host => {
            respond_early_error(
                &mut stream,
                HttpParseError {
                    status: 403,
                    reason: "Forbidden",
                    message: "Host header does not match the bridge address",
                },
                None,
            );
            return;
        }
        Some(_) => {}
    }

    // 2. Validate Origin header (exact match against allowlist; never wildcard)
    let matched_origin = match head.origin.as_deref() {
        Some(origin) if ctx.allowed_origins.iter().any(|allowed| allowed == origin) => origin,
        _ => {
            respond_early_error(
                &mut stream,
                HttpParseError {
                    status: 403,
                    reason: "Forbidden",
                    message: "origin is missing or not allowed",
                },
                None,
            );
            return;
        }
    };

    // 3. Message framing errors and the body (CORS headers from here on)
    if let Some(err) = head.framing_error {
        respond_early_error(&mut stream, err, Some(matched_origin));
        return;
    }
    let body = match read_request_body(&mut stream, head.content_length, &leftover, deadline) {
        Ok(body) => body,
        Err(err) => {
            respond_early_error(&mut stream, err, Some(matched_origin));
            return;
        }
    };
    drop(leftover);

    // 4. Handle CORS preflight
    if head.method == "OPTIONS" {
        let _ = write_preflight_response(&mut stream, matched_origin, head.request_private_network);
        return;
    }

    // 5. Constant-time Bearer token authentication on all non-OPTIONS routes
    let token_valid = head
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

    // 6. Require Content-Type: application/json on POST requests
    if head.method == "POST"
        && !head
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

    // 7. Dispatch routes
    match (head.method.as_str(), head.path.as_str()) {
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
        ("POST", "/v1/connect") => handle_connect(&mut stream, ctx, matched_origin, &body),
        ("POST", "/v1/transmit") => handle_transmit(&mut stream, ctx, matched_origin, &body),
        ("POST", "/v1/disconnect") => handle_disconnect(&mut stream, ctx, matched_origin, &body),
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

/// Answers a request that was rejected before it was fully read, then closes
/// the connection gracefully so the client can read the response.
fn respond_early_error(stream: &mut TcpStream, err: HttpParseError, origin: Option<&str>) {
    let _ = write_json_response(
        stream,
        err.status,
        err.reason,
        origin,
        &ErrorBody { error: err.message },
    );
    drain_and_close(stream);
}

/// Half-closes `stream` and discards up to [`MAX_DRAIN_BYTES`] unread request
/// bytes for at most [`DRAIN_TIMEOUT`], so closing the socket does not send a
/// TCP reset that could destroy the response before the client reads it.
fn drain_and_close(stream: &mut TcpStream) {
    if stream.shutdown(Shutdown::Write).is_err() {
        return;
    }
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    let mut buf = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_DRAIN_BYTES {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => drained = drained.saturating_add(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    buf.zeroize();
}

/// Reads from `stream` into `buf`, failing with `408` once `deadline` passes.
///
/// The deadline bounds the whole request, not each `read`, so a client that
/// trickles bytes cannot hold a connection slot indefinitely.
fn read_before_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> std::result::Result<usize, HttpParseError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HttpParseError::timeout());
        }
        if stream.set_read_timeout(Some(remaining)).is_err() {
            return Err(HttpParseError::bad_request("failed to read HTTP request"));
        }
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            // Re-check the deadline: a read timeout may fire marginally early.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(HttpParseError::bad_request("failed to read HTTP request")),
        }
    }
}

/// Reads and strictly parses the request line and header block from `stream`.
///
/// Returns the parsed head and any bytes already read past the header block,
/// or `None` if the client closed (or let the deadline pass) without sending
/// anything.
fn read_request_head(
    stream: &mut TcpStream,
    deadline: Instant,
) -> std::result::Result<Option<ParsedHead>, HttpParseError> {
    let mut raw = Zeroizing::new(Vec::with_capacity(1024));
    let mut chunk = Zeroizing::new([0u8; 1024]);

    let header_end = loop {
        if let Some(pos) = find_header_end(&raw)? {
            break pos;
        }
        if raw.len() > MAX_HEADER_BYTES {
            return Err(HttpParseError::headers_too_large());
        }
        let n = match read_before_deadline(stream, chunk.as_mut_slice(), deadline) {
            Ok(n) => n,
            Err(_) if raw.is_empty() => return Ok(None),
            Err(err) => return Err(err),
        };
        if n == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Err(HttpParseError::bad_request(
                "incomplete HTTP request headers",
            ));
        }
        raw.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };

    if header_end > MAX_HEADER_BYTES {
        return Err(HttpParseError::headers_too_large());
    }

    let header_bytes = raw.get(..header_end).unwrap_or_default();
    let head = parse_request_head(header_bytes)?;
    let leftover = Zeroizing::new(raw.get(header_end + 4..).unwrap_or_default().to_vec());
    Ok(Some((head, leftover)))
}

/// Parses the request line and header fields (without the terminating empty line).
fn parse_request_head(header_bytes: &[u8]) -> std::result::Result<HttpRequestHead, HttpParseError> {
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| HttpParseError::bad_request("HTTP headers must be valid UTF-8"))?;

    let mut lines = header_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(HttpParseError::bad_request("missing HTTP request line"))?;

    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if parts.next().is_some()
        || !is_token(method)
        || target.is_empty()
        || target.bytes().any(|b| !b.is_ascii_graphic())
        || (version != "HTTP/1.1" && version != "HTTP/1.0")
    {
        return Err(HttpParseError::bad_request("unsupported HTTP request line"));
    }

    let mut head = HttpRequestHead {
        method: method.to_string(),
        path: target.to_string(),
        host: None,
        origin: None,
        authorization: None,
        content_type: None,
        request_private_network: false,
        content_length: 0,
        framing_error: None,
    };
    let mut content_length_seen = false;

    for line in lines {
        // obs-fold (RFC 9112 §5.2) and whitespace before the first field are rejected.
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(HttpParseError::bad_request(
                "obsolete line folding or leading whitespace in HTTP header",
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HttpParseError::bad_request("malformed HTTP header line"))?;

        // RFC 9112 §5.1: no whitespace between the field name and the colon.
        if !is_token(name) {
            return Err(HttpParseError::bad_request(
                "invalid HTTP header field name",
            ));
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F) {
            return Err(HttpParseError::bad_request(
                "invalid character in HTTP header value",
            ));
        }

        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => {
                head.framing_error
                    .get_or_insert(HttpParseError::bad_request(
                        "Transfer-Encoding is not supported",
                    ));
            }
            "host" => {
                set_unique(&mut head.host, value, "duplicate Host header")?;
            }
            "origin" => {
                set_unique(&mut head.origin, value, "duplicate Origin header")?;
            }
            "authorization" => {
                if head.authorization.is_some() {
                    return Err(HttpParseError::bad_request(
                        "duplicate Authorization header",
                    ));
                }
                head.authorization = Some(Zeroizing::new(value.to_string()));
            }
            "content-type" => {
                set_unique(
                    &mut head.content_type,
                    value,
                    "duplicate Content-Type header",
                )?;
            }
            "access-control-request-private-network" => {
                head.request_private_network |= value == "true";
            }
            "content-length" => {
                let parsed = if content_length_seen {
                    Err(HttpParseError::bad_request(
                        "duplicate Content-Length header",
                    ))
                } else {
                    parse_content_length(value)
                };
                content_length_seen = true;
                match parsed {
                    Ok(len) => head.content_length = len,
                    Err(err) => {
                        head.content_length = 0;
                        head.framing_error.get_or_insert(err);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(head)
}

/// Stores a header value that must appear at most once.
fn set_unique(
    slot: &mut Option<String>,
    value: &str,
    duplicate_message: &'static str,
) -> std::result::Result<(), HttpParseError> {
    if slot.is_some() {
        return Err(HttpParseError::bad_request(duplicate_message));
    }
    *slot = Some(value.to_string());
    Ok(())
}

/// Parses a `Content-Length` value: ASCII digits only, at most [`MAX_BODY_BYTES`].
fn parse_content_length(value: &str) -> std::result::Result<usize, HttpParseError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpParseError::bad_request("invalid Content-Length header"));
    }
    match value.parse::<usize>() {
        Ok(len) if len <= MAX_BODY_BYTES => Ok(len),
        _ => Err(HttpParseError::payload_too_large(
            "request body exceeds maximum allowed size",
        )),
    }
}

/// Reads exactly `expected_len` body bytes, starting with `already_read`.
fn read_request_body(
    stream: &mut TcpStream,
    expected_len: usize,
    already_read: &[u8],
    deadline: Instant,
) -> std::result::Result<Zeroizing<Vec<u8>>, HttpParseError> {
    if already_read.len() > expected_len {
        return Err(HttpParseError::bad_request(
            "request body larger than Content-Length",
        ));
    }

    // `expected_len` is at most MAX_BODY_BYTES (checked while parsing headers).
    let mut body = Zeroizing::new(vec![0u8; expected_len]);
    let mut filled = already_read.len();
    if let Some(prefix) = body.get_mut(..filled) {
        prefix.copy_from_slice(already_read);
    }
    while filled < expected_len {
        let n = read_before_deadline(stream, body.get_mut(filled..).unwrap_or_default(), deadline)?;
        if n == 0 {
            return Err(HttpParseError::bad_request("incomplete HTTP request body"));
        }
        filled += n;
    }
    Ok(body)
}

/// Finds the byte index of the `\r\n\r\n` terminating the header block.
///
/// Every line must end in CRLF: a bare LF or a CR not followed by LF before the
/// end of the header block is rejected with `400` (RFC 9112 §2.2 permits
/// rejecting both; accepting them invites parser disagreements).
fn find_header_end(buf: &[u8]) -> std::result::Result<Option<usize>, HttpParseError> {
    for (i, &byte) in buf.iter().enumerate() {
        match byte {
            b'\n' if i.checked_sub(1).and_then(|prev| buf.get(prev)) != Some(&b'\r') => {
                return Err(HttpParseError::bad_request(
                    "bare LF in HTTP header (CRLF line endings required)",
                ));
            }
            b'\r' => {
                match buf.get(i + 1) {
                    Some(b'\n') | None => {}
                    Some(_) => {
                        return Err(HttpParseError::bad_request("bare CR in HTTP header"));
                    }
                }
                if buf.get(i..i + 4) == Some(b"\r\n\r\n".as_slice()) {
                    return Ok(Some(i));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Returns `true` if `s` is a non-empty RFC 9110 `token` (`1*tchar`).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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

/// Writes the error response for a transport failure during `/v1/connect` or
/// `/v1/transmit` (`409` card reset, `503` device gone, `502` otherwise).
fn write_transport_error(stream: &mut TcpStream, origin: &str, context: &str, err: &Error) {
    let _ = match err {
        Error::CardReset => write_json_response(
            stream,
            409,
            "Conflict",
            Some(origin),
            &ErrorBody {
                error: CARD_RESET_MESSAGE,
            },
        ),
        Error::DeviceDisconnected => write_json_response(
            stream,
            503,
            "Service Unavailable",
            Some(origin),
            &ErrorBody {
                error: "YubiKey device disconnected",
            },
        ),
        other => write_json_response(
            stream,
            502,
            "Bad Gateway",
            Some(origin),
            &OwnedErrorBody {
                error: format!("{context}: {other}"),
            },
        ),
    };
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

    // `shutdown_inner` sets the flag before clearing the session under this lock,
    // so no session can be created after shutdown has cleared it.
    if ctx.shutdown.load(Ordering::SeqCst) {
        let _ = write_json_response(
            stream,
            503,
            "Service Unavailable",
            Some(origin),
            &ErrorBody {
                error: "bridge is shutting down",
            },
        );
        return;
    }

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

    // Select the PIV applet as one exclusive exchange (including any 0x6C
    // wrong-Le retry and 0x61 GET RESPONSE chain) before issuing a session ID.
    match transmit_chained(transport.as_mut(), &build_select_piv_apdu()) {
        Ok(resp) if resp.is_success() => {}
        Ok(resp) => {
            let msg = format!(
                "PIV SELECT failed with status word {:02X}{:02X}",
                resp.sw1(),
                resp.sw2()
            );
            let _ = write_json_response(
                stream,
                502,
                "Bad Gateway",
                Some(origin),
                &OwnedErrorBody { error: msg },
            );
            return;
        }
        Err(e) => {
            write_transport_error(stream, origin, "PIV SELECT failed", &e);
            return;
        }
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
            last_activity: Instant::now(),
        });
        drop(state);
        // Wake the idle watchdog so it starts timing the new session.
        ctx.session_changed.notify_all();
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

    let mut apdu = match validate_bridge_apdu(&raw_apdu, ctx.allow_key_generation) {
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

    let Some(session) = live_session(&mut state, &req.session_id, ctx.idle_timeout) else {
        apdu.zeroize_data();
        let _ = write_json_response(
            stream,
            409,
            "Conflict",
            Some(origin),
            &ErrorBody {
                error: NO_SESSION_MESSAGE,
            },
        );
        return;
    };

    // One exclusive exchange: the command, its 0x6C retry and its whole 0x61
    // GET RESPONSE chain, so no other PC/SC client can interleave.
    let transmit_result = transmit_chained(session.transport.as_mut(), &apdu);
    session.last_activity = Instant::now();

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
        Err(e) => {
            if matches!(e, Error::CardReset | Error::DeviceDisconnected) {
                // The card lost its PIV selection, PIN and management key state
                // (or is gone): end the session so the client reconnects cleanly.
                state.active_session = None;
            }
            write_transport_error(stream, origin, "APDU transmit failed", &e);
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

    if live_session(&mut state, &req.session_id, ctx.idle_timeout).is_none() {
        let _ = write_json_response(
            stream,
            409,
            "Conflict",
            Some(origin),
            &ErrorBody {
                error: NO_SESSION_MESSAGE,
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

/// Returns the CORS response header lines for an allowed `origin`.
fn cors_headers(origin: &str) -> String {
    format!(
        "Access-Control-Allow-Origin: {origin}\r\n\
         Vary: Origin\r\n\
         Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Max-Age: 600\r\n"
    )
}

/// Writes an HTTP/1.1 JSON response with strict security and optional CORS headers.
///
/// `allowed_origin` must only be `Some` once the request's `Host` and `Origin`
/// have been validated.
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
        header.push_str(&cors_headers(origin));
    }
    header.push_str("\r\n");

    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

/// Writes the `204 No Content` CORS preflight response for an allowed origin.
///
/// Adds `Access-Control-Allow-Private-Network: true` when the preflight carried
/// `Access-Control-Request-Private-Network: true` (Private Network Access).
fn write_preflight_response(
    stream: &mut TcpStream,
    allowed_origin: &str,
    private_network: bool,
) -> std::io::Result<()> {
    let mut header = String::from(
        "HTTP/1.1 204 No Content\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n",
    );
    header.push_str(&cors_headers(allowed_origin));
    if private_network {
        header.push_str("Access-Control-Allow-Private-Network: true\r\n");
    }
    header.push_str("\r\n");

    stream.write_all(header.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yubikey::piv::{
        build_generate_key_apdu, build_get_certificate_apdu, build_get_metadata_apdu,
        build_get_response_apdu, build_mgmt_auth_request_witness_apdu, build_sign_apdu,
        build_verify_pin_apdu,
    };

    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn origins() -> Vec<String> {
        vec!["http://localhost:8000".to_string()]
    }

    fn bytes(apdu: &Apdu) -> Vec<u8> {
        apdu.to_bytes().unwrap()
    }

    #[test]
    fn config_rejects_non_loopback_and_wildcard_origin() {
        let non_loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8765);
        assert!(BridgeConfig::new(non_loopback, origins(), None, "mock").is_err());

        let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8765);
        assert!(BridgeConfig::new(lan, origins(), None, "mock").is_err());

        let loopback = loopback(0);
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
        assert!(!valid.allow_key_generation());
        assert_eq!(valid.idle_timeout(), DEFAULT_IDLE_TIMEOUT);
        assert_eq!(valid.request_timeout(), DEFAULT_REQUEST_TIMEOUT);
        assert!(format!("{valid:?}").contains("<redacted>"));
        assert!(!format!("{valid:?}").contains(valid.token()));
    }

    #[test]
    fn config_accepts_only_ipv4_localhost() {
        for ip in [
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 1, 0, 1)),
        ] {
            let addr = SocketAddr::new(ip, 0);
            assert!(
                BridgeConfig::new(addr, origins(), None, "mock").is_err(),
                "{addr} must be rejected"
            );
        }
        assert!(BridgeConfig::new(loopback(8765), origins(), None, "mock").is_ok());
    }

    #[test]
    fn config_rejects_port_80() {
        for result in [
            BridgeConfig::new(loopback(80), origins(), None, "mock"),
            BridgeConfig::loopback(80),
        ] {
            match result {
                Err(Error::ConnectionFailed(msg)) => assert_eq!(msg, PORT_80_MESSAGE),
                other => panic!("port 80 must be rejected, got {other:?}"),
            }
        }
        for port in [0, 8080, 8765, 65535] {
            assert!(BridgeConfig::loopback(port).is_ok(), "port {port}");
        }
    }

    #[test]
    fn config_rejects_origins_browsers_never_send() {
        let mut config = BridgeConfig::loopback(0).unwrap();
        for origin in [
            "http://localhost:80",
            "http://localhost:080",
            "http://localhost:08000",
            "http://localhost:",
            "https://example.com:443",
            "http://[::1]:80",
        ] {
            assert!(
                config.add_allowed_origin(origin).is_err(),
                "{origin} must be rejected"
            );
            assert!(BridgeConfig::new(loopback(0), vec![origin.to_string()], None, "m").is_err());
        }
        for origin in [
            "http://localhost:8000",
            "http://example.com",
            "https://example.com",
            "https://example.com:80",
            "http://example.com:443",
            "http://[::1]",
            "http://[::1]:8000",
        ] {
            assert!(
                config.add_allowed_origin(origin).is_ok(),
                "{origin} must be accepted"
            );
        }
    }

    #[test]
    fn config_rejects_weak_explicit_tokens() {
        let weak = [
            String::new(),
            "short".to_string(),
            "a".repeat(MIN_TOKEN_LEN - 1),
            format!("{} ", "a".repeat(MIN_TOKEN_LEN)),
            format!("{}\tb", "a".repeat(MIN_TOKEN_LEN)),
            format!("{}\x7F", "a".repeat(MIN_TOKEN_LEN)),
            format!("{}é", "a".repeat(MIN_TOKEN_LEN)),
        ];
        for token in weak {
            assert!(
                BridgeConfig::new(loopback(0), origins(), Some(token.clone()), "mock").is_err(),
                "token {token:?} must be rejected"
            );
        }

        let ok =
            BridgeConfig::new(loopback(0), origins(), Some(TEST_TOKEN.to_string()), "m").unwrap();
        assert_eq!(ok.token(), TEST_TOKEN);
        assert!(
            BridgeConfig::new(
                loopback(0),
                origins(),
                Some("!#$%&'()*+,-./:;<=>?@[]^_`{|}~AZaz09".to_string()),
                "mock"
            )
            .is_ok()
        );
    }

    #[test]
    fn config_validates_timeouts() {
        let config = BridgeConfig::loopback(0).unwrap();
        assert!(config.clone().with_idle_timeout(Duration::ZERO).is_err());
        assert!(
            config
                .clone()
                .with_idle_timeout(MAX_IDLE_TIMEOUT + Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(
            config
                .clone()
                .with_idle_timeout(MAX_IDLE_TIMEOUT)
                .unwrap()
                .idle_timeout(),
            MAX_IDLE_TIMEOUT
        );
        assert!(config.clone().with_request_timeout(Duration::ZERO).is_err());
        assert!(
            config
                .clone()
                .with_request_timeout(MAX_REQUEST_TIMEOUT + Duration::from_secs(1))
                .is_err()
        );
        let short = config
            .with_request_timeout(Duration::from_millis(50))
            .unwrap()
            .with_allow_key_generation(true);
        assert_eq!(short.request_timeout(), Duration::from_millis(50));
        assert!(short.allow_key_generation());
    }

    #[test]
    fn apdu_allowlist_permits_read_and_sign_commands_for_all_slots() {
        for allow in [false, true] {
            assert!(validate_bridge_apdu(&bytes(&build_select_piv_apdu()), allow).is_ok());
            let verify = build_verify_pin_apdu("123456").unwrap();
            assert!(validate_bridge_apdu(&bytes(&verify), allow).is_ok());
            // VERIFY retry query (empty data)
            assert!(validate_bridge_apdu(&[0x00, 0x20, 0x00, 0x80], allow).is_ok());

            for slot in BRIDGE_SLOTS {
                for apdu in [
                    build_get_certificate_apdu(slot),
                    build_get_metadata_apdu(slot),
                    build_sign_apdu(slot, &[0xAB; 32]),
                ] {
                    let parsed = validate_bridge_apdu(&bytes(&apdu), allow).unwrap();
                    assert!(parsed == apdu, "{slot:?} {:02X}", apdu.ins());
                }
            }
        }
    }

    #[test]
    fn apdu_allowlist_gates_key_generation_behind_flag() {
        let mut gated = Vec::new();
        for slot in BRIDGE_SLOTS {
            gated.push(build_generate_key_apdu(slot));
            gated.push(build_delete_certificate_apdu(slot));
        }
        for alg in BRIDGE_MGMT_ALGORITHMS {
            gated.push(build_mgmt_auth_request_witness_apdu(alg));
        }

        for apdu in &gated {
            let err = validate_bridge_apdu(&bytes(apdu), false).unwrap_err();
            assert!(
                err.to_string().contains("--allow-generate"),
                "INS {:02X}: {err}",
                apdu.ins()
            );
            assert!(validate_bridge_apdu(&bytes(apdu), true).is_ok());
        }
    }

    #[test]
    fn apdu_allowlist_rejects_out_of_policy_variants() {
        let slot_9a = Slot::Authentication.object_id();
        let rejected_always: Vec<Vec<u8>> = vec![
            // SELECT FIDO2 AID
            bytes(&Apdu::new(
                0x00,
                0xA4,
                0x04,
                0x00,
                vec![0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01],
            )),
            // VERIFY with wrong P2 or wrong data length
            vec![0x00, 0x20, 0x00, 0x81],
            vec![0x00, 0x20, 0x00, 0x80, 0x04, 1, 2, 3, 4],
            // GET RESPONSE: the bridge completes 61 XX chains itself
            bytes(&build_get_response_apdu(0x20)),
            // GET DATA: CHUID, discovery object, wrong P1/P2, extra data
            bytes(&Apdu::new(
                0x00,
                0xCB,
                0x3F,
                0xFF,
                vec![0x5C, 0x03, 0x5F, 0xC1, 0x02],
            )),
            bytes(&Apdu::new(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C, 0x01, 0x7E])),
            bytes(&Apdu::new(
                0x00,
                0xCB,
                0x3F,
                0xFE,
                vec![0x5C, 0x03, slot_9a[0], slot_9a[1], slot_9a[2]],
            )),
            bytes(&Apdu::new(
                0x00,
                0xCB,
                0x3F,
                0xFF,
                vec![0x5C, 0x03, slot_9a[0], slot_9a[1], slot_9a[2], 0x00],
            )),
            // GET METADATA: management key (9B), PIN (80), wrong P1, data
            vec![0x00, 0xF7, 0x00, 0x9B, 0x00],
            vec![0x00, 0xF7, 0x00, 0x80, 0x00],
            vec![0x00, 0xF7, 0x01, 0x9A, 0x00],
            vec![0x00, 0xF7, 0x00, 0x9A, 0x01, 0x00],
            // Signing: RSA/P-384 algorithm, non-bridge slot, ECDH template, short digest
            bytes(&Apdu::new(0x00, 0x87, 0x14, 0x9A, vec![0x7C, 0x00])),
            {
                let mut sign = bytes(&build_sign_apdu(Slot::Authentication, &[1; 32]));
                sign[2] = 0x07;
                sign
            },
            {
                let mut sign = bytes(&build_sign_apdu(Slot::Authentication, &[1; 32]));
                sign[3] = 0x82;
                sign
            },
            bytes(&Apdu::new(
                0x00,
                0x87,
                0x11,
                0x9D,
                [&[0x7C, 0x24, 0x82, 0x00, 0x85, 0x20][..], &[7; 32]].concat(),
            )),
            bytes(&Apdu::new(
                0x00,
                0x87,
                0x11,
                0x9A,
                [&SIGN_TEMPLATE_PREFIX[..], &[7; 31]].concat(),
            )),
            // Non-zero CLA: proprietary, command chaining, logical channel
            vec![0x80, 0xCB, 0x3F, 0xFF],
            {
                let mut select = bytes(&build_select_piv_apdu());
                select[0] = 0x10;
                select
            },
            {
                let mut select = bytes(&build_select_piv_apdu());
                select[0] = 0x01;
                select
            },
            // Truncated / malformed
            vec![0x00, 0xA4, 0x04],
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x01],
        ];
        // CHANGE PIN, RESET RETRY, SET MGMT KEY, RESET, IMPORT, ATTEST
        let mut rejected = rejected_always;
        for &ins in &[0x24u8, 0x2C, 0xFF, 0xFB, 0xFE, 0xF9] {
            rejected.push(bytes(&Apdu::new(0x00, ins, 0x00, 0x9A, vec![0x01])));
        }

        // Key generation commands outside their exact shape (rejected even when enabled)
        let mut rejected_when_enabled = rejected.clone();
        rejected_when_enabled.extend([
            // GENERATE in 9B / retired slot, wrong P1, RSA-2048 or P-384 template
            bytes(&Apdu::new(
                0x00,
                0x47,
                0x00,
                0x9B,
                GENERATE_P256_TEMPLATE.to_vec(),
            )),
            bytes(&Apdu::new(
                0x00,
                0x47,
                0x00,
                0x82,
                GENERATE_P256_TEMPLATE.to_vec(),
            )),
            bytes(&Apdu::new(
                0x00,
                0x47,
                0x01,
                0x9A,
                GENERATE_P256_TEMPLATE.to_vec(),
            )),
            bytes(&Apdu::new(
                0x00,
                0x47,
                0x00,
                0x9A,
                vec![0xAC, 0x03, 0x80, 0x01, 0x07],
            )),
            bytes(&Apdu::new(
                0x00,
                0x47,
                0x00,
                0x9A,
                vec![0xAC, 0x03, 0x80, 0x01, 0x14],
            )),
            // Management GENERAL AUTHENTICATE with an unknown algorithm
            bytes(&Apdu::new(
                0x00,
                0x87,
                0x07,
                0x9B,
                vec![0x7C, 0x02, 0x80, 0x00],
            )),
            // PUT DATA writing a certificate, CHUID, or delete with Le
            bytes(&Apdu::new(
                0x00,
                0xDB,
                0x3F,
                0xFF,
                vec![
                    0x5C, 0x03, slot_9a[0], slot_9a[1], slot_9a[2], 0x53, 0x01, 0x00,
                ],
            )),
            bytes(&Apdu::new(
                0x00,
                0xDB,
                0x3F,
                0xFF,
                vec![0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, 0x00],
            )),
            {
                let mut delete = bytes(&build_delete_certificate_apdu(Slot::Authentication));
                delete.push(0x00);
                delete
            },
        ]);

        for raw in &rejected {
            assert!(
                validate_bridge_apdu(raw, false).is_err(),
                "{} must be rejected",
                hex::encode(raw)
            );
        }
        for raw in &rejected_when_enabled {
            assert!(
                validate_bridge_apdu(raw, true).is_err(),
                "{} must be rejected with key generation enabled",
                hex::encode(raw)
            );
        }
    }

    #[test]
    fn header_end_requires_crlf() {
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\n\r\n").ok(),
            Some(Some(14))
        );
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nA: b\r").ok(),
            Some(None)
        );
        assert!(find_header_end(b"GET / HTTP/1.1\n\n").is_err());
        assert!(find_header_end(b"GET / HTTP/1.1\r\nA: b\rc\r\n\r\n").is_err());
        // Bytes after the header block (the body) are not inspected.
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\n\r\n\n\rbody").ok(),
            Some(Some(14))
        );
    }

    #[test]
    fn header_parsing_rejects_malformed_fields() {
        let ok = parse_request_head(
            b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:1\r\nOrigin:\thttp://a \t",
        )
        .ok();
        let head = ok.unwrap();
        assert_eq!(head.host.as_deref(), Some("127.0.0.1:1"));
        assert_eq!(head.origin.as_deref(), Some("http://a"));

        for bad in [
            "GET /v1/health HTTP/1.1\r\nHost : 127.0.0.1:1",
            "GET /v1/health HTTP/1.1\r\n Host: 127.0.0.1:1",
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\tx",
            "GET /v1/health HTTP/1.1\r\n: value",
            "GET /v1/health HTTP/1.1\r\nHo(st: x",
            "GET /v1/health HTTP/1.1\r\nHost: a\x00b",
            "GET /v1/health HTTP/1.1\r\nNoColon",
            "GET  /v1/health HTTP/1.1",
            "GET /v1/health HTTP/2",
            "G\"T /v1/health HTTP/1.1",
        ] {
            assert!(
                parse_request_head(bad.as_bytes()).is_err(),
                "{bad:?} must be rejected"
            );
        }

        let head =
            parse_request_head(b"POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999")
                .ok()
                .unwrap();
        assert_eq!(head.framing_error.map(|e| e.status), Some(413));
        let head = parse_request_head(b"POST / HTTP/1.1\r\nContent-Length: +5")
            .ok()
            .unwrap();
        assert_eq!(head.framing_error.map(|e| e.status), Some(400));
        let head = parse_request_head(b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5")
            .ok()
            .unwrap();
        assert_eq!(head.framing_error.map(|e| e.status), Some(400));
        let head = parse_request_head(b"POST / HTTP/1.1\r\nContent-Length: 0012")
            .ok()
            .unwrap();
        assert!(head.framing_error.is_none());
        assert_eq!(head.content_length, 12);
    }

    #[test]
    fn token_grammar() {
        assert!(is_token("Content-Length"));
        assert!(is_token("x!#$%&'*+-.^_`|~9"));
        assert!(!is_token(""));
        assert!(!is_token("Host "));
        assert!(!is_token("a:b"));
        assert!(!is_token("a\"b"));
    }
}
