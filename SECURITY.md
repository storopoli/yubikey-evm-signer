# Security policy

## Reporting a vulnerability

Report suspected security vulnerabilities privately by emailing [jose@storopoli.com](mailto:jose@storopoli.com). Do not open a public GitHub issue, pull request, or discussion for an unpatched vulnerability.

Include enough detail to reproduce and assess the issue:

- Affected crate, module, or component (such as `yubikey-evm-signer-core`, `yubikey-evm-signer-wasm`, `yubikey-cli`, or `demo/`)
- Crate version or Git commit hash
- Steps to reproduce or a minimal proof of concept
- Practical impact and any suggested fix

This is a maintainer-run open-source project without a bug bounty program. Reports are handled on a best-effort basis, and the maintainer will coordinate disclosure and a fix with you once a report is confirmed.

## Supported versions

| Version | Supported |
|---------|-----------|
| `0.1.x` / `main` | Yes |
| `< 0.1.0` | No |

This library is pre-1.0 and has not undergone an independent security audit. Review the code before relying on it to protect anything of value.

## Scope

### In scope

- P-256 ECDSA signature verification (`verify_signature`, `p256_verify`), recovery ID calculation (`try_recover_public_key`, `calculate_recovery_parameter`), low-S normalization (`normalize_s`), and canonical ASN.1 DER parsing (`parse_der_signature`)
- EIP-155 legacy and EIP-1559 transaction RLP encoding and signing hashes, strict transaction and EIP-712 JSON parsing, EIP-712 typed structured data hashing, and EIP-191 personal message hashing
- PIV APDU encoding and response chaining, PC/SC transaction scoping of multi-command operations, card-reset detection, slot public key lookup (Yubico `GET METADATA` with certificate fallback and stale-certificate detection), NIST SP 800-73-4 mutual management key authentication, PIN verification and secret zeroization, and X.509 or gzip-compressed certificate parsing
- Local PC/SC loopback bridge boundaries in `crates/signer-core/src/bridge.rs`: `127.0.0.1`-only binding, exact `Host` header validation against DNS rebinding, exact `Origin` allowlist checks, constant-time Bearer token verification, HTTP framing, size and deadline limits, the PIV-only APDU allowlist with opt-in key generation (`--allow-generate`), one PC/SC transaction per forwarded command, and session teardown on idle timeout, card reset, and shutdown
- WASM bindings (`crates/signer-wasm/`), WebUSB CCID framing and frame assembly, and input validation in `demo/`

### Out of scope

- Loss of funds sent to an address derived from a YubiKey P-256 key on a chain that validates transactions with secp256k1 (see [Known limitations](#known-limitations-and-user-responsibilities)); this is a property of those chains, not a vulnerability in this project
- YubiKey hardware or firmware vulnerabilities, which should be reported directly to Yubico
- Bugs in host operating system smart card daemons (`pcscd`, macOS CryptoTokenKit, or the Windows Smart Card service)
- Chromium's WebUSB device blocklist (`usb_blocklist.cc`) and protected USB Smart Card interface class (`0x0B`) enforcement, which are intentional browser security controls

## Known limitations and user responsibilities

The YubiKey key is a P-256 (secp256r1) key, and the "address" this project derives from it (`keccak256(X‖Y)[12..]` of the public key) is only an identifier of that key. It is not a secp256k1 externally owned account. Ethereum mainnet and standard EVM chains validate transaction signatures with secp256k1 `ecrecover`; EIP-7951 only adds the `P256VERIFY` precompile that contracts can call. Therefore:

- A legacy or EIP-1559 transaction signed with this project is not accepted by a standard node as a transaction from the derived address.
- Nothing can be spent from the derived address on such chains. Do not send ETH or tokens to it; they cannot be recovered.
- Verifying a signature requires the public key `(qx, qy)`, which neither the signature nor the transaction carries.

The signatures are useful only to verifiers that call `P256VERIFY` with a known public key, such as smart accounts with P-256 validation, ERC-1271 `isValidSignature` implementations, or chains that validate transactions with P-256 natively. You are responsible for registering the correct public key (`getPublicKey()` in JavaScript, or the uncompressed key printed by `yubikey-cli address`) with your verifier and for confirming that the verifier accepts these signatures before relying on it.

## Operational guidance

Change factory PIV credentials with `ykman piv access` before storing keys you rely on. Factory YubiKeys ship with PIN `123456`, PUK `12345678`, and management key `010203040506070801020304050607080102030405060708` (AES-192 on firmware 5.7 and newer, 3DES on earlier firmware).

Enable the `always` touch policy on signing slots when generating keys with `ykman` so every signature requires physical presence on the YubiKey. Neither `YubiKeyDevice.generateKey()` nor `yubikey-cli generate` configures a touch policy. If you choose the `cached` touch policy, additional signatures are permitted for 15 seconds after a touch without another tap. Independently of touch, slot `9c` requires PIN verification on every signature by default, though host software that already holds the PIN can still sign unless a touch policy is also set.

Treat `YubiKeyDevice.generateKey()` and `yubikey-cli generate` as destructive operations. Generating a key in a PIV slot permanently overwrites the previous private key in that slot (and both tools then delete the slot's certificate), and YubiKey hardware provides no way to export or recover an overwritten private key. Anything that relied on the old key, such as a smart account that registered its public key, can no longer be signed for with it.

Keep the local PC/SC bridge bound to `127.0.0.1` and allow only exact browser origins you trust. Do not expose the bridge port over a LAN, VPN, or reverse proxy. Start it with `--allow-generate` only while you intend to generate a key from a browser page: without that flag, the bridge refuses management key authentication, key generation, and certificate deletion.

The bridge's Bearer token is valid for the whole life of the bridge process, across all sessions. Stop the bridge (Ctrl+C or SIGTERM) when you are done: it closes the YubiKey session, resets the card so the verified PIN and management key authentication are cleared, and discards the token. An idle session is also closed and the card reset after the idle timeout (`--idle-timeout`, 120 seconds by default), but the token stays valid until the process exits.

Each forwarded command runs as one PC/SC transaction, but a session spans many requests. PIV PIN and management key state lives on the card, so while a bridge session holds a verified PIN, other local PC/SC clients are not prevented from using that state between the bridge's requests until the session ends. Avoid running untrusted local software that talks to the smart card while a bridge session is open.

Never hardcode PIV PINs, management keys, or bridge Bearer tokens in source files, shell scripts, or browser storage. Prompt for them at runtime and clear sensitive buffers after use.
