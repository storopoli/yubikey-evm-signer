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
| `0.0.1` / `main` | Yes |

This library is pre-1.0 and has not undergone an independent security audit. Review the code before using it with mainnet funds.

## Scope

### In scope

- P-256 ECDSA signature verification (`verify_signature`, `p256_verify`), recovery ID calculation (`try_recover_public_key`, `calculate_recovery_parameter`), low-S normalization (`normalize_s`), and canonical ASN.1 DER parsing (`parse_der_signature`)
- EIP-155 legacy and EIP-1559 transaction RLP encoding and signing hashes, EIP-712 typed structured data hashing, and EIP-191 personal message hashing
- PIV APDU encoding and response chaining, NIST SP 800-73-4 mutual management key authentication, PIN verification and secret zeroization, and X.509 or gzip-compressed certificate parsing
- Local PC/SC loopback bridge boundaries in `crates/signer-core/src/bridge.rs`: loopback-only binding, `Host` header validation against DNS rebinding, exact `Origin` allowlist checks, constant-time Bearer token verification, HTTP framing and size limits, and the PIV-only APDU allowlist
- WASM bindings (`crates/signer-wasm/`), WebUSB CCID framing and frame assembly, and input validation in `demo/`

### Out of scope

- YubiKey hardware or firmware vulnerabilities, which should be reported directly to Yubico
- Bugs in host operating system smart card daemons (`pcscd`, macOS CryptoTokenKit, or the Windows Smart Card service)
- Chromium's WebUSB device blocklist (`usb_blocklist.cc`) and protected USB Smart Card interface class (`0x0B`) enforcement, which are intentional browser security controls

## Operational guidance

Change factory PIV credentials with `ykman piv access` before storing keys that control real funds. Factory YubiKeys ship with PIN `123456`, PUK `12345678`, and management key `010203040506070801020304050607080102030405060708` (AES-192 on firmware 5.7 and newer, 3DES on earlier firmware).

Enable the `always` touch policy on signing slots when generating keys with `ykman` so every signature requires physical presence on the YubiKey. Neither `YubiKeyDevice.generateKey()` nor `yubikey-cli generate` configures a touch policy. If you choose the `cached` touch policy, additional signatures are permitted for 15 seconds after a touch without another tap. Independently of touch, slot `9c` requires PIN verification on every signature by default, though host software that already holds the PIN can still sign unless a touch policy is also set.

Treat `YubiKeyDevice.generateKey()` and `yubikey-cli generate` as destructive operations. Generating a key in a PIV slot permanently overwrites the previous private key in that slot, and YubiKey hardware provides no way to export or recover an overwritten private key.

Keep the local PC/SC bridge bound to `127.0.0.1` and allow only exact browser origins you trust. Do not expose the bridge port over a LAN, VPN, or reverse proxy, and stop the bridge process when your signing session ends so its per-session Bearer token is discarded.

Never hardcode PIV PINs, management keys, or bridge Bearer tokens in source files, shell scripts, or browser storage. Prompt for them at runtime and clear sensitive buffers after use.
