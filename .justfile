# List all the available commands
default:
  just --list

# =============================================================================
# Formatting
# =============================================================================

# Fix Rust formatting
[group('format')]
fmt:
  cargo fmt --all

# Fix TOML formatting with `taplo`
[group('format')]
toml-fmt:
  taplo format

# Check Rust formatting
[group('format')]
check-fmt:
  cargo fmt --all --check

# Check TOML formatting with `taplo`
[group('format')]
toml-check-fmt:
  taplo format --check

# =============================================================================
# Linting
# =============================================================================

# Rust `clippy` lints (excludes WASM crate which needs wasm32 target)
[group('lint')]
clippy:
  RUSTFLAGS="-D warnings" cargo clippy --workspace --exclude yubikey-evm-signer-wasm --examples --tests --benches --all-features --all-targets --locked

# Rust `clippy` lints for WASM crate (requires wasm32 target)
[group('lint')]
clippy-wasm:
  RUSTFLAGS="-D warnings --cfg=web_sys_unstable_apis" cargo clippy -p yubikey-evm-signer-wasm --target wasm32-unknown-unknown --all-features --locked

# TOML lint with `taplo`
[group('lint')]
toml-lint:
  taplo lint

# Run all lints and formatting checks
[group('lint')]
lints: toml-check-fmt toml-lint check-fmt clippy clippy-wasm

# =============================================================================
# Testing
# =============================================================================

# Rust unit tests with `cargo-nextest`
[group('test')]
unit-test:
  cargo --locked nextest run --all-features --workspace

# Rust documentation tests
[group('test')]
doctest:
  cargo test --doc --all-features --workspace

# Rust all tests
[group('test')]
test: unit-test doctest

# =============================================================================
# Publishing
# =============================================================================

# Publish crate to crates.io
[group('publish')]
publish:
  cargo publish --token $CARGO_REGISTRY_TOKEN

# Publish NPM package (requires npm login)
[group('publish')]
npm-publish: wasm-build-release
  cd packages/npm && npm publish --access public

# =============================================================================
# Security
# =============================================================================

# Check supply chain security analsis with `cargo-audit`
[group('security')]
audit:
  cargo audit

# Check GitHub Actions security analysis with `zizmor`
[group('security')]
check-github-actions-security:
  zizmor .

# =============================================================================
# WASM Build
# =============================================================================

# Build WASM package
[group('wasm')]
wasm-build:
  wasm-pack build crates/signer-wasm --target web --no-opt --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Build WASM package in release mode
[group('wasm')]
wasm-build-release:
  wasm-pack build crates/signer-wasm --target web --release --no-opt --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Clean WASM build artifacts
[group('wasm')]
wasm-clean:
  rm -rf packages/npm/dist

# Rebuild WASM package from scratch
[group('wasm')]
wasm-rebuild: wasm-clean wasm-build

# =============================================================================
# Demo
# =============================================================================

# Build WASM for demo site
[group('demo')]
demo-build:
  wasm-pack build crates/signer-wasm --target web --release --no-opt --out-dir ../../demo/wasm --out-name yubikey_evm_signer_wasm

# Clean demo WASM artifacts
[group('demo')]
demo-clean:
  rm -rf demo/wasm

# Serve demo site locally (requires Python 3)
[group('demo')]
demo-serve:
  @echo "Starting local server at http://localhost:8000"
  @echo "Note: WebUSB requires HTTPS in production, but localhost is exempt"
  python3 -m http.server 8000 --directory demo

# Build and serve demo site locally
[group('demo')]
demo: demo-build demo-serve

# =============================================================================
# Native CLI (requires YubiKey and PC/SC - works on macOS/Linux/Windows)
# =============================================================================

# Build CLI example with PCSC support
[group('cli')]
cli-build:
  cargo build --example yubikey-cli -p yubikey-evm-signer-core --features pcsc

# List available YubiKey devices
[group('cli')]
cli-list:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- list

# Show YubiKey connection info
[group('cli')]
cli-info:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- info

# Get Ethereum address from slot 9a
[group('cli')]
cli-address:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- address

# Generate a new P-256 key in slot 9a (requires PIN, overwrites existing key!)
[group('cli')]
cli-generate:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- generate

# Sign a sample EIP-1559 transaction (requires PIN)
[group('cli')]
cli-sign-tx:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- sign-tx

# Sign a custom 32-byte hash (requires PIN)
[group('cli')]
cli-sign hash:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- sign {{hash}}

# Show CLI help
[group('cli')]
cli-help:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- --help
