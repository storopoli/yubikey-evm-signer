# List all the available commands
default:
  just --list

# Fix Rust formatting
fmt:
  cargo fmt --all

# Fix TOML formatting with `taplo`
toml-fmt:
  taplo format

# Check Rust formatting
check-fmt:
  cargo fmt --all --check

# Rust `clippy` lints (excludes WASM crate which needs wasm32 target)
clippy:
  RUSTFLAGS="-D warnings" cargo clippy --workspace --exclude yubikey-evm-signer-wasm --examples --tests --benches --all-features --all-targets --locked

# Rust `clippy` lints for WASM crate (requires wasm32 target)
clippy-wasm:
  RUSTFLAGS="-D warnings --cfg=web_sys_unstable_apis" cargo clippy -p yubikey-evm-signer-wasm --target wasm32-unknown-unknown --all-features --locked

# TOML lint with `taplo`
toml-lint:
  taplo lint

# Check TOML formatting with `taplo`
toml-check-fmt:
  taplo format --check

# Rust unit tests with `cargo-nextest`
unit-test:
  cargo --locked nextest run --all-features --workspace

# Rust documentation tests
doctest:
  cargo test --doc --all-features --workspace

# Run all lints and formatting checks
lints: toml-check-fmt toml-lint check-fmt clippy clippy-wasm

# Rust all tests
test: unit-test doctest

# Publish crate to crates.io
publish:
  cargo publish --token $CARGO_REGISTRY_TOKEN

# Check supply chain security analsis with `cargo-audit`
audit:
  cargo audit

# Check GitHub Actions security analysis with `zizmor`
check-github-actions-security:
  zizmor .

# Build WASM package
wasm-build:
  wasm-pack build crates/signer-wasm --target web --no-opt --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Build WASM package in release mode
wasm-build-release:
  wasm-pack build crates/signer-wasm --target web --release --no-opt --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Clean WASM build artifacts
wasm-clean:
  rm -rf packages/npm/dist

# Rebuild WASM package from scratch
wasm-rebuild: wasm-clean wasm-build

# Publish NPM package (requires npm login)
npm-publish: wasm-build-release
  cd packages/npm && npm publish --access public

# Build WASM for demo site
demo-build:
  wasm-pack build crates/signer-wasm --target web --release --no-opt --out-dir ../../demo/wasm --out-name yubikey_evm_signer_wasm

# Clean demo WASM artifacts
demo-clean:
  rm -rf demo/wasm

# Serve demo site locally (requires Python 3)
demo-serve:
  @echo "Starting local server at http://localhost:8000"
  @echo "Note: WebUSB requires HTTPS in production, but localhost is exempt"
  python3 -m http.server 8000 --directory demo

# Build and serve demo site locally
demo: demo-build demo-serve

# =============================================================================
# Native CLI Demo (requires YubiKey and PC/SC - works on macOS/Linux/Windows)
# =============================================================================

# Build CLI example with PCSC support
cli-build:
  cargo build --example yubikey-cli -p yubikey-evm-signer-core --features pcsc

# List available YubiKey devices
cli-list:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- list

# Show YubiKey connection info
cli-info:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- info

# Get Ethereum address from slot 9a
cli-address:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- address

# Generate a new P-256 key in slot 9a (requires PIN, overwrites existing key!)
cli-generate:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- generate

# Sign a sample EIP-1559 transaction (requires PIN)
cli-sign-tx:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- sign-tx

# Sign a custom 32-byte hash (requires PIN)
cli-sign hash:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- sign {{hash}}

# Show CLI help
cli-help:
  cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- --help
