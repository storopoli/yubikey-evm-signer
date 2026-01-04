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

# Rust `clippy` lints
clippy:
  cargo clippy --workspace --examples --tests --benches --all-features --all-targets --locked

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
lints: toml-check-fmt toml-lint check-fmt clippy

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
  wasm-pack build crates/signer-wasm --target web --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Build WASM package in release mode
wasm-build-release:
  wasm-pack build crates/signer-wasm --target web --release --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Clean WASM build artifacts
wasm-clean:
  rm -rf packages/npm/dist

# Rebuild WASM package from scratch
wasm-rebuild: wasm-clean wasm-build

# Publish NPM package (requires npm login)
npm-publish: wasm-build-release
  cd packages/npm && npm publish --access public
