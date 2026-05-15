build:
    cargo build --release

build-dev:
    cargo build

build-ci:
    cargo build --release --locked --bin rocoon

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

check-deny:
    cargo deny check

test:
    cargo test --workspace --locked

check: fmt-check clippy test
