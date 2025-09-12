# Build the complete project: CometBFT and felidae
build:
    #!/usr/bin/env bash
    set -euo pipefail
    git submodule update --init --recursive
    cd cometbft && make build
    cargo build --release

# Clean build artifacts
clean:
    cargo clean
    cd cometbft && make clean || true

# Update submodules
update-submodules:
    git submodule update --remote --merge

# Build only CometBFT
build-cometbft:
    cd cometbft && make build

# Build only felidae in release mode
build-felidae:
    cargo build --release

# Run tests
test:
    cargo test

# Run CometBFT (builds if necessary)
cometbft:
    just build-cometbft
    ./cometbft/build/cometbft init
    ./cometbft/build/cometbft start

# Run felidae (builds if necessary)
felidae:
    just build-felidae
    ./target/release/felidae start

# Reset the node
reset:
    just build-cometbft
    ./cometbft/build/cometbft unsafe-reset-all