# Build the complete project: CometBFT and felidae
build:
    git submodule update --init --recursive
    just build-cometbft
    just build-felidae

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

# Build WASM package for felidae-oracle
build-wasm:
    cd crates/felidae-oracle && wasm-pack build --target web --out-dir pkg

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
    just build-felidae
    ./cometbft/build/cometbft unsafe-reset-all
    ./target/release/felidae reset

# Run the frontend
frontend:
  cd frontend && npm run dev

# Run nix-specific linters
nix-lint:
  nix flake check --all-systems
