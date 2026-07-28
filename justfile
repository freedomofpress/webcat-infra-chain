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
    cargo nextest run

# Run integration tests (block_time in seconds; default 1s for fast CI)
integration block_time="2":
    FELIDAE_BLOCK_TIME_SECS={{block_time}} cargo nextest run -p felidae-deployer --features integration --no-fail-fast --test-threads 1

# Run a single integration test by name (e.g. just integration-one test_oracle_quorum_reached)
integration-one test block_time="2":
    FELIDAE_BLOCK_TIME_SECS={{block_time}} cargo nextest run -p felidae-deployer --features integration --test-threads 1 -E 'test({{test}})'

# Read-only pre-flight: validate a live deployment's committed configs under strict domain parsing
live-config-check url:
    cargo run -q --bin felidae -- debug parse-config --url {{url}}

# Build WASM package for felidae-oracle
build-wasm:
    cd crates/felidae-oracle && wasm-pack build --target web --out-dir pkg

# Author a single-node genesis: dev admin/oracle keys wired into app_state.config.
# InitChain refuses a genesis without a valid config — there is no default.
genesis-single:
    cargo run --bin felidae-deployer -- inject-config --genesis ~/.cometbft/config/genesis.json

# Run CometBFT (builds if necessary; authors genesis app_state on first init)
cometbft:
    just build-cometbft
    ./cometbft/build/cometbft init
    just genesis-single
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
frontend chain_url="http://localhost:8080":
  cd frontend && CHAIN_API_URL="{{chain_url}}" npm run dev

# Run nix-specific linters
nix-lint:
  nix flake check --all-systems

alias container := container-felidae

# Build OCI container image for felidae via nix
container-felidae:
  nix build .#container-felidae

# Build OCI container image for whiskers via nix
container-whiskers:
  nix build .#container-whiskers

testnet_dir := "/tmp/test-network"
# spin up a local devnet with multiple validators
dev:
  # prebuild bins
  cargo build -q --bins
  cometbft unsafe-reset-all
  cargo run --bin felidae -- reset
  rm -rf "{{testnet_dir}}"
  cargo run --bin felidae-deployer -- create-network --directory "{{testnet_dir}}" --num-validators 1
  cargo run --bin felidae-deployer -- run-network --directory "{{testnet_dir}}" --dev --process-compose

# Run all project linters
lint:
  cargo check --all-features --all-targets
  cargo fmt --all --check
  just nix-lint
