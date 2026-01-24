# WEBCAT Infra Chain

This repository showcases how a quick, permissioned blockchain for the WEBCAT infrastructure could
look. The goal is to replace both the Enrollment Server and the Build Server with a distributed
system, reducing censorship risks and avoiding single points of trust or failure. It may also be
cheaper to run, as distributing trust makes high availability, backups, and redundancy of individual
nodes less critical.

For sequence diagrams of the enrollment flow and oracle/validator communication, see [here](docs/seq_diag.md).

## Key entities and behaviors

The chain consists of a number of *nodes*, each of whom may or may not be a consensus validator.
Every node has a consensus key, but only some have non-zero voting power, designated by the
application. Those nodes with non-zero voting power are called *validators*. Every node, regardless
of whether it is a validator or not, is capable of accepting transactions for submission into a
block, and serves a REST API for querying various aspects of the chain state, in addition to the
default CometBFT API.

Validators are responsible for the liveness of the chain. Even if there are other non-voting nodes,
the chain will not make progress without 2/3 of the validators participating. The entities operating
a validator may or may not perform other services related to the chain, such as functioning as an
*admin* or an *oracle*.

The chain is configured by a voting quorum of *admins*, each of whom has a unique *admin key*.
This is an offline key which is only used to sign transactions approving changes to the chain's
configuration (i.e. voting parameters, registration quotas, validator set, oracle set, etc.).

The chain stores a *canonical state* which maps *domains* to *enrollment manifest hashes*. This
state is updated by the action of *oracles*, which post signed observations of domains to the chain
itself. The mechanism for triggering an oracle observation of a domain is external to the chain
itself and oracles are separate entities which may be hosted on different infrastructure than chain
nodes. This canonical state is internally stored by domain or subdomain in prefix-order, i.e.
`.com.example` instead of `example.com`, to facilitate efficient prefix lookups of all subdomains.
An API server for querying this state and other internal states of interest is hosted by the
`felidae` binary: go to `/snapshot` for the current full snapshot, or (for example) to
`/snapshot/example.com` for a filtered view showing the snapshot only for `example.com` and all its
subdomains. Other endpoints are described where declared in `crates/felidae/src/cli/start/query.rs`.

When a domain owner wishes to enroll or unenroll their domain in the WEBCAT chain, they must
interact with a *frontend* (not yet built) which will communicate with all known and reachable
oracles and instruct them to render an *observation* of the `/.well-known/webcat/enrollment.json`
file on their domain. Each oracle independently validates this file and submits a signed observation
to the chain. Once a quorum of oracles has observed the same file hash, the chain inserts that hash
into a *pending queue* on-chain which waits for a configured *delay* before applying that enrollment
update to the canonical state. Any new updates abort pending updates in the queue, so that domain
owners could be notified when their domain enters the pending queue and push a new update to revert
any malicious enrollment modification.

All on-chain cryptographic keys with the exception of validator consensus keys are NIST P-256 ECDSA
keypairs using SHA-256, to ensure compatibility with a wide variety of signing environments for
oracles and admins. Additionally, care has been taken to ensure that the oracle transaction building
code in particular can be run in a WASM environment, so that future iterations of oracles could be
run in serverless Javascript environments, e.g. Cloudflare Workers.

## Getting Started

You'll need to install the following tools:

 * [Rust](https://rustup.rs/)
 * [Go](https://go.dev/)
 * [`protoc`](https://protobuf.dev/installation/)
 * [`just`](https://just.systems/man/en/)

Or you can use the in-repo [nix flake](https://nixos.org/explore/) to bootstrap tooling.

Once you have the dependencies installed, you can use the justfile targets locally.
Build and run the chain by running both CometBFT and Felidae (the ABCI application),
each in its own terminal window. Start CometBFT via:

```bash
just cometbft
```

And the ABCI application via:

```bash
just felidae
```

Finally, to reset the chain state by blowing away both CometBFT and Felidae's state:

```bash
just reset
```

Note that the application's genesis file, which contains the initial configuration of the starting state of the chain, is located in `~/.cometbft/config/genesis.json`.

> **Tip:** For more verbose logging, run commands with `RUST_LOG=info` (or `RUST_LOG=debug` for even more detail).

## Setting Up Admin and Oracle

### 1. Generate Configuration Template

```bash
cargo run --bin felidae admin template > config.json
```

This generates a configuration template (see the `Config` proto) that you'll edit to add your own keys as an admin and oracle.

### 2. Generate Your Admin and Oracle Keypairs

```bash
cargo run --bin felidae admin init
```

This creates your admin keypair. To view your admin public key:

```bash
cargo run --bin felidae admin identity
```

Similarly for oracle:


```bash
cargo run --bin felidae oracle init
```

To view your oracle public key:

```bash
cargo run --bin felidae oracle identity
```
### 3. Configure `config.json`

Add your public keys (from step 2) to the `authorized` lists for both admins and oracles in `config.json`. For oracles, you'll need to provide both the `identity` (public key) and `endpoint` (domain or IP address) for each oracle.

For a single-validator testing setup, configure the following:

**Example chain configuration:**
```json
{
  "version": 1,
  "admins": {
    "voting": {
      "total": 1,
      "quorum": 1,
      "timeout": "1day",
      "delay": "0s"
    },
    "authorized": ["YOUR_ADMIN_KEY_HERE"]
  },
  "oracles": {
    "enabled": true,
    "voting": {
      "total": 1,
      "quorum": 1,
      "timeout": "5m",
      "delay": "30s"
    },
    "max_enrolled_subdomains": 5,
    "observation_timeout": "5m",
    "authorized": [
      {
        "identity": "YOUR_ORACLE_KEY_HERE",
        "endpoint": "127.0.0.1"
      }
    ]
  },
  "onion": {
    "enabled": false
  }
```

**Note:** Each oracle in the `authorized` array must have:
- `identity`: The hex-encoded public key of the oracle (required)
- `endpoint`: The endpoint (domain name or IP address) for the oracle (optional, defaults to `"127.0.0.1"` if omitted)

The endpoint is used by frontends to know where to submit enrollment requests to the oracle set.

**Important:** You must increment the `version` number in the config file unless you add the config to the genesis file.

**Note:** You can now skip steps 3-4 by adding the initial chain config in the genesis file by adding an `app_state` key with the `config`, e.g.:

```
{
  "genesis_time": "2025-09-13T23:47:47.144389Z",
  "chain_id": "my-webcat-testchain",
  "initial_height": 0,
  "app_state": {
    "config": {
      "version": 0,
      "admins": {
        "authorized": [...],
        "voting": { ... }
      },
      "oracles": {
        "enabled": true,
        "authorized": [...],
        "voting": { ... },
        "max_enrolled_subdomains": 5,
        "observation_timeout": "5m"
      },
      "onion": {
        "enabled": false
      }
    }
  }
}
```

### 4. Submit Configuration to Chain

```bash
cargo run --bin felidae admin config config.json --chain <CHAIN_ID>
```

Replace `<CHAIN_ID>` with the chain ID from `~/.cometbft/config/genesis.json`.

Once the chain accepts this transaction, you'll be configured as both admin and oracle. Verify the current configuration:

```bash
curl http://localhost/config
```

### 5. Post an Oracle Observation

You can now submit oracle observations. For example:

```bash
cargo run --bin felidae oracle observe --domain element.nym.re. --zone nym.re.
```

After the observation reaches quorum and the delay period expires, the observed hash will be visible in the snapshot:

```bash
curl http://localhost/snapshot
```

## Run Oracle as HTTP Server

Instead of using the CLI, you can run the oracle as an HTTP server that accepts observation requests via API:

```bash
cargo run --bin felidae oracle server \
  --homedir /persistent/keys \
  --node http://localhost:26657 \
  --port 8080
```

The server exposes two endpoints:
- `POST /observe` - Submit observation requests (JSON: `{"domain": "example.com.", "zone": "com."}`)
- `GET /health` - Health check endpoint

Example request:
```bash
curl -X POST http://localhost:8080/observe \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com.", "zone": "com."}'
```

## Example Scenario

### Nodes

- The network consists of 3 authoritative nodes, each operated by a different semi-trusted organization.
- Authoritative node identities (public keys) are hardcoded in the blockchain configuration.
- Adding or replacing nodes requires either:
  - manual reconfiguration by all existing nodes, or
  - a consensus-based update mechanism approved by the network.
- Non-authoritative (observer) nodes can sync and audit the blockchain but do not participate in consensus.
- Consensus requires 2 out of 3 nodes, allowing tolerance for one offline or malicious participant.
- Malicious updates require collusion by at least 2 nodes.

### Enrollment

- Enrollment requests can be submitted via a web interface hosted by authoritative nodes, or optionally by non-authoritative nodes which relay the transaction request.
- The first receiving authoritative node performs integrity checks:
  - Verifies policy list consistency.
  - Fetches and inspects the domain (e.g., HTTP headers).
- Upon successful validation, the node signs and broadcasts the transaction to its peers.
- If ≥2/3 of nodes validate and sign the transaction, it is committed to the blockchain.

### List Consensus

- Each node maintains a local state mapping domains to their policy hash.
- Every new block includes:
  - the hash of the current trust list state,
  - a timestamp, and
  - signatures from ≥2/3 of nodes.
- The list hash and signatures form a verifiable consensus snapshot.
- Any node (authoritative or not) can export the full list + consensus metadata.
- This bundle is distributed via CDN.

### Browser component (e.g. WEBCAT Extension)

- The browser extension embeds the public keys of authoritative nodes.
- Periodically fetches trust list updates from the CDN.
- Verifies:
  - At least 2/3 valid node signatures.
  - The timestamp is newer than the last known update.
- On success, the browser trusts and imports the new list.

### Censorship considerations

- Enrollment censorship requires ≥2 nodes to block a valid submission.
- List publication censorship requires ≥2 nodes to omit entries.

### CometBFT

[CometBFT](https://cometbft.com) is the de facto library for building custom blockchains with consensus. It handles networking, cryptographic operations, and consensus, leaving transaction and block validation mostly to the application developer. The blockchain can be permissioned: nodes are manually authorized (or voted in, if implemented), so scalability issues and takeover risks are minimal or non-existent.

### Feature Parity with WEBCAT Infra

The transparency logging requirement of WEBCAT Infra is dropped—here, the blockchain itself serves as a transparency log.
*Note: transparency logging is still required for manifest signatures and for Sigstore's OIDC certificates.*

Monitoring can be performed by any blockchain node that is not a validator. Non-validators can perform the same checks on the list state and verify domain consensus, enabling both:

- **Monitoring**: e.g., a service that alerts domain owners when changes are initiated.
- **Auditing**: independent verification of consensus and list state.

### Ideal Scenario

Organizations like the **Freedom of the Press Foundation**, **Tor Project**, and others—ideally across different jurisdictions (e.g., Tor relay associations)—run validator nodes on low-cost VPSes or on-premises hardware (from ~$5/month). There is native support for using (cloud) HSMs if needed.

Each organization may offer a web interface for submission to their local node, secured with CAPTCHA or basic rate-limiting. The receiving node performs validation and broadcasts the transaction to the rest of the network.

### List Building

At every finalized block, the current state of the preload list—agreed upon by a majority of validators—can be extracted and signed. Any node can then publish this list for the WEBCAT extension to consume.

The WEBCAT extension does **not** trust a specific node; instead, it verifies that:

- There was valid consensus.
- The current block height/timestamp is greater than the previous one.

### Hacking / Censorship Scenario

To fake or force an enrollment operation, an attacker would need control of at least 3 out of 5 validator nodes (this threshold is configurable). The preload list cannot be forged or censored, as clients require a valid network consensus. Thus, only a majority of nodes (or the organizations behind them) could alter the list content.

### Pros

- No single point of failure; harder to censor
- Lower operational cost (no HA or per-org redundancy needed)
- Shared trust/liability across jurisdictions

### Cons

- Slightly more complex setup
- Frontends must implement rate-limiting, or use alternatives like proof-of-work
- Involves more parties to coordinate

### Development Roadmap (Beta Release)

- ~1 month of full-time development for basic chain + frontend
- WEBCAT extension changes are minimal (still fetching updates from a CDN, but verifying consensus signatures instead of Sigsum proofs)

### Future Work

Extending the chain with non-breaking changes mostly involves updating the software. For example, implementing Tor-specific validation (if agreed upon) or testing alternate policies should be straightforward. Note that what is in the list (Sigstore, versus just public keys) does not influence the technical setup of this. There's just the need to change the validatot function according to the schema we agree upon.
