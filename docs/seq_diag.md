# Sequence Diagrams

## Enrollment Flow

This document illustrates the flow of enrolling a domain in WEBCAT. Also see the
specification [here](https://github.com/freedomofpress/webcat-spec/blob/main/enrollment.md).

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Site as example.com
    participant Oracle as Oracle
    participant Chain as Chain (Validators)
    participant CDN as CDN
    participant User as User

    Dev->>Site: Deploy /.well-known/webcat/enrollment.json
    Dev->>Oracle: Request observation for example.com

    Note over Site,Chain: Oracle Observation Phase
    Oracle->>Site: GET https://example.com/.well-known/webcat/enrollment.json
    Site-->>Oracle: Enrollment JSON (or 404 if unenrolled)
    Oracle->>Oracle: Compute canonical hash of enrollment
    Oracle->>Chain: Get latest block (height, app_hash)
    Chain-->>Oracle: Block info (height N, app_hash)
    Oracle->>Oracle: Create signed observation transaction
    Oracle->>Chain: Broadcast observation tx (domain, hash, blockstamp)

    Note over Chain: Consensus & Processing Phase
    Chain->>Chain: Validators receive observation tx
    Chain->>Chain: Validate oracle signature & blockstamp
    Chain->>Chain: Add to oracle voting queue
    Chain->>Chain: Wait for quorum of oracles<br/>(same hash observed)
    Chain->>Chain: Move to pending queue<br/>(with configured cooldown delay)
    Chain->>Chain: After delay, update canonical state

    Note over Chain,CDN: Publishing Phase (every ~day)
    Chain->>CDN: Publish canonical state (Merkle tree leaves + Merkle proof to AppHash)
    Chain->>CDN: Publish light block (signed header including AppHash)

    Note over User,CDN: User Verification Phase (when preload list updated)
    User->>CDN: Fetch canonical state
    CDN-->>User: Canonical Merkle tree leaves + Merkle proof
    User->>CDN: Fetch light block
    CDN-->>User: Light block (signed header + validator set)
    User->>User: Verify light block signatures<br/>(>2/3 voting power)
    User->>User: Reconstruct JMT from leaves
    User->>User: Verify canonical root hash
    User->>User: Verify Merkle proof:<br/>canonical_root → app_hash
    User->>User: Verify app_hash in light block header
    Note over User: ✅  User has verified latest canonical state
```

## Oracle and Validator Flows

This diagram shows the crypto operations specifically between oracles and validators:

```mermaid
sequenceDiagram
    participant Oracle as Oracle<br/>(ECDSA P-256 Key)
    participant Mempool as Chain Mempool
    participant Proposer as Proposer Validator<br/>(Ed25519 Consensus Key)
    participant OtherValidators as Other Validators<br/>(Ed25519 Consensus Keys)
    participant Block as Block N+1

    Note over Oracle: Key Ownership: Oracle ECDSA P-256 Keypair<br/>- Private key: signs observation transactions<br/>- Public key: registered in chain config

    Note over Oracle: Transaction Creation & Signing
    Oracle->>Oracle: Create observation transaction<br/>(domain, hash, blockstamp)
    Oracle->>Oracle: Compute SHA-256 digest<br/>of transaction
    Oracle->>Oracle: Sign digest with<br/>ECDSA P-256 private key
    Oracle->>Oracle: Attach signature + public key<br/>to transaction

    Note over Oracle,Mempool: Transaction Flow
    Oracle->>Mempool: Broadcast signed observation tx
    Mempool->>Mempool: Verify oracle signature:<br/>ECDSA.verify(public_key, digest, signature)
    Mempool->>Mempool: Check oracle is authorized<br/>(public key in config)
    Mempool->>Mempool: Validate blockstamp<br/>(not future, not too old)

    Note over Mempool,Block: Block Proposal & Consensus
    Proposer->>Proposer: Propose block with<br/>observation transactions
    Proposer->>Proposer: Create block header<br/>(height, app_hash, etc.)
    Proposer->>Proposer: Sign block with<br/>Ed25519 consensus key
    Proposer->>OtherValidators: Broadcast block proposal

    Note over Proposer,OtherValidators: Signature Verification & Voting
    OtherValidators->>OtherValidators: Verify proposer signature:<br/>Ed25519.verify(consensus_key, block, sig)
    OtherValidators->>OtherValidators: Verify all oracle signatures<br/>in transactions
    OtherValidators->>OtherValidators: Precommit: Sign votes with<br/>Ed25519 consensus keys

    Note over Proposer,Block: Block Commitment
    Proposer->>Block: Collect >2/3 precommit signatures
    OtherValidators->>Block: Include precommit signatures
    Block->>Block: Finalize block with commit<br/>(all validator signatures)

    Note over Block: Key Ownership: Validator Ed25519 Keys<br/>- Each validator has Ed25519 consensus keypair<br/>- Public keys in validator set<br/>- >2/3 signatures required for block validity
```
