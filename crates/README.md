# Developing on `felidae`

The `felidae` project is split into a variety of crates. Here's a map:

- `felidae`: ABCI application which works in concert with CometBFT to operate a chain node
- `felidae-state`: all the logic defining the actual state machine which the chain replicates; this
  is where *all* the stateful logic lives, and it is split into submodules for readability; it also
  implements the actual `tower-abci` service trait, for use in the `felidae` binary
- `felidae-types`: definitions of nice-to-work-with Rust types which can be converted to/from
  canonical protobuf representations for storage or transmission over the wire
- `felidae-proto`: protobuf definitions for all messages transmitted or stored in the state; in
  particular, transactions and all types stored within them, as well as the code for *transaction
  signing* lives here, because signing and signature verification happens at the
  protobuf/domain-type conversion boundary
- `felidae-oracle` and `felidae-admin`: small convenience crates for constructing the two kinds of
  transactions needed by the chain, the former of which may be compiled to WASM
- `felidae-traverse` and `felidae-traverse-derive`: helper crates which are used in automatically
  deriving the transaction signing procedure so that it is malleability-attack-proof by
  construction; these define a trait `Traverse` and `derive(Traverse)` macro which is applied at
  build-time to all generated protobuf types, so that we can visit the structure of transactions and
  manipulate all their embedded signatures and public keys
