# Test Data for Light Clients

This contains two bits of data:
- what would be returned by the query interface `/canonical/leaves` in `leaves.json`
- the `LightBlock` that contains the corresponding `AppHash` in `block.json`

# How to regenerate

You will need:
- CometBFT and the ABCI application running, with at least one domain in the canonical data

To regenerate `leaves.json`, you just save whatever is published by `http://127.0.0.1/canonical/leaves`.

To regenerate `block.json`, you just run:

```
cargo run --bin felidae-publish print --height <BLOCK_HEIGHT>
```

(The `<BLOCK_HEIGHT>` will be what you see in the `/canonical/leaves` endpoint + 1
because the AppHash reflecting that snapshot's changes is in the header of block N + 1)

# Test data for frontend

In `oracles.json` we get the public keys and endpoints of the oracle set. You can
regenerate this by hitting `/oracles`.
