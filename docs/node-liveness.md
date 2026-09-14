# Node liveness

A felidae node runs two independent servers: the ABCI service CometBFT drives,
and the read-only query API on `--query-bind`. They share committed storage and
nothing else, which is deliberate — a slow query must never stall consensus.

The cost of that decoupling is that the two can die separately. `tower_abci`
spawns a task per accepted ABCI connection and never looks at it again
(`tower-abci-0.19.1`, `src/v038/server.rs:173`), so a panic while serving a
request kills one connection, not the listener. Before this was addressed, such
a node kept answering `/config` and `/chain-info` with frozen state
indefinitely, and nothing — not a supervisor, not a health check — could tell.

Two mechanisms close that gap.

## `/healthz`

Reports whether this node is still *advancing*, which no other endpoint can
answer: they all read the latest committed snapshot and will happily serve it
forever.

    $ curl -s localhost:8080/healthz | jq
    {
      "healthy": true,
      "block_height": 10421,
      "block_time": "2026-09-14T00:31:12.994Z",
      "block_age_secs": 2,
      "tolerance_secs": 50,
      "observed_interval_secs": 5
    }

The status code mirrors `healthy`: **200** when advancing, **503** when stale or
when the node has not yet finished `InitChain`. A checker that reads nothing but
the status code still gets the right answer.

`felidae query health` is the same question from a shell, and exits non-zero
when unhealthy:

    $ felidae query --query-url http://localhost:8080 health

### How tolerance is chosen

Staleness is judged against the chain's own cadence, sampled from the block
times already in state, so neither CometBFT's `timeout_commit` nor a hand-tuned
threshold is needed:

    tolerance = max(30s, 10 × mean interval over the last 20 blocks)

The floor keeps a fast chain from flapping on one slow round, and covers a chain
too young to have measured an interval. `--health-max-block-age 45s` overrides
the whole calculation when an operator knows better.

A node that is behind and catching up reports unhealthy. That is the right
answer for routing, which is what this endpoint is for — it is not a judgement
about whether the node is doing something useful.

## Fail-fast on ABCI panic

The ABCI service is wrapped so that a panic anywhere in request handling aborts
the process instead of silently killing one connection. The crash becomes a
restart, which is the correct posture for a consensus node.

This is deliberately narrower than `panic = "abort"`: query handlers are
read-only and already turn their errors into 500s, so a panic serving an
outside request should not cost the node its consensus connection.

Restart is the supervisor's job. The test topology sets it
(`crates/felidae-deployer/src/network.rs` emits `restart: on_failure` with
`max_restarts: 3`); in production it belongs to whatever runs the container,
and `Dockerfile` deliberately sets no policy. Note that `on_failure` keys on a
non-zero exit — the abort satisfies that, a clean exit would not.
