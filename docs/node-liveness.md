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
      "tolerance_secs": 30
    }

The status code mirrors `healthy`: **200** when advancing, **503** when stale or
when the node has not yet finished `InitChain`. A checker that reads nothing but
the status code still gets the right answer.

`felidae query health` is the same question from a shell, and exits non-zero
when unhealthy:

    $ felidae query --query-url http://localhost:8080 health

A node is unhealthy once its newest committed block is older than 30s.
`--health-max-block-age 2m` overrides that for a slower chain.

A node that is behind and catching up reports unhealthy. That is the right
answer for routing, which is what this endpoint is for — it is not a judgement
about whether the node is doing something useful.

### A 503 is a routing signal, not a restart signal

This matters more than it sounds, because the endpoint's name invites the
opposite reading.

When a chain halts, **every** node reports unhealthy, including the ones that
are working perfectly. At a validator count with `f = 0` — three validators,
say — one node losing its ABCI service stops the whole chain, so all three go
503. Wiring that to anything that restarts (`Restart=` in systemd, a
Kubernetes `livenessProbe`) then cycles the entire validator set, and the
restarts do not help: the chain is halted on quorum, and it stays halted while
every node bounces. A bounded `max_restarts` turns a restart loop into a set
of stopped nodes, which is better but not good.

So: **`/healthz` is a readiness signal.** "Do not route reads to me" is exactly
right. "Kill and restart me" is not safe to derive from it alone.

### Telling "I am broken" from "the chain is stopped"

There is one signal that separates them, and `felidae query health --peer`
exists to compute it:

    broken node:   app height 2, its CometBFT peer at 3 — and it stays behind
    healthy node:  app height 3, its CometBFT peer at 3 — both stopped together

A node whose ABCI service died sits permanently behind the CometBFT process
feeding it, because it panicked partway through finalizing a block. A healthy
node on a halted chain is level with its peer. Measured across a reproduction
where two of three validators were broken: the skew appeared on exactly those
two and on neither the third nor any node of a healthy run.

    $ felidae query --query-url http://localhost:8080 \
                    health --peer http://localhost:26657

Exit codes are the point:

| exit | meaning | what to do |
|------|---------|------------|
| 0 | advancing | nothing |
| 1 | behind its own peer, or the peer is unreachable | restart this node |
| 2 | level with its peer, or catching up | **do not restart**; the chain is stopped, or the node is syncing |
| 3 | not advancing, no `--peer` given | undecided; do not restart on this alone |

A syncing node is exempt via CometBFT's `catching_up`: mid-sync its peer can lead
by a block while that block is being applied, which looks like a broken node.
`--json` carries the same decision as a `verdict` field: `advancing`,
`node_behind`, `wait` or `unknown`, in exit-code order.

The comparison lives in the CLI rather than in `/healthz` deliberately. Having
`felidae start` poll its own consensus engine would give the application an
outbound dependency on CometBFT and invert the ABCI relationship, which is
worth avoiding for a diagnostic.

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

## CometBFT needs a different policy from felidae

`on_failure` is right for felidae and wrong for CometBFT, for two measured
reasons.

**CometBFT hangs in shutdown.** When its ABCI connection drops it logs
`mempool connection terminated. Did the application crash?`, signals itself to
exit within a millisecond — and then does not finish. Observed at 125 seconds
and still going, ending only when felidae was killed by hand; 7 of 7 nodes
behaved this way while felidae stayed resident, and 1 of 5 still hung after
felidae had aborted. A process that never exits is a process no supervisor
restarts.

**When it does exit, it exits 0.** It is completing a shutdown it asked for,
not crashing, so `Restart=on-failure` will not restart it.

Together those mean the CometBFT unit wants `Restart=always` and a
`TimeoutStopSec` short enough to SIGKILL a shutdown that has stalled. Without
both, the failure mode is two live processes, two green ports, and a chain
that has stopped.
