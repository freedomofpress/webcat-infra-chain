# WEBCAT validator onboarding

## Introduction

This onboarding document is intended to help parties who are joining the WEBCAT ring.
The WEBCAT architecture is built on open source software involving [CometBFT](https://cometbft.com) and FPF's '[Felidae](https://github.com/freedomofpress/webcat-infra-chain)' ABCI application.

There are many different ways of setting up that software which may vary depending on an organization's needs.
Freedom of the Press Foundation has developed several Ansible roles which aim to help organizations quickly get up and running.
You are not obliged to use the Ansible roles if you have other means of provisioning and configuring systems, but if you know Ansible and would like to use it, we hope it helps!

Please don't hesitate to get in touch if you run into problems using the guide.

---

## Topology of the Ansible roles

These Ansible roles are designed around setting up CometBFT and Felidae on a group of servers with different roles, known as **validators + sentries**:

In our CometBFT setup:

- Validators peer with **all sentries**
- Each sentry peers with **its partner validator**, plus **all other sentries**
- The partner relationship is expressed with `cometbft_partner` (the value of which is an inventory hostname)

There are three Ansible roles:

- [ansible-role-cometbft-bootstrap](https://github.com/freedomofpress/ansible-role-cometbft-bootstrap)
- [ansible-role-cometbft](https://github.com/freedomofpress/ansible-role-cometbft)
- [ansible-role-felidae](https://github.com/freedomofpress/ansible-role-felidae)

The 'CometBFT Bootstrap' role generates a CometBFT "testnet" directory `node0/..nodeN/`. It then **rsyncs** the right `node{{ cometbft_node_index }}` data to the right machine. It's intended to be run just once.

The 'CometBFT' role is for managing the CometBFT config.toml and Docker configuration going forward.

The 'Felidae' role is for managing the Felidae ABCI component's Docker configuration and other settings going forward.

The CometBFT and Felidae components work closely with one another and there is an explicit relationship between them at the infrastructure level, in particular the shared Docker network that allows the containers to communicate together.

---

## Prerequisites

**On the bootstrap machine (usually your Ansible control host):**

- Docker installed (bootstrap runs `docker run ... cometbft testnet ...`)

**On every node (validators and sentries):**

- Docker + Docker Compose plugin available (`docker compose ...`)
- `rsync` available (for `ansible.posix.synchronize` to rsync the bootstrapped data out to the nodes)
- Firewall rules appropriate for P2P and any exposed HTTP endpoints (more on Firewalls below).

---

## Ansible Inventory: required groups and required vars

We recommend to use the `host_group_vars` plugin in your `ansible.cfg`:

```yaml
vars_plugins_enabled = host_group_vars
```

### Required host groups

Your Ansible inventory must contain these groups:

- `cometbft_bootstrap` (typically just `localhost` as member, as the bootstrapping happens locally)
- `cometbft_validators` (just the 'validator' nodes as members)
- `cometbft_sentries` (just the 'sentry' nodes as members)
- optional: a `cometbft` parent group that includes validators+sentries, to share common vars for convenience.

### Required per-group variables (common)

Put these in `group_vars/cometbft.yml` (or equivalent):

```yaml
# --- CometBFT common ---
cometbft_home: "/opt/cometbft"
cometbft_testnet_dir: "/tmp/comet-testnet"

# IMPORTANT: avoid the "double v" issue by pinning the image explicitly.
# cometbft-bootstrap defaults to cometbft_version: "v0.38.21" and uses
# cometbft_docker_image: "cometbft/cometbft:{{ cometbft_version }}".
# cometbft role defaults to cometbft_version: "0.38.21" and uses
# cometbft_docker_image: "cometbft/cometbft:v{{ cometbft_version }}".
#
# Easiest: set cometbft_docker_image directly and treat cometbft_version as informational.
cometbft_version: "0.38.21"
cometbft_docker_image: "cometbft/cometbft:v{{ cometbft_version }}"

# --- Docker network contract (MUST match what Felidae uses) ---
cometbft_docker_network: "webcat"
cometbft_docker_setup_network: false  # Felidae creates the network by default

# --- Felidae common ---
felidae_home: "/opt/felidae"
felidae_docker_network: "{{ cometbft_docker_network }}"   # MUST match CometBFT
felidae_docker_setup_network: true                        # Felidae creates it

# Container naming contract:
felidae_docker_container_name: "felidae"

# ABCI port contract:
felidae_abci_internal_port: 26658
felidae_abci_host: 0.0.0.0

# CRITICAL: CometBFT must reach Felidae *on the docker network*, by container name.
# Felidae listens on 0.0.0.0:26658 inside its container, so CometBFT should use:
cometbft_proxy_app: "tcp://{{ felidae_docker_container_name }}:{{ felidae_abci_internal_port }}"

# Allow Felidae oracle to talk to CometBFT over the docker network.
# CometBFT role uses container_name: cometbft-{{ cometbft_role }}
# so the sentry CometBFT container is "cometbft-sentry".
cometbft_rpc_internal_port: 26657
felidae_oracle_node: "http://cometbft-sentry:{{ cometbft_rpc_internal_port }}"
```

> Why the `cometbft_proxy_app` override matters:
> The CometBFT role defaults `cometbft_proxy_app` to `tcp://127.0.0.1:26658`, but in this deployment both CometBFT and Felidae run in separate Docker containers, on a common bridge network.

CometBFT needs to connect to Felidae by **container DNS name** (`felidae`), not host loopback.

### Required per-group variables (role)

`group_vars/cometbft_validators.yml`:

```yaml
cometbft_role: "validator"
felidae_admin: true
felidae_oracle: false
cometbft_consensus_double_sign_check_height: 0 # TODO this will change once we make it production ready
```

`group_vars/cometbft_sentries.yml`:

```yaml
cometbft_role: "sentry"
felidae_admin: false
felidae_oracle: true
```

### Required per-host variables

Every host needs:

- `cometbft_node_index` (selects which `nodeX/` from bootstrap gets synced). This can be '0' for validator-1, '1' for validator-2, and so on.
- `cometbft_partner` (inventory hostname of the paired node; required for sentries).

Example `host_vars/validator-1.yml`:

```yaml
cometbft_node_index: 0
cometbft_partner: "sentry-1"
```

Example `host_vars/sentry-1.yml`:

```yaml
cometbft_node_index: 3
cometbft_partner: "validator-1"
```

### Important: `ansible_host` must be P2P-reachable

The CometBFT role builds peer addresses using:

- `hostvars[item].ansible_host`
- fixed P2P port `:26656`

So set `ansible_host` to an address that other nodes can reach on **26656/tcp**.

---

## Step 1 — Bootstrap (generate the testnet directory)

Create a playbook `playbooks/cometbft-bootstrap.yml`:

```yaml
---
- name: Bootstrap CometBFT testnet config
  hosts: cometbft_bootstrap
  connection: local
  gather_facts: false
  roles:
    - ansible-role-cometbft-bootstrap

- name: Push node config to each remote node
  hosts: "cometbft_validators:cometbft_sentries"
  become: true
  tasks:
    - name: Ensure cometbft home exists
      ansible.builtin.file:
        path: "{{ cometbft_home }}"
        state: directory
        mode: "0755"

    - name: Sync node{{ cometbft_node_index }} dir to remote CMTHOME
      ansible.posix.synchronize:
        src: "{{ cometbft_testnet_dir }}/node{{ cometbft_node_index }}/"
        dest: "{{ cometbft_home }}/"
        delete: yes
```

Run:

```bash
ansible-playbook -i inventory.yml playbooks/cometbft-bootstrap.yml
```

This generates:

```
{{ cometbft_testnet_dir }}/
  node0/
  node1/
  ...
  nodeN/
```

It will rsync the bootstrapped data out to each of the validators and sentries.

**This is the "keys correctness" step.** If `cometbft_node_index` is wrong, you will deploy the wrong node keys/config to that machine.

---

## Step 1b — Author the chain config (genesis `app_state.config`)

The genesis files produced by the bootstrap step contain **no `app_state`**, and
Felidae refuses to start a chain without one: `InitChain` requires a complete,
valid `app_state.config` (there is no default, and the first reconfigure is
never permissionless). Before deploying, author the config and inject it into
every node's genesis.

1. Collect the admin and oracle **public keys** from each operator (see
   ["How to generate and get the keys"](#how-to-generate-and-get-the-keys-for-the-felidae-admin-and-oracle)
   below — these identities go into the config authored here).

2. Author `config.json`. Start from `felidae admin template`, copy a
   deployed example such as `genesis/testnet01/genesis.json`'s
   `app_state.config`, or generate a known-good reference with
   `felidae-deployer create-network` (see
   ["Using felidae-deployer"](#using-felidae-deployer-local-networks-and-genesis-reference)
   below). Fill in:
   - `admins.authorized`: every admin public key; `admins.voting.total` must
     equal the list length, and `quorum` is your threshold (e.g. 2 of 3).
   - `oracles.authorized` / `oracles.voting`: same rules. At least one oracle
     is required.
   - Leave no placeholder identities and no zero quorums — the chain will
     refuse to start otherwise.

3. Pre-flight the config:

   ```bash
   felidae debug parse-config config.json
   ```

4. Inject it into **each** node directory before the rsync in Step 1 (genesis
   must be byte-for-byte identical on every node). The easiest way is
   `felidae-deployer inject-config`, which re-validates the config with the
   same checks `InitChain` runs before writing anything:

   ```bash
   felidae-deployer inject-config --config config.json \
       $(printf -- '--genesis %s ' "${COMETBFT_TESTNET_DIR}"/node*/config/genesis.json)
   ```

   Or equivalently with `jq`, if you don't have the deployer built:

   ```bash
   for g in "${COMETBFT_TESTNET_DIR}"/node*/config/genesis.json; do
       jq --slurpfile cfg config.json '.app_state = {config: $cfg[0]}' "$g" > "$g.new" \
           && mv "$g.new" "$g"
   done
   ```

   If you have already rsynced, re-run the sync play from Step 1 after
   injecting, so all hosts receive the updated genesis.

---

## Using `felidae-deployer` (local networks and genesis reference)

`felidae-deployer` is a Rust CLI that ships in the
[webcat-infra-chain](https://github.com/freedomofpress/webcat-infra-chain)
repository (`crates/felidae-deployer`). It orchestrates complete
CometBFT + Felidae networks on a single machine — no Docker, no Ansible. It is
a **developer/testing tool, not a production deployment path**, but it earns
its place in this guide two ways:

1. **Rehearsal.** Spin up the full topology locally (validators, optional
   sentries, oracles) and watch a chain reach consensus before you touch real
   infrastructure.
2. **Genesis reference.** It performs Step 1b for you — generates admin and
   oracle keys, computes BFT-safe quorums (`2n/3 + 1`), and injects a complete,
   valid `app_state.config` into every node's genesis. Its output is a
   known-good template for authoring your production `config.json`.

Build it from the repo:

```bash
cargo build --release -p felidae-deployer
```

### `create-network` — generate a network directory

```bash
felidae-deployer create-network \
    --directory ./testnet \
    --num-validators 3 \
    --use-sentries \
    --chain-id felidae-test \
    --admin-delay 0s \
    --oracle-delay 1s
```

This produces, under `--directory`:

- Per-node CometBFT homes (keys, `config.toml`, `genesis.json`) with
  non-conflicting ports
- Freshly generated **admin and oracle keypairs** for each validator
- A genesis `app_state.config` listing those identities, with
  `voting.total` = validator count and `quorum = 2n/3 + 1`, injected
  identically into every node's genesis
- `network.json` (network metadata) and a `process-compose.yaml` for
  optional use with [process-compose](https://github.com/F1bonacc1/process-compose)

The `--admin-delay` and `--oracle-delay` flags map to the `voting.delay`
fields from Step 1b; `--timeout-commit` (alias `--blocks-every`) controls the
block interval.

To crib a config for Step 1b, extract it from any generated genesis:

```bash
jq .app_state.config ./testnet/validator-0/cometbft/config/genesis.json > config.json
```

Then replace the generated identities and endpoints with the real operators'
public keys and URLs, adjust delays/timeouts for production, and pre-flight it
with `felidae debug parse-config` as usual.

### `run-network` — run it

```bash
# Run directly, with prefixed log output per process:
felidae-deployer run-network --directory ./testnet \
    --felidae-bin ./target/release/felidae \
    --cometbft-bin ./cometbft/build/cometbft

# Or build felidae from the current workspace automatically:
felidae-deployer run-network --directory ./testnet --dev

# Or hand off process management to process-compose:
felidae-deployer run-network --directory ./testnet --process-compose
```

With no `--directory`, it creates a throwaway single-validator network in a
temporary directory — the fastest way to a working chain. All processes
(CometBFT, Felidae, one oracle server per validator) start together and shut
down together on Ctrl+C. The repo's `justfile` wraps the common case:
`just testnet-create` and `just testnet-run`.

### `inject-config` — validate and inject a config into genesis files

The command behind Step 1b's injection. With `--config`, it validates an
authored config (the same stateless checks `InitChain` runs: placeholder
identities, zero quorums, inconsistent voting totals) and writes it into the
`app_state.config` of every `--genesis` file given:

```bash
felidae-deployer inject-config --config config.json \
    --genesis node0/config/genesis.json --genesis node1/config/genesis.json
```

Without `--config`, it generates a **single-node dev config** instead: fresh
admin and oracle keys (quorum 1 of 1), created in the same homedirs the
`felidae` CLI uses, so `felidae admin ...` and `felidae oracle server` find
them without extra flags. This is what `just genesis-single` uses to make a
bare `cometbft init` home chain-startable. `--admin-delay`, `--oracle-delay`,
and `--oracle-endpoint` tune the generated config.

### `join-network` — bootstrap an additional node

To add a full node to an already-running network:

```bash
felidae-deployer join-network \
    --genesis-file genesis.json \
    --peer <NODE_ID@HOST:26656> \
    --directory ./fullnode
```

Genesis must come from `--genesis-file` or `--genesis-url` — a raw file, used
byte-for-byte. Fetching genesis via CometBFT RPC is deliberately unsupported:
the RPC re-serializes the JSON, which changes bytes and causes AppHash
mismatches. This is the same byte-for-byte constraint behind the Step 1b rule
that genesis must be identical on every node. Peers may instead be
auto-discovered from a running node with `--cometbft-url <RPC>`, and
`--find-free-ports` avoids collisions when joining on the same host. The
command prints (or emits as JSON with `--json`) the exact `cometbft start` and
`felidae start` invocations to launch the node.

---

## Step 2 — Deploy Felidae, then CometBFT

Create a playbook `playbooks/cometbft-nodes.yml`:

```yaml
---
- name: Deploy Felidae and CometBFT
  hosts: "cometbft_validators:cometbft_sentries"
  become: true
  roles:
    - ansible-role-felidae
    - ansible-role-cometbft
```

Run:

```bash
ansible-playbook -i inventory.yml playbooks/cometbft-nodes.yml
```

### What the Felidae role does

- Creates `{{ felidae_home }}` and storage dirs
- Renders `{{ felidae_home }}/docker-compose.yml`
- Ensures the shared Docker network exists
- Starts the Felidae services via `docker compose up -d`

The following Felidae services are controlled by this role and its inventory:

#### felidae_admin (on validators)

This runs on the validatores. It provides the one-shot CLI admin identity container (keys under `{{ felidae_home }}/admin_keys`), when you need to run it from time to time.

Admins sign reconfiguration transations to change the chain configuration (for example, when new validators are added). The *initial* configuration is not set this way — it ships in the genesis `app_state.config` (Step 1b), and every reconfigure thereafter must be signed by an admin listed in the current config.

Admins need access to the chain RPC on the validator.

#### felidae_oracle (on sentries)

This runs the oracle server container and binds its port to `127.0.0.1:{{ felidae_oracle_external_port }}`. This is an ongoing service.

Oracles fetch enrollment information (a JSON file) from public domains and they submit their observations to the CometBFT chain.

Similarly to the felidae admin, it's a simple Rust CLI but it will expose an HTTP API (just two endpoints, `POST /observe` and `GET /health`) that needs to be accessible to frontends.

See the bottom of this document for suggestions on running an Nginx proxy in front of the oracle container, in order to terminate TLS and proxy to the oracle.


#### felidae (main service)

This is the ABCi proxy_app itself. It exposes endpoints like /canonical/leaves and /config and is intended to be publicly accessible. (Again, see the bottom of this document for suggestions on terminating TLS with Nginx or other proxies). You will proxy all other requests to the sentry (other than the `/observe` and `/health` endpoints ownedb y the oracle above) to this container.


### What the CometBFT role does

- Runs `docker run ... show-node-id` against `{{ cometbft_home }}` to learn each node's ID
- Builds peers based on group membership and `cometbft_partner`
- Renders the following templates:
  - `{{ cometbft_home }}/config/config.toml` # this contains the peer IDs and other relationship information
  - `{{ cometbft_home }}/docker-compose.yml`
- Starts CometBFT via `docker compose up -d`

---

## Understanding the relationship between Felidae ↔ CometBFT

These are the vars that make Felidae and CometBFT connect correctly in this specific role design:

### 1) Shared Docker network name
Must match:

```yaml
felidae_docker_network: webcat
cometbft_docker_network: webcat
```

Recommended setting to avoid duplication or mismatch mistakes:

```yaml
cometbft_docker_network: webcat
felidae_docker_network: "{{ cometbft_docker_network }}"
```

### 2) CometBFT proxy_app must target Felidae container name + port
Because CometBFT is in Docker, `127.0.0.1` is **that of its own container**, not the host.

Set:

```yaml
felidae_docker_container_name: felidae
felidae_abci_internal_port: 26658
cometbft_proxy_app: "tcp://{{ felidae_docker_container_name }}:{{ felidae_abci_internal_port }}"
```

### 3) Felidae oracle must target the CometBFT sentry container name + RPC port
CometBFT sentry container name is `cometbft-sentry` (from `container_name: cometbft-{{ cometbft_role }}`).

Set:

```yaml
cometbft_rpc_internal_port: 26657
felidae_oracle_node: "http://cometbft-sentry:{{ cometbft_rpc_internal_port }}"
```

And ensure:
- sentry hosts have `felidae_oracle: true`

### 4) Ensure CometBFT RPC is reachable on the docker network
The CometBFT defaults are already aligned for this:

```yaml
cometbft_rpc_internal_host: 0.0.0.0
```

Keep it, unless you have a reason to change it.

---

## Validation checklist

Run these on a node after deployment:

### Check containers are running
```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

You should see (depending on role):
- validator: `felidae`, `cometbft-validator` (and possibly `felidae-admin` exited, because it's a one-shot tool)
- sentry: `felidae`, `cometbft-sentry`, `felidae-oracle`

### Confirm CometBFT config has the right proxy_app
On the host:
```bash
grep '^proxy_app' {{ cometbft_home }}/config/config.toml
```

Should be:
```
proxy_app = "tcp://felidae:26658"
```
(or whatever you set via `felidae_docker_container_name` / port)

### Confirm CometBFT peers got rendered
```bash
grep 'persistent_peers' {{ cometbft_home }}/config/config.toml # should be a comma-delimited list of all validators and sentries peer IDs
grep 'private_peer_ids' {{ cometbft_home }}/config/config.toml # empty on the validator, otherwise set to the validator peer id if on a sentry
```

### Check Felidae oracle is pointing at the sentry CometBFT container
On a sentry:
```bash
docker inspect felidae-oracle --format '{{json .Config.Cmd}}'
```

Output should look like this:

```
["/usr/bin/felidae","oracle","server","--homedir","/keys","--node","http://cometbft-sentry:26657","--port","8080"]
```

---

## Common failure modes (and what to check)

1) **CometBFT can't connect to Felidae (ABCI)**
- `cometbft_proxy_app` is still `tcp://127.0.0.1:26658`?
- `felidae_docker_container_name` changed but `cometbft_proxy_app` wasn't updated?
- Docker network name mismatch (`webcat` in the felidae compose file vs something else in the cometbft compose file, or vice versa)?

2) **Felidae oracle can't connect to CometBFT**
- `felidae_oracle_node` points to the wrong container name (must be `cometbft-sentry` on sentries)
- `cometbft_rpc_internal_host` not `0.0.0.0` (oracle needs it to be reachable inside docker network)

3) **Peers are wrong / no peers**
- `ansible_host` is not the address other nodes can reach on 26656
- `cometbft_partner` points to the wrong inventory hostname (sentry peering/private IDs break)
- Hosts not correctly in `cometbft_validators` / `cometbft_sentries`

4) **Version tag mismatch**
- One role uses `v0.38.21` while another uses `0.38.21`
- Fix: set `cometbft_docker_image` explicitly (recommended above)

---

## Setting up HTTPS termination for the Sentry oracle and Felidae query port

Since the sentries run the 'oracle', with endpoints that are intended to be public, you probably want to put something like Nginx (or another HTTP server) in front to offer TLS and proxy to the backend container.

Here is an example Nginx configuration for the sentries. Adjust to suit your needs. The `location` blocks are the main ones to consider.

```
server {
   listen 443 ssl;
   server_name webcat-sentry-1.example.com;
   # Cribbed nginx SSL config from https://cipherli.st/
   ssl_protocols TLSv1.3 TLSv1.2;
   ssl_prefer_server_ciphers on;
   ssl_ecdh_curve secp384r1;
   ssl_session_cache shared:SSL:10m;
   ssl_session_tickets off;
   ssl_stapling on;
   ssl_stapling_verify on;
   resolver_timeout 5s;
   more_set_headers 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload';
   more_set_headers 'X-Content-Type-Options: nosniff';
   more_set_headers 'X-Frame-Options: DENY';
   more_set_headers 'X-XSS-Protection: 1; mode=block';
   more_set_headers 'Referrer-Policy: same-origin';

   ssl_certificate /etc/letsencrypt/live/webcat-sentry-1.example.com/fullchain.pem;
   ssl_certificate_key /etc/letsencrypt/live/webcat-sentry-1.example.com/privkey.pem;

   # Proxy /observe and /health to the felidae oracle
   location = /observe {
       proxy_pass http://localhost:8081;
   }
   location = /health {
       proxy_pass http://localhost:8081;
   }
   # Everything else proxies to the main felidae query port
   location / {
       proxy_pass http://localhost:8080;
   }
}
```

As you can see, the `/observe` and `/health` routes are passed to the Oracle container.

Meanwhile, all other requests (to routes such as `/canonical/leaves`, `/config` etc) are proxied to the Felidae container's query port

---

## How to generate and get the keys for the Felidae Admin and Oracle

To join the chain, we need to know the public keys. For a new chain, collect
these from every operator *before launch*: they belong in the genesis
`app_state.config` (Step 1b). For an existing chain, an admin adds them via a
signed reconfigure.

Run the below to 'init' (create) the keys. The public key will be returned in the output of the second command.

### Admin (on the validators)

```
felidae admin init --homedir /keys
felidae admin identity --homedir /keys
```

### Oracle (on the sentries)

```
felidae oracle init --homedir /keys
felidae oracle identity --homedir /keys
```
