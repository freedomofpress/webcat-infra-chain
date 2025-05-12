## WEBCAT Infra Chain

This repository showcases how a quick, permissioned blockchain for the WEBCAT infrastructure could look. The goal is to replace both the Enrollment Server and the Build Server with a distributed system, reducing censorship risks and avoiding single points of trust or failure. It may also be cheaper to run, as distributing trust makes high availability, backups, and redundancy of individual nodes less critical.

## Example Scenario

### Nodes

- The network consists of four authoritative nodes, each operated by a different semi-trusted organization.
- Authoritative node identities (public keys) are hardcoded in the blockchain configuration.
- Adding or replacing nodes requires either:
  - manual reconfiguration by all existing nodes, or
  - a consensus-based update mechanism approved by the network.
- Non-authoritative (observer) nodes can sync and audit the blockchain but do not participate in consensus.
- Consensus requires 3 out of 4 nodes, allowing tolerance for one offline or malicious participant.
- Malicious updates require collusion by at least 3 nodes.

### Enrollment

- Enrollment requests can be submitted via a web interface hosted by authoritative nodes, or optionally by non-authoritative nodes which relay the transaction request.
- The first receiving authoritative node performs integrity checks:
  - Verifies policy list consistency.
  - Fetches and inspects the domain (e.g., HTTP headers).
- Upon successful validation, the node signs and broadcasts the transaction to its peers.
- If ≥3/4 of nodes validate and sign the transaction, it is committed to the blockchain.

### List Consensus

- Each node maintains a local state mapping domains to their policy hash.
- Every new block includes:
  - the hash of the current trust list state,
  - a timestamp, and
  - signatures from ≥3/4 of nodes.
- The list hash and signatures form a verifiable consensus snapshot.
- Any node (authoritative or not) can export the full list + consensus metadata.
- This bundle is distributed via CDN.

### Browser component (e.g. WEBCAT Extension)
- The browser extension embeds the public keys of authoritative nodes.
- Periodically fetches trust list updates from the CDN.
- Verifies:
  - At least 3/4 valid node signatures.
  - The timestamp is newer than the last known update.
- On success, the browser trusts and imports the new list.

### Censorship considerations
 - Enrollment censorship requires ≥3 nodes to block a valid submission.
 - List publication censorship requires ≥3 nodes to omit entries.


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
