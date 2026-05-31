# CEWP vs. decentralized storage & replication

CEWP's storage substrate (CIRISPersist `federation_blobs` +
`holds_bytes:sha256:*` holder attestations, content-addressed by SHA-256)
is a peer-to-peer replicated store. This compares it against the deployed
decentralized-storage field. Source: FEDERATION_SCALING_MODEL §9.2.

## The two-property lens

The field splits cleanly on two questions the CEWP substrate answers
*together*:

| System | Identity-aware bytes? | Per-actor eviction? | Pattern |
|---|---|---|---|
| **CEWP** | **Yes (byte-level)** | **Yes (substrate primitive)** | `put_blob_signing` welds attribution + eviction |
| IPFS / Kubo | No | No | Anonymous content-addressing; LRU watermark GC only |
| IPFS Cluster | Partial | Partial | Knows "the peer who pinned," not the author |
| Filecoin | Partial | **No (by design)** | Contract binds host to *keep* data; eviction = slashing |
| Sia | Partial | **No (by design)** | Same — contract-bound hosting |
| Storj | Partial (satellite) | Partial | Nodes see only erasure-coded ciphertext |
| Hypercore / Holepunch | Yes (feed-level) | Yes (feed-level) | Identity rides the feed; cross-feed blobs re-attributed |
| SSB (Scuttlebutt) | Yes (feed-level) | Partial | Replicated blobs decouple from feed identity |
| Tahoe-LAFS | Partial (planned) | Partial | Accounting design proposed, not deployed |
| Freenet | **No (by design)** | No | "Infeasible to discover origin" — anonymity is the goal |
| Tor (relays) | **No (by design)** | No | Unlinkability is the threat model |

**The combination (identity-aware *and* per-actor-evictable at the byte
storage layer) does not appear unified in any deployed system.** The
closest are SSB/Hypercore (feed-level, not byte-level) and Mastodon
(object-level, but at the application layer — see [`03`](03_federated_web_identity.md)).

## Why the contract-storage systems reject per-actor eviction

Filecoin / Sia / Storj are the **inverse** design: their value proposition
is that the host *cannot* evict the renter — sign a contract, post
collateral, get slashed for dropping data. Operator-side per-actor
eviction is the threat model they sell against. CEWP makes the opposite
call because it is a **federation of mutually-attesting peers, not a paid
marketplace**: trust changes over time (a peer slashed today shouldn't
have their content held indefinitely), and the substrate's authority to
evict is exactly what makes federation governance enforceable at the
storage layer.

## Why anonymous content-addressing hits a wall

The documented scaling/abuse pains in IPFS and Freenet are the failures
this property forecloses:

| Known pain (prior art) | CEWP structural answer |
|---|---|
| IPFS pin-set bloat — no popularity/trust signal to drive GC; pinning services curate *outside* the protocol | Trust×capacity intake + popularity×freshness eviction are **in** the wire format (`scores` for trust, `holds_bytes` TTL for freshness) |
| Freenet can't handle abuse — by-design anonymity ⇒ operators hold opaque content with no surface to refuse a specific actor | `attesting_key_id` per byte ⇒ refuse / evict by actor structurally |
| IPFS Cluster: "untrusted peers lying about free space" — resource attestation with no identity-tied recourse | Resource + holder claims are signed attestations with identity-tied recourse |

## Where the prior art is genuinely better

Honest trade-offs CEWP does **not** beat:

- **Erasure-coded durability at rest** (Storj, Filecoin) — CEWP v1 replicates whole blobs by trust/popularity, not Reed-Solomon shards; raw durability-per-byte-stored is a Storj/Filecoin strength.
- **Economic durability guarantees** (Filecoin/Sia) — paid contracts give a *contractual* keep-guarantee CEWP deliberately doesn't offer.
- **Maximal anonymity** (Freenet, Tor, IPFS-over-Tor) — CEWP v1 is identity-aware by design; the holder graph is observable (below). Anonymity-needing content uses the CEG locality dividend (`cohort_scope ∈ {self, family}` never emits `holds_bytes` → never discoverable) or the v2 anonymous tier.

## The deliberate privacy trade-off (stated, not hidden)

Identity-aware storage means the **holder graph is observable**: peers can
query "who holds content from author X?" against the public
`federation_attestations` rows. This is the design's privacy-vs-trust
trade — IPFS/Freenet/Tor preserve anonymity (and inherit
abuse-impossible-to-handle + indiscriminate-replication scaling pain); CEWP
chooses identity-aware + trust-enforceable + governable, and scaling works
*because* admission is selective. Content needing anonymity stays
self-hosted via the locality dividend; trust-aware content rides the
federation (FEDERATION_SCALING_MODEL §9.5).

## Sources

- FEDERATION_SCALING_MODEL §9.2–§9.5 (vendored, with the full citation list)
- [IPFS GC](https://docs.ipfs.tech/how-to/kubo-garbage-collection/) · [IPFS Cluster allocator](https://github.com/ipfs-cluster/ipfs-cluster/blob/master/allocate.go) · [Storj v3](https://static.storj.io/storjv3.pdf) · [Filecoin storage market](https://spec.filecoin.io/systems/filecoin_markets/storage_market/) · [Sia](https://sia.tech/hosting-best-practices) · [Hypercore DEP-0002](https://www.datprotocol.com/deps/0002-hypercore/) · [Tahoe-LAFS accounting](https://tahoe-lafs.org/trac/tahoe-lafs/wiki/NewAccountingDesign) · [Freenet](https://www.cs.cornell.edu/people/egs/615/freenet.pdf)
