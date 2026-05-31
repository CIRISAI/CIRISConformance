# CEWP vs. the federated web & portable identity

CEWP is a federation of cryptographically-accountable peers with portable,
key-rooted identity. This compares it against the deployed federated-web /
decentralized-social field.

## Identity & portability

| System | Identity root | Portability | Account recovery / continuity |
|---|---|---|---|
| **CEWP** | Self-held federation key (Ed25519 + ML-DSA-65, hybrid PQC) | Key is wire-native; content SHA-addressed; works across deployments | Key custody is the user's; hardware-rooted on mobile (Keystore/Secure Enclave) |
| ActivityPub / Mastodon | `@user@instance` (DNS + instance DB) | **Instance-bound** — move = new actor URI; followers migrate via redirect, content does not | Instance admin holds the account |
| Bluesky / AT Protocol | DID (`did:plc` / `did:web`) + PDS | Portable DID; data in a PDS you can migrate | `did:plc` recovery via the PLC directory (a coordinating service) |
| Nostr | Raw secp256k1 keypair (npub) | Fully portable; relays are interchangeable | No recovery — lose the key, lose the identity |
| SSB | Ed25519 feed key | Portable feed; gossip replication | No recovery; single-device feed-tail problem |
| Solid (W3C) | WebID (URI) + data pod | Pod-portable; identity is a URI (often domain-bound) | Pod-provider / WebID-OIDC |
| Email / DNS | Address @ domain | Domain-bound | Provider holds it |

CEWP is closest to **Nostr/SSB** (self-held key, no administrative root)
but adds **post-quantum** key longevity, **hardware rooting** on mobile,
and a **trust graph** computed over the key — where Nostr has keys but no
native trust computation and SSB has feed-level trust but no governance
layer. **Solid** is the closest *platform-level* framing (Berners-Lee's
"your data in your pod, apps ask permission"), but its identity is a WebID
URI (DNS-anchored, not a self-held key) and it has no native trust-graph or
PQC posture; it solves data-ownership, not federation trust or AI
governance.

## Multi-transport — a substrate-level differentiator

The deployed federated-web stacks are each **single-transport**: Mastodon
is ActivityPub-over-HTTPS only, Nostr is WebSocket-relay only, Bluesky is
its single PDS/XRPC protocol, SSB is its own gossip. CEWP's wire format is
**transport-agnostic** and the substrate rides multiple media: **Reticulum**
(mesh / LoRa / infrastructure-independent), **HTTPS** (CDN/corporate-network
deployments), and content piggybacked on IPFS/Veilid as a backing tier
(see [`01`](01_storage_replication.md)). The same signed CEG artifact
round-trips over whichever medium is reachable — which matters for the
"works regardless of medium availability" reach claim (CEWP can run where
HTTPS is blocked but a mesh isn't, or vice versa). No federated-web peer
treats the transport as a swappable substrate axis this way.

## Trust, moderation & content quality

| Property | ActivityPub | Bluesky | Nostr | **CEWP** |
|---|---|---|---|---|
| Moderation locus | Per-instance admin (defederation) | Composable labelers (opt-in) | Per-relay / client mute lists | Per-cohort governance: `ModerationEvent` → witness aggregation → WA-quorum slashing, **with reconsideration** |
| Trust signal | Follow graph + instance blocklists | Labeler subscriptions | Web-of-trust (NIP-* experiments) | `weighted_aggregate` over signed `scores` attestations, consumer-computed at query time |
| Reversibility | Deplatform (hard) | Re-label | Unmute | `ReconsiderationRequest` is structural |
| Feed ranking | Chronological / server algo | Custom feeds (algos as services) | Client choice | No engagement-optimizer in the substrate; trust depth is a consumer knob (0/1/2/3) |
| Provenance of a claim | Object signature (LD-Signatures, patchy) | Repo commit signatures | Event signature | Hybrid Ed25519 + ML-DSA-65 on **every** wire artifact; Merkle-anchored transparency log |

## The structural difference

The federated-web systems put **identity and (sometimes) signatures** on
the wire, but moderation/trust/quality live at the **application or
instance layer** (Mastodon defederation, Bluesky labelers, Nostr relay
policy). CEWP pushes trust, moderation, and content-quality into the **wire
format itself** (the CEG 1+4 attestation primitives), and the *same* signed
attestations that govern social content also govern AI-agent behavior
(agents carry the same key shape as humans — CEWP §10). None of the
federated-web stacks treat AI agents as first-class governed participants
on the same substrate.

## Where the prior art is genuinely better

- **Maturity & adoption** — ActivityPub (millions of users), Bluesky (tens of millions), Nostr (active ecosystem) are deployed at scale today; CEWP v1 is shipping, not at that scale.
- **Algorithmic choice marketplace** — Bluesky's custom-feeds / labelers are a mature, well-designed composability surface.
- **Simplicity** — Nostr's "dumb relays + signed events" is radically simpler to implement than CEG's 18-section grammar.

## Sources

- CEWP.md §7 (CEG wire format), §10 (participants) · [ActivityPub](https://www.w3.org/TR/activitypub/) · [AT Protocol](https://atproto.com/) · [Nostr NIPs](https://github.com/nostr-protocol/nips) · [SSB protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
