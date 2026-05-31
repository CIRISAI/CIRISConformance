# CEWP — prior art & state-of-the-art comparison

How **CEWP** (the CIRIS Epistemic Web Platform) sits against the deployed
and published state of the art, *as a whole platform*. The substrate
sisters each carry a focused comparison for their own layer:

- [`CIRISVerify/docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/STANDARDS_COMPARISON.md) — remote attestation, mobile attestation, PQC, license verification
- [`CIRISEdge/docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/STANDARDS_COMPARISON.md) — transport, wire format
- `BENCHMARKS.md` "state of the art" sections (verify, edge) — where the measured numbers land vs the field

This set is the **platform-level** view those don't cover: it compares
CEWP as a system against the prior art in each domain it spans, and names
the property the field does *not* have unified anywhere.

| File | Domain | Compared against |
|---|---|---|
| [`01_storage_replication.md`](01_storage_replication.md) | Decentralized storage + replication | IPFS, Filecoin, Storj, Sia, Hypercore, SSB, Tahoe-LAFS, Freenet, Tor |
| [`02_ai_governance_alignment.md`](02_ai_governance_alignment.md) | AI governance / alignment | RLHF, Constitutional AI, scalable oversight, mech-interp, EU AI Act, Web3-AI |
| [`03_federated_web_identity.md`](03_federated_web_identity.md) | Federated web + portable identity | ActivityPub/Mastodon, Bluesky/AT Protocol, Nostr, SSB, email/DNS |
| [`04_crypto_transparency.md`](04_crypto_transparency.md) | Crypto, attestation, transparency log | Sigstore/Rekor, Certificate Transparency, Trillian, KT; PQC posture |

## The load-bearing claim: a property the field has not unified

CEWP's distinguishing property is the **combination** of two things into
one substrate primitive (FEDERATION_SCALING_MODEL §9):

1. **identity-aware storage at the byte level** — every stored byte
   carries its holder's cryptographic provenance (`holds_bytes` +
   `attesting_key_id`), and
2. **per-actor eviction granularity** — the substrate can answer "whose
   bytes am I holding?" and "evict everything from actor X right now."

Surveyed against IPFS, Veilid, Hypercore, SSB, Storj, Filecoin, Sia,
Tahoe-LAFS, Mastodon, Tor, Freenet, **the two-property combination does not
appear unified anywhere** (§9.2). The closest analogs are SSB/Hypercore
(feed-level identity) and Mastodon (object-level identity at the
*application* layer, not the storage substrate). CEWP welds attribution
and eviction into a single byte-storage primitive (`put_blob_signing`),
which is what makes the trust×capacity intake + popularity×freshness
eviction discipline work at internet scale on commodity hardware — and the
same property is what makes its AI-governance layer enforceable.

## How CEWP positions itself (not a winner-takes-all claim)

CEWP is **not** "better at storage than Filecoin" or "better at social
than Bluesky." It is the *unification*: a substrate where the same
cryptographic-accountability property serves decentralized storage,
portable identity, **and** AI governance simultaneously — and where the
deliberate trade-offs (identity-aware ⇒ holder graph is observable; see
the privacy note in `01`) are stated, not hidden. Each file below is
honest about what the prior art does *better* as well as what CEWP unifies
that they do not.

## Provenance

Drawn from the vendored specs ([`../CEWP.md`](../CEWP.md) §1, §4;
[`../FEDERATION_SCALING_MODEL.md`](../FEDERATION_SCALING_MODEL.md) §9) and
public sources cited inline. Snapshot: 2026-05-31. Update alongside the
spec snapshots in [`../README.md`](../README.md).
