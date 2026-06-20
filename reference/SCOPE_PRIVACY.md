# FSD: Scope-Native Privacy

**Status:** Design proposal. Realization of the CIRIS Constitution
**CC 1.13.3.4** scope-native anonymity *default* — the construction
by which cohort-scoped confidentiality and structural
anonymity-to-outsiders are provided **by default** at every scope
below federation, via substrate-tier configuration of primitives the
holonomic substrate already ships. Companion to
[ANONYMOUS_TIER.md](ANONYMOUS_TIER.md), which realizes the residual
**opt-in** mechanism — full unobservability against a *global passive
adversary* at federation scope (Sphinx onion routing) — via a
different (parallel-tier) construction.

**Companion docs:**
[CEWP.md](CEWP.md) (substrate framing),
[FEDERATION_SCALING_MODEL.md §9](FEDERATION_SCALING_MODEL.md)
(identity-aware-storage trade),
[MEDIA_SHARING.md](MEDIA_SHARING.md) (per-stream MLS exporter
precedent). CIRISRegistry CEG 1.0-RC29 §7 (`cohort_scope`
lattice), §19 (holonomic substrate). CIRISEdge MISSION.md §13,
docs/THREAT_MODEL.md AV-49 / AV-50 / AV-52.

**Threat model.** State-level adversary with legal coercion
authority, full forensic access to seized hardware in the
cold-state condition, subpoena power over the federation
directory, and ability to compel cooperation under duress.
Out of scope: live-seizure RAM extraction, endpoint compromise
of the publisher's device, TCN-class compulsion of future
architectural cooperation, statistical disclosure over months
of observation below the anonymity trilemma.

---

## 1. Thesis

CC 1.13.3.4 establishes that **anonymity defaults to the smallest
cohort scope**: at every scope below federation, structural
anonymity-to-outsiders is the default, and only *federation
(public-commons) scope* opts out of it. The single residual non-goal
— full unobservability against a *global passive adversary* at
federation scope — routes to a separate opt-in mechanism. This FSD
specifies the default construction (and that opt-in tier's substrate
hooks) as a configuration of primitives the holonomic substrate
already ships.

The earlier framing — that base CEG provides *no* anonymity and
routes all anonymity-seekers to opt-in — overclaimed the limit:
cohort-scoping **is** structural anonymity-to-outsiders
("trust-enforceability to insiders, anonymity to outsiders," §1
below), and it is on by default. Making anonymity opt-in would have
weakened protection only for the non-savvy vulnerable, never for a
motivated adversary who clears any toggle trivially.

GPA-unobservability at federation scope stays opt-in for a cost
reason, not a deserving reason: it is the one protection that is
genuinely expensive (onion-routing latency + mixing + dedicated
cover, not free-rider maintenance cover) and is only reached by an
operator already deliberately publishing to the public commons.
**This boundary is provisional.** It should be revisited as the
real overhead of GPA-resistance is measured against the
free-rider-cover budget (§2.6 / §3.1): if the marginal cost for an
*individual* federation-scope publisher proves low enough, the line
MAY move toward making it default for human publishers while leaving
infrastructure traffic (revocation lists, steward keys) on the
cheaper path.

The wire-format addressing primitive at federation scope is
identity-typed (`author_id`, `attesting_key_id`). At every smaller
scope the addressing primitive is **scope-typed**:

    cohort_scope ∈ {self, family, community, federation}

- `self`: federation of one; journaling-grade, content-confidential
  per CC 1.13.3. Cross-attestation (CC 1.13.1 #1) is structurally
  inapplicable; self-scope is not identity-constituting.
- `family`: federation of 2–5 with shared MLS group state.
- `community`: federation of 10–1000 with per-community DEK.
- `federation`: Commons plaintext; full identity-aware substrate.

The identity-aware property of FEDERATION_SCALING_MODEL.md §9 is a
property of the **federation tier**, not the substrate. At every
smaller tier the full identity-aware substrate runs *inside the
encryption boundary*; outsiders cannot adjudicate what they cannot
see. Trust-enforceability and anonymity are the same property
viewed from opposite sides of that boundary — trust-enforceability
to insiders, anonymity to outsiders.

---

## 2. Substrate primitives the construction composes

### 2.1 Scope-typed addressing — CEG §7 / CC 4.4.3.2.1

`cohort_scope` is wire-format. CC 0.2 §4.4.3.2.1 ratified seven
values grouped into three crypto tiers (the substrate-level
privacy lattice), with `cohort_subkind: infrastructure` as the
Commons opt-out hook:

| Crypto tier | `cohort_scope` values | At-rest | Wire discovery | Reader |
|---|---|---|---|---|
| **InvisibleEncrypted** (self/family) | `self`, `family` | encrypted, per-write DEK | none (CC 5.2 structural invisibility) | occurrences / family members |
| **CommunityDek** | `community`, `affiliations` | encrypted under per-community DEK | `holds_bytes:*` + cleartext provenance | community members (DEK cascade) |
| **Commons** | `species`, `biosphere`, `federation` | plaintext | `holds_bytes:*` | anyone |

The `infrastructure` subkind on `community` / `affiliations` opts
OUT of the DEK cascade and becomes Commons-tier (for
`ciris-canonical` and governance/trust root, per CC 4.4.3.2.1).

`affiliations` semantic handling beyond the crypto-tier mapping
remains deferred per CC 0.2 (§11.2 candidate-round backlog); the
substrate construction binds on the crypto-tier resolution, which
is fully ratified.

This FSD's construction applies to **InvisibleEncrypted and
CommunityDek tiers** (the five values `self`, `family`,
`community`, `affiliations`, and `community|affiliations` with
non-`infrastructure` subkind). Commons-tier content (`species`,
`biosphere`, `federation`, plus the `infrastructure` opt-out) is
plaintext federation-scope material outside this FSD's scope; the
CC 1.13.3.1 GPA-unobservability residual for federation-scope
publication is the [ANONYMOUS_TIER.md](ANONYMOUS_TIER.md)
opt-in tier.

The 65% locality dividend
([FEDERATION_SCALING_MODEL.md §1.3](FEDERATION_SCALING_MODEL.md))
re-reads as the structural privacy property of the
InvisibleEncrypted tier: typical activity is self/family-scope
and structurally undiscoverable to the federation by wire format
alone.

**Implementation note (persist).** Persist already implements
this grouping at `federation/types.rs:824` via
`crypto_tier(cohort_scope, cohort_subkind) -> CryptoTier`, with
test coverage matching CC 0.2 §4.4.3.2.1 exactly. Edge consumers
of this FSD MUST resolve through `crypto_tier()` rather than
matching on `cohort_scope` strings directly, so that future
`affiliations` semantic changes flow without wire-format churn.

### 2.2 MLS group state — RFC 9420 ciphersuite 0x004D

Every group has openmls 0.8 MLS group state under X-Wing
(X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65). Two distinct
group-scoped subkeys are derived per-epoch via **bare HKDF-Expand**
on the group's raw `exporter_secret` (as exposed by the MLS key
schedule per RFC 9420 §8.4 — the value `epoch_secret →
DeriveSecret("exporter")` produces):

    K_record_id = HKDF-SHA256-Expand(
        PRK  = raw group exporter_secret,
        info = "ciris-edge/scope-privacy/record-id/v1"  (ASCII),
        L    = 32
    )
    K_symbol    = HKDF-SHA256-Expand(
        PRK  = raw group exporter_secret,
        info = "ciris-edge/scope-privacy/symbol/v1"  (ASCII),
        L    = 32
    )

This is **NOT** RFC 9420 `MLS_Exporter()` / `ExpandWithLabel()` —
there is no HKDF-Extract step, no MLS structured KDF-label
(`"MLS 1.0 " || …`), and no second `DeriveSecret("exporter")`
wrap. The reason: ciphersuite 0x004D is a custom X-Wing suite
whose KDF wrapping conventions are not pinned by RFC 9420; the
labeled expand is owned by `ciris-crypto`'s
`scope_privacy::{k_record_id, k_symbol}` helpers so that two
implementations cannot drift by chasing openmls internals.
CIRISEdge MUST pass the raw `exporter_secret` to those helpers
and MUST NOT call openmls's `export_secret()` for these labels.

The MLS exporter_secret is intrinsically group-and-epoch-bound;
distinct ASCII labels provide domain separation between
`K_record_id` and `K_symbol`. Per-record / per-symbol
diversification is downstream via §2.4.

The HKDF used here is **SHA-256** (matching openmls cs 0x004D's
key-schedule hash); §2.4's `symbol_key` derivation uses
**HKDF-SHA3-256** for HNDL discipline at the per-symbol layer.

### 2.3 Deterministic ALM topology — CEG §19.4

`compute_alm_topology(snapshot) → AlmTopology` is a pure function
over `(capacity_ads, trust_grants, reachability, locality,
snapshot_epoch_id)`. Every observer of the snapshot derives the
same topology. There is no directory authority; the "directory"
is a function whose addressing argument is HMAC-opaque to
non-members (§2.4).

### 2.4 Group-keyed fountain-coded distribution — CEG §19.3

RaptorQ defaults `(N=20, K=6, target_holders=30)`. Each record:

    record_id_input = CBOR_dCE({
        "v":   1,
        "epc": mls_group_epoch,
        "iid": internal_id,
        "typ": record_type,    // integer per RecordType table below
    })
    record_id       = HMAC-SHA3-256(K_record_id, record_id_input)

`CBOR_dCE` is RFC 8949 §4.2.1 Core Deterministic Encoding
(shortest-form integer encoding, definite lengths only,
no floating-point unless required), with map keys ordered
**by encoded-length first, then lexicographically by encoded
key bytes**. The four-entry map at v=1 therefore serializes
keys in the canonical order `v, epc, iid, typ`.

`RecordType` integer encoding (pinned for cross-impl
conformance; CIRISConformance asserts byte-for-byte
reproducibility):

| Type             | int |
|------------------|-----|
| reserved         | 0   |
| SelfRecord       | 1   |
| FamilyRecord     | 2   |
| CommunityRecord  | 3   |
| FederationRecord | 4   |

Additional record types extend this table via CEG §11.

For each RaptorQ symbol:

    symbol_key = HKDF-SHA3-256(salt=record_id, ikm=K_symbol,
                               info="ciris-edge/scope-privacy/symbol/v1"
                                    || u16_be(symbol_index), len=32)
    symbol_envelope = (record_id, u16_be(symbol_index), nonce,
                       XChaCha20-Poly1305(symbol_key, nonce, fragment), tag)

Without `K_symbol` and `record_id`, the holder has indistinguishable-
from-random bytes (Tahoe-LAFS least-authority by reduction to
XChaCha20-Poly1305 IND-CCA + HKDF-SHA3 extract-then-expand).
Fragment-set rebinds on MLS Add/Remove; archive policy is §3.5.

### 2.5 Reticulum (RNS) link layer

RNS packets carry no source addresses; every destination is
`SHA256(public_key)[:16]`. Initiator anonymity is structural.
Transport-node mode means every participating peer is a relay;
LXMF store-and-forward serves asleep recipients. Group-scoped
destinations are excluded from RNS announce flooding (§3.3).

### 2.6 Maintenance traffic budget

L1 steady-state maintenance — anti-entropy + RaptorQ lazy repair
+ ALM topology snapshots + witness chains — is ~10–60 KB/s/peer.
This traffic is emitted for substrate liveness regardless of any
anonymity goal. §3.1 shapes it into the cover budget.

---

## 3. The construction

### 3.1 Poisson emission with substrate-maintenance cover

All outbound substrate traffic conforms:

- **Fixed envelope size: 1.4 KB**, one MTU. Larger payloads chunk
  per CEG §11 fragmentation/reassembly spec.
- **Uniform XChaCha20-Poly1305 AEAD framing** for both real and
  synthetic envelopes.
- **Per-scope Poisson inter-emission intervals.** Each peer
  samples `t_next ~ Exp(λ_scope)` from a peer-local CSPRNG. On
  timer fire, emit the next-queued envelope at that scope; if
  empty, emit a synthetic cover envelope marked `type=cover` in
  the AEAD-protected header.
- **λ_scope tuned so cover emission dominates real publication on
  a lifetime-average inequality** across the measurement window —
  the budget anchor is §2.6 maintenance throughput.

This is the Loopix Poisson discipline applied at the sender-side
emission boundary. The substrate's existing maintenance traffic
(anti-entropy, RaptorQ repair, witness chains — emitted regardless
of the anonymity goal) **is** the cover budget. RNS forwarders
do not perform per-hop re-mixing; cover is sender + recipient
only.

### 3.2 Default cohort_scope

`cohort_scope` defaults to the smallest scope consistent with the
publisher's stated audience: community when a group context is
active, family when in a family context, self when no group
context exists. Federation scope is opt-in. The operator API
returns the chosen scope on every publication ("published at
scope=X to audience=Y") so silent demotions cannot occur.

### 3.3 MLS handshake discipline

- **PrivateMessage-only at non-federation scope.** PublicMessage
  framing is banned at community/family/self.
- **Welcome wrap.** MLS Welcome messages are wrapped by HPKE
  mode_base (RFC 9180 §5.1.1) under the invitee's static X-Wing
  public key. X-Wing has no AuthEncap (per
  draft-connolly-cfrg-xwing-kem; confirmed in draft-ietf-hpke-pq
  §7.2), so HPKE mode_auth is structurally unavailable; sender
  authentication is provided out-of-band by an ML-DSA-65 signature
  from the inviter. Both halves of ciphersuite 0x004D are used.
  
  HPKE parameters (cross-impl pinned; private-use suite-id since
  X-Wing has no IANA KEM-id):
  
        HPKE_SUITE_ID = b"HPKE-xwing-hkdf-sha256-aes256gcm-v1"
        KDF           = HKDF-SHA256
        AEAD          = AES-256-GCM
  
  The suite-id string is used consistently in every RFC 9180
  `LabeledExtract` / `LabeledExpand` call; both sides must use
  identical bytes. The AEAD is AES-256-GCM at the HPKE layer
  (distinct from §2.4 / §3.1 XChaCha20-Poly1305, which protects
  symbols and envelopes at lower layers).
  
  The inviter signs the encapsulation bytes with ML-DSA-65:
  
        encap_signing_bytes
            = x25519_ephemeral_pub      (32 bytes)
            || u32_be(len(mlkem768_ct))
            || mlkem768_ciphertext
  
  The encoding is length-delimited; no `algorithm` field is
  included. Verification of the signature is a precondition to
  unwrapping the Welcome — implementations that omit it forfeit
  sender authentication, and §4 "Forwarder-side membership
  opacity" no longer holds.
- **Invitee key discovery via cached federation directory.**
  Every participating L1 peer maintains a complete local copy of
  the federation directory's X-Wing public keys, refreshed via
  the substrate's existing `federation_keys` anti-entropy. **No
  per-invitation directory query is emitted.** Phone-class peers
  query through their L1-relay parent over a relay-blinded path.
  The directory remains federation-public (per §9.5) but exposes
  no `querier → invitee` edges under subpoena.
- **No RNS announce for group-scoped destinations.** Group
  members resolve each other's destinations from the cached
  directory + per-group HKDF. Per-destination announce control
  is a small Leviculum extension.

### 3.4 Witness chain content discipline

- **Federation witness chain** commits to federation-scope
  record_ids and a single rate-smoothed counter for
  non-federation activity. The counter ticks on a federation-
  wide constant schedule (1 tick / federation epoch). At each
  tick the witness commits to `count mod target_rate`: real
  leaves below target are padded by cover leaves to the target;
  real leaves above target back-pressure into the next tick.
  Cover leaves commit to
  `HMAC-SHA3(witness_signing_key, leaf_position || epoch_id)` —
  cryptographically indistinguishable from real Merkle roots
  under the IND of HMAC-SHA3. Deviation from the constant tick
  is a federation-tier slashing condition.
- **Per-community witness chain** commits to the community's
  record_id set with member-only visibility, signed inside the
  community MLS encryption.

### 3.5 Per-community archive policy

MLS epoch advance bounds the lifetime of `K_record_id` and
`K_symbol`. Each community configures one of:

- **`rotate-forward`** (default, 30-day window): honest holders
  delete past-epoch keys after the window. Forward-secrecy is
  honest-holder discipline, not cryptographic — a holder under
  coercion or running modified software can retain keys (§7.8).
- **`retain`**: holders retain past-epoch keys indefinitely for
  archive readability; an adversary compromising a member at
  epoch N+k recovers everything back to their join epoch.

The choice surfaces at group creation. The mode itself is
operator-local config (§7.14).

---

## 4. Properties

| Property | Source | Notes |
|---|---|---|
| Operator-cryptographic-opacity for stored ciphertext (cold-state) | §2.4 symbol AEAD; §6 at-rest-encrypted openmls StorageProvider with hardware-bound boot key | Operator cryptographically cannot decrypt seized cold-state disk. Tahoe-LAFS least-authority property. Warm-state seizure is §7.8. |
| No directory authority to subpoena for routing | §2.3 deterministic ALM + §2.4 HMAC'd record_id + §3.3 cached directory | The routing "directory" is a pure function; addressing argument is HMAC-opaque; key discovery is cached, not queried per-invitation. |
| Sender + recipient anonymity at link layer | §2.5 RNS source-anonymous packets + §3.3 no group-scoped announces | Free from RNS; group destinations resolved from cached directory + HKDF. |
| In-group safety + moderation | §2.2 MLS + full v1 substrate inside encryption boundary | Trust graph, attestation, eviction, witness chains run inside the encryption — the same encryption that delivers outsider opacity. |
| Client-side Loopix-class GPA cover | §2.6 maintenance budget + §3.1 sender-side Poisson with lifetime-average λ inequality | Defeats sender-side timing and aggregate-volume analysis. Cover is reused non-anonymity-domain maintenance traffic. No per-hop RNS re-mixing; long-term SDA remains (§7.10). |
| PQC group secrecy (industry standard 2026) | §2.2 X-Wing | HNDL preserved. PCS posture depends on §3.5. |
| Forwarder-side membership opacity | §2.4 + §3.3 PrivateMessage-only + signed-wrapped Welcome | Forwarders see uniform envelopes; cannot enumerate members or read handshakes. Welcome-emission timing on freshly-instantiated paths remains observable (§7.13). |
| Past-epoch forward-secrecy (honest-holder) | §3.5 rotate-forward | Honest-holder assumption; coerced or modified holders are §7.8. |
| Locality dividend | §2.1 wire format | Self/family content never federates. |

**Accepted in-scope.** Group members can confirm any record_id
their group has published (the anonymity target is outsiders, not
insiders). In-group adversary tolerance is in-group governance,
not anonymity (§7.1). Cross-fragment timing correlation across K=6
holders is dampened by independent Poisson timers but not
eliminated below the trilemma (§7.10). Federation-scope content
is public by design.

---

## 5. Threat-model mapping

| Adversary capability | Defense |
|---|---|
| Subpoena federation directory | Non-federation records never enter `federation_attestations`; record_id is HMAC-opaque; federation witness commits to a constant-rate counter (no bucket structure). Directory exposes federation-public X-Wing keys — already public per §9.5 — but no per-invitation `querier → invitee` edges (§3.3 cached, no queries). |
| Compel cold-state disk + keys | §2.4 symbol AEAD; openmls StorageProvider encrypts persisted state at-rest under a hardware-bound key (SQLCipher with TPM-sealed boot passphrase). Seized cold-state node yields ciphertext only. |
| Coerce reveal whose data the operator holds | Opaque fragments under HMAC'd record_ids. Operator can truthfully claim cold-state ignorance. |
| Compel active cooperation (cold-state) | Scope-segregated deployment (§6.3): the federation-tier node identity and the community-tier node identity are different processes. A seized community-tier node lacks federation-tier signing authority; a seized federation-tier node lacks community MLS state. |
| Global passive adversary at maintenance budget | §3.1 sender-side Poisson emission with lifetime-average λ inequality (Loopix safety, sender-side only). |
| K=6 of 20 holders compromised | Recovery still requires `K_symbol`; that requires either breaking X-Wing or compromising threshold of group members. |
| DS-role adversary (RFC 9750 §5) | Substrate AEAD covers handshake content; deterministic ALM lets any holder verify topology. Residual: drop/reorder extends Remove-propagation latency (§7.1). |

**Acknowledged residual.** TCN-class compulsion (§7.7),
live-seizure RAM extraction (§7.8), long-term SDA (§7.10),
targeted in-community Sybil (§7.9), Welcome-emission timing on
freshly-instantiated paths (§7.13), operator-local-config metadata
including `archive_mode` and same-node detection telemetry
(§7.14).

---

## 6. Implementation

### 6.1 Cross-repo distribution

| Repo | What ships | LOC |
|---|---|---|
| **CIRISVerify (ciris-crypto)** | HKDF-SHA3 + HMAC-SHA3 + XChaCha20-Poly1305 + HPKE mode_base (RFC 9180 §5.1.1) over X-Wing KEM + ML-DSA-65 sign/verify wrapper for §3.3 Welcome authentication; §2.2 / §2.4 derivation helpers. Minor release with cross-cdylib lockstep cascade. | ~700–1000 |
| **CIRISPersist** | `BlobStorage::put_scope_blob` for symbol-AEAD admission; schema migration on SQLite + Postgres for `federation_scope_blobs` keyed on `(record_id, symbol_index)` with per-symbol nonce. The 7-value `cohort_scope` lattice + `crypto_tier()` grouping is already in tree at `federation/types.rs:824` and matches CC 4.4.3.2.1 — no lattice migration needed (see [CEWP#4](https://github.com/CIRISAI/CEWP/issues/4)). | ~600 + migration |
| **CIRISEdge** | `CohortScope` reconciled with persist's 7-value closed set via `crypto_tier()` resolution (no edge-side lattice contraction; see [CEWP#4](https://github.com/CIRISAI/CEWP/issues/4)); openmls StorageProvider impl backed by SQLCipher with TPM-sealed boot passphrase (substrate-tier MLS state, distinct from per-AV-stream MLS); new emission layer between every `Edge::send_*` and `Transport::send` running per-scope Poisson + synthetic cover synth + per-holder CSPRNG jitter; uniform-envelope chunking/reassembly across ReplicationCoordinator, durable outbound, realtime-AV dispatcher, ALM relay fan-out, blob_swarm, MDC sub-streams; §3.2 default flip with per-publication scope echo; §3.3 HPKE-base Welcome wrap + ML-DSA-65 signature + full directory caching + Leviculum announce-suppression extension + L1-relay-blinded query for phone-class; §3.4 per-community witness chain + single-counter federation witness; §3.5 archive_mode config. | ~3500–4500 |
| **CIRISRegistry (CEG §11)** | Normative absorption: deterministic CBOR profile (RFC 8949 §4.2.1) for record_id; symbol AEAD; fragmentation/reassembly spec; HPKE mode_base + ML-DSA-65 Welcome wrap; per-community witness chain; constant-tick federation counter; announce-suppression discovery primitive; archive_mode vocabulary; constitutional cross-reference. | spec |
| **CIRISAgent / CIRISServer** | PyO3 surface audit for default-scope flip + migration helper. | ~200 |
| **CIRISConformance** | Cross-implementation `record_id` reproducibility on the deterministic CBOR profile; forensic disk-inspection test; Poisson emission KS-test (per-scope λ_real ≤ λ_cover, p > 0.01); 20-holder cross-fragment cluster-detection KS-test. | ~600 |

**Total: ~6000–7500 LOC** across the substrate triple plus a
multi-week cross-cdylib release cascade.

### 6.2 What this does not require

No `AnonymousContribution` parallel record class. No new
MessageType. No Sphinx packet format. No new rendezvous protocol.
No new transport class — wraps existing transport-http /
transport-reticulum / store-and-forward.

### 6.3 Operator deployment guidance — scope segregation

For high-sensitivity communities, operators SHOULD run a
scope-segregated deployment: separate process / VM / box for the
community-tier role, addressing the federation tier through a
different operator identity. Same-node multi-tier participation
leaks community membership via timing correlation. This is
operator-facing deployment discipline; the substrate emits a
warning when a community group's holder set includes peers
running the same node identity at federation scope.

---

## 7. Non-goals

### 7.1 In-group adversary, Remove latency
Encryption boundary IS moderation boundary; a member-adversary
holds the keys. Defense is MLS Remove + epoch rotation; PCS
depends on §3.5. Remove-propagation under §3.1 Poisson and
§2.5 LXMF store-and-forward can be hours; communities requiring
fast Remove SHOULD trigger an explicit epoch flush. DS-role
adversaries can deliberately delay handshake propagation.

### 7.2 Publisher OPSEC failures
Device compromise, key theft, biometric coercion — out of
substrate scope.

### 7.3 Federation-scope content
Commons plaintext is intentionally public. Authors who want
anonymity stay at community scope or below.

### 7.4 Same-node bleeding without §6.3 scope segregation
Without segregation, timing correlation between federation-tier
and community-tier activity leaks community membership.
Deployment discipline, not cryptographic property.

### 7.5 Cross-fragment timing correlation
K=6 holders receive symbols under per-holder Poisson; complete
elimination requires breaking the trilemma.

### 7.6 LoRa / cellular L0 peers
Bytes-per-minute regime cannot afford the §3.1 cover budget.
Per-publication warning when the holder set includes
degraded-mode peers; high-sensitivity communities restrict
membership.

### 7.7 TCN-class compulsion
A Technical Capability Notice compelling future architectural
cooperation is beyond cryptographic mitigation. The construction
is robust against cold-state subpoena; not against compelled
architectural change.

### 7.8 Warm-state seizure / hot-key extraction / dishonest holder
RAM acquisition of a running node recovers the openmls in-memory
state including derived keys. A holder retaining past-epoch keys
against §3.5 policy is structurally undetectable. Universal across
systems; mitigation is deployment discipline (hot-key zeroization
on suspicious-event detection, full-disk encryption with at-boot
passphrase).

### 7.9 ALM-Sybil
Adversary controlling capacity-ads + trust-grants can engineer
into target holder sets. Decryption threshold (K=6 of 20 + group
key) ~15–20% global Sybil. **Observation threshold** (holding
opaque symbols, correlating across many groups) is lower because
it requires only being a holder. **Targeted in-community Sybil**
engineering trust-grant + locality-ad adjacency to a single
community's posture wins K=6 holders below the global threshold;
defense is community-level holder-admission diversity. Defended
at v1 by trust-grant + capacity-ad discipline (CEG §19.4) and
CC 13.3 5-hop delegation cap.

### 7.10 Long-term statistical disclosure
SDA over months of observation recovers persistent patterns even
under continuous Poisson cover. Trilemma lower bound; not
eliminable.

### 7.11 Group lifecycle — split / merge / death
Split: forks retain pre-split exporter_secret and operate
independently from that epoch forward. Merge: no automatic
mechanism. Death: last member departure destroys the only copy of
exporter_secret; records become permanent ciphertext, eventually
GC'd as unowned. Surfaced at group creation.

### 7.12 Compromise recovery
Group-key compromise recovery is **rotate-forward**, not mass
re-publication. Old records are compromised; new records under
new exporter_secret are not.

### 7.13 Welcome-emission timing
The §3.3 HPKE-Base + signature wrap protects content but not the
*event*. A link-adjacent forwarder observing a fresh path
instantiation between two peers observes the invitation
signature. §3.1 cover camouflages volume but not new-path
emergence. Mitigation guidance: batch Welcomes at scheduled
epoch transitions.

### 7.14 Operator-local config metadata
`archive_mode` per community + same-node-detection telemetry
(§6.3 warning state) are operator-local config, observable under
compelled disclosure on the same terms. Operators with
high-sensitivity participation run §6.3 scope-segregated
deployments per archive_mode class or treat the metadata as
known-leak.

### 7.15 DS-role adversary residual (RFC 9750 §5)
Substrate AEAD covers handshake content; deterministic ALM
prevents misroute. Residual: drop/reorder extends Remove latency
(§7.1) at adversary choice.

---

## 8. The harmful-community trade

The construction protects exactly the dissident under a
totalitarian government that CC 1.13.3 names. **It also protects
communities whose content the federation would refuse to host.**
This is structurally true and the Constitution permits it —
CC 1.13.3.4 ratified the protective-default explicitly knowing
that anonymity-by-default is what reaches the non-savvy vulnerable
who would never clear an opt-in toggle, while motivated bad
actors clear toggles trivially. The trade is the same on both
sides of the encryption boundary.

CC 1.13.4 establishes that the substrate cannot moderate content.
The federation governance mechanisms (CC 13.3) act on
federation-scope content, operator behavior at federation tier,
and refusal to host operators whose federation-tier behavior
signals harm. They do not act on community-scope content
(cryptographically invisible), community membership lists
(encrypted MLS state), or in-group adjudication outcomes
(application-layer, in-group).

The substrate's authority does not extend inside the encryption
boundary. CC 1.13.3.4 ratified anonymity-by-default knowing the
default-protection reaches dissidents AND those the federation
would refuse; the Constitutional decision is that the
alternative (opt-in anonymity) strips protection from the
non-savvy vulnerable while leaving motivated adversaries
unaffected, and that substrate visibility into community
content violates CC 1.13.4 categorically. CC 4.2
HUMANITY_ACCORD's substrate-protective discipline against
bad-actor takedown of whistleblowers is the same discipline
that protects bad actors. The trade is permitted because the
alternative is categorical CC 1.13.4 violation and a
discriminatory protection regime against exactly those who need
it most.

---

## 9. Acceptance criteria

- [ ] CIRISVerify ships HKDF-SHA3 + HMAC-SHA3 + XChaCha20-Poly1305
      + HPKE mode_base over X-Wing + ML-DSA-65 wrap + §2.2 / §2.4
      derivation helpers (with cross-cdylib lockstep cascade).
- [ ] CIRISPersist ships `BlobStorage::put_scope_blob` + V091
      schema migration. (Lattice contraction is moot — persist's
      `crypto_tier()` already implements CC 4.4.3.2.1's 7-value
      grouping; see [CEWP#4](https://github.com/CIRISAI/CEWP/issues/4).)
- [ ] CIRISEdge ships `CohortScope` resolving through persist's
      `crypto_tier()` per CC 4.4.3.2.1; SQLCipher-backed
      openmls StorageProvider with TPM-sealed boot passphrase;
      Poisson emission layer on all enumerated emission paths;
      §3.2 default flip + scope echo; §3.3 HPKE-Base + ML-DSA-65
      Welcome wrap + cached federation directory + Leviculum
      announce-suppression; §3.4 per-community witness + single
      federation counter; §3.5 archive_mode config.
- [ ] CIRISRegistry CEG §11 normatively absorbs the construction,
      pins RFC 8949 §4.2.1 deterministic CBOR profile, and
      cross-references the constitutional alignment: this FSD
      provides the **CC 1.13.3.4 anonymity-by-default**
      construction at every scope below federation, with the
      CC 1.13.3.1 GPA-unobservability residual at federation
      scope routing to [ANONYMOUS_TIER.md](ANONYMOUS_TIER.md) as
      the opt-in tier; CC 1.13.5 operational-language gate binds
      substrate-reserved vocabulary at federation tier; in-group
      governance language is application-layer; self-scope
      content is journaling-grade (CC 1.13.1 #1 cross-attestation
      is structurally inapplicable to a federation-of-one).
- [ ] CIRISConformance ships cross-artifact integration tests:
      forensic cold-state disk inspection recovers no publisher
      identity / no group identity / no record content;
      cross-implementation `record_id` reproducibility on the
      deterministic CBOR profile; per-scope Poisson discipline
      lifetime-average inequality verified by KS-test at p > 0.01
      over ≥24h; 20-holder cross-fragment cluster-detection KS-test
      at p > 0.01.
- [ ] Bench: per-tier steady-state maintenance budget measured
      under realistic federation conditions; ~10–60 KB/s/peer
      prediction validated; per-scope cover ratio reported.

---

## 10. Prior art and the narrow novelty claim

The construction recombines well-known primitives:
encrypt-then-erasure-code with operator opacity
(Tahoe-LAFS, Storj, Hyphanet); MLS group key state with X-Wing
PQC (RFC 9420, openmls 0.8, MIMI-MLS draft); group-shaped wire
addressing (ssb-tribes GroupId, libp2p GossipSub topics, Waku v2
topics, MIMI `mimi://domain/g/id` URIs); encryption boundary =
moderation boundary (Briar, Session closed groups, Cwtch,
SimpleX); directory-free routing (mainline DHT, Iroh, Briar
contact graph); Loopix Poisson cover (Loopix, Nym, Katzenpost);
RNS source-anonymous link layer (Reticulum); AEAD with
subcredential KDF (Tor v3 §B.2 HSDir).

The substrate-tier integration of (a) a typed scope lattice as a
**privacy-tier addressing primitive with default-non-federation**
— distinct from MIMI's URI tier naming taxonomy, which enumerates
identifier types without a privacy ordering or default flip —
and (b) **non-anonymity-domain storage-substrate maintenance
traffic** (anti-entropy + RaptorQ repair + witness chains, emitted
for storage liveness regardless of any anonymity regime) reused as
the Loopix cover budget — distinct from Loopix's purpose-built
monitoring loops, which exist because of the anonymity requirement
— has no published implementation.

---

## 11. Relationship to ANONYMOUS_TIER.md

CC 1.13.3 splits anonymity into two complementary protections that
this FSD and ANONYMOUS_TIER.md realize jointly, not as alternative
realizations of one mechanism:

- **CC 1.13.3.4 — anonymity-by-default at every scope below
  federation.** This FSD specifies the default construction via
  substrate-tier configuration of existing primitives:
  `cohort_scope` wire-format, group-keyed fountain AEAD,
  deterministic ALM topology, Poisson emission over maintenance
  cover, MLS HPKE-Base Welcome wrap, per-community witness chains.
  Every CIRIS deployment runs this construction; opting out means
  opting *up* to federation (public-commons) scope per-publication.

- **CC 1.13.3.1 — GPA-unobservability at federation scope (opt-in
  residual).** Full unobservability against a *global passive
  adversary* at federation (public-commons) scope is the single
  residual protection beyond the substrate-maintenance cover budget
  this FSD anchors. [ANONYMOUS_TIER.md](ANONYMOUS_TIER.md) realizes
  this residual via the parallel CIRISNodeCore Anonymous Tier
  (Sphinx onion routing). Operators publishing federation-scope
  content who additionally require GPA-resistance layer that tier;
  the substrate-tier construction below it is unchanged.

The two FSDs are complementary, not alternative. This FSD is the
**default protection floor** at non-federation scopes;
ANONYMOUS_TIER.md is the **GPA-resistant opt-in tier** layered
when federation-scope traffic must additionally defeat a global
passive adversary.

The CC 1.13.3.4 / CC 1.13.3.1 boundary is provisional per §1 — if
the real overhead of GPA-resistance proves low enough against the
free-rider maintenance budget, the line may move toward making
GPA-resistance default for individual federation-scope publishers
while leaving infrastructure traffic (revocation lists, steward
keys) on the cheaper substrate-maintenance path.

---

## 12. References

- [FSD/ANONYMOUS_TIER.md](ANONYMOUS_TIER.md) (companion
  realization)
- [FSD/FEDERATION_SCALING_MODEL.md §9](FEDERATION_SCALING_MODEL.md)
  (identity-aware-storage trade)
- [FSD/CEWP.md §7.1, §8](CEWP.md) (CEG + scaling/privacy)
- CIRISRegistry CEG 1.0-RC29 §7, §19, §19.4, §19.7
- CIRISEdge MISSION.md §13, docs/THREAT_MODEL.md AV-49/50/52
- [RFC 9420 MLS](https://datatracker.ietf.org/doc/rfc9420/),
  [RFC 9750 MLS Architecture](https://datatracker.ietf.org/doc/rfc9750/),
  [RFC 9180 HPKE](https://datatracker.ietf.org/doc/rfc9180/),
  [RFC 8949 §4.2.1 CBOR Deterministic Encoding](https://datatracker.ietf.org/doc/rfc8949/)
- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/),
  [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/),
  [draft-ietf-mimi-protocol](https://datatracker.ietf.org/doc/draft-ietf-mimi-protocol/)
- [Loopix (Piotrowska et al., USENIX Security 2017)](https://arxiv.org/abs/1703.00536)
- [Anonymity Trilemma (Das–Meiser–Mohammadi–Kate, IEEE S&P 2018)](https://eprint.iacr.org/2017/954)
- [Tor v3 onion services](https://spec.torproject.org/rend-spec/),
  [Briar](https://briarproject.org), [Session](https://getsession.org),
  [Cwtch](https://cwtch.im), [SimpleX](https://simplex.chat),
  [Hyphanet](https://www.hyphanet.org/)
