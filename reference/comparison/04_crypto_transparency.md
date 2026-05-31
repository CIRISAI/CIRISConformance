# CEWP vs. cryptographic attestation & transparency logs

CEWP's crypto + transparency substrate is CIRISVerify (hybrid signing,
Merkle transparency log, hardware-rooted identity) consumed across the
federation. The **layer-level** standards comparison (remote attestation,
mobile attestation, PQC parameter choices, license verification) lives in
[`CIRISVerify/docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/STANDARDS_COMPARISON.md)
and should not be duplicated. This file covers the **platform-level**
positioning: the transparency log and the federation-wide PQC posture.

## Transparency log

CEWP signs every wire artifact and anchors federation state in a
Merkle-tree transparency log (CIRISPersist audit chain + STH /
consistency-proof surface, per CEG §10.3). Against the deployed
transparency-log field:

| System | What it logs | Consistency/inclusion proofs | PQC | Governs |
|---|---|---|---|---|
| **CEWP** | Federation attestations, trust grants, audit chain | RFC-6962-style STH + consistency + inclusion proofs (CEG §10.3.1) | **Hybrid Ed25519 + ML-DSA-65** day one | Trust, content, **and AI-agent** claims |
| Certificate Transparency (RFC 6962 / 9162) | X.509 certificate issuance | Yes (the model CEWP tracks) | Classical (Ed25519/ECDSA) | Web PKI only |
| Sigstore / Rekor | Software signing events | Yes (Merkle, Trillian-backed) | Classical | Software supply chain |
| Trillian | General verifiable log (backend) | Yes | Classical | Whatever you put in it |
| Key Transparency (e.g. WhatsApp/Proton) | Identity-key bindings | Yes | Mostly classical | Key directories |

CEWP's transparency log is **6962-lineage by design** (it cites RFC 6962
and tracks 9162-bis where it supersedes) — so it inherits the proven CT
discipline rather than inventing one — and extends it in two ways the
deployed logs do not combine: **(1) post-quantum hybrid signatures on log
entries from day one**, and **(2) the log governs an open attestation
vocabulary** (trust, content quality, moderation, AI-agent claims) rather
than a single artifact type (certs / signatures / key bindings).

## Post-quantum posture (federation-wide)

| Layer | CEWP choice | Field default |
|---|---|---|
| Signatures | Hybrid **Ed25519 + ML-DSA-65** (FIPS-204) on every artifact | Classical Ed25519/ECDSA; PQC signing is rare in deployed federation/social systems |
| Key exchange | **X25519 + ML-KEM-768** (hybrid KEM, CIRISVerify v4.6.0) | Classical X25519/ECDH; hybrid KEX emerging in TLS 1.3 (X25519MLKEM768) but not in decentralized-social stacks |
| Hashing | SHA-256 / SHA-3 family (FIPS-180-4 / 202), TupleHash for domain separation | SHA-256 standard |

The distinguishing claim is **breadth, not novelty of primitive**: hybrid
PQC is applied uniformly across signing *and* key exchange *and* the
transparency log, in a *deployed, cohabiting* multi-wheel substrate — the
posture most of the decentralized-social / decentralized-storage field has
not adopted (they remain classical-signature).

## Where the prior art is genuinely better / more proven

- **Certificate Transparency** is battle-tested at internet PKI scale with a mature ecosystem of monitors/auditors; CEWP's log is younger.
- **Sigstore** has broad supply-chain adoption and a polished UX (keyless signing via OIDC); CEWP's signing is key-custody-based by design.
- **TLS 1.3 hybrid KEX** (X25519MLKEM768) is standardized and shipping in major browsers/servers — a larger deployment surface than any decentralized federation's PQC.

## Sources

- CEG §0.4 (normative refs: FIPS-204 ML-DSA, FIPS-202, RFC 6962/9162), §10.3 (transparency endpoints)
- [`CIRISVerify/docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/STANDARDS_COMPARISON.md) (the attestation/PQC/mobile layer detail) · [RFC 9162 CT v2](https://www.rfc-editor.org/rfc/rfc9162) · [Sigstore](https://www.sigstore.dev/) · [Trillian](https://github.com/google/trillian)
