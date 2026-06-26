# Related work — who is near, and what has no parallel

Where CIRIS sits relative to the work it is most often confused with. The honest claim is **not** that any single idea here is unprecedented — the *institutional* thesis in particular has serious peers — but that the **integrated, decision-level, cryptographically-accountable, federated, conformance-tested, shipping** system appears (to our knowledge, mid-2026; this is a fast-moving space) to have no direct peer. Each near-neighbor fills *some* columns below; CIRIS is the only row that fills all of them **and** targets aligned, accountable *decisions* rather than media provenance, tool interop, or social identity.

This complements [`ALIGNMENT_RATIONALE.md`](ALIGNMENT_RATIONALE.md) (why external constraints) and the README's [superalignment-landscape](../README.md#where-this-sits-in-the-superalignment-landscape) section (where we stand + the anti-singleton stance).

## The matrix

Legend: ✓ yes · ~ partial / adjacent · ✗ no.

| Approach (example) | Mechanism · what it makes accountable | Runtime¹ | Crypto² | Federated³ | Conformance⁴ | Shipping⁵ |
|---|---|:--:|:--:|:--:|:--:|:--:|
| **Value internalization** — RLHF, Constitutional AI, debate/amplification *(Anthropic, OpenAI)* | train the model's values; trust the weights | ✗ | ✗ | ✗ | ✗ | ✓ |
| **AI control** — assume misalignment, constrain actions *(Redwood Research)* | runtime monitoring / untrusted-model protocols, one deployment | ✓ | ✗ | ✗ | ~ | ~ |
| **Guaranteed-safe AI** — proofs / world-models / safety specs *(davidad·ARIA, Bengio·Scientist AI, Tegmark/Omohundro)* | externalize safety into a *formal proof* the system must satisfy | ✓ | ✗ | ✗ | ~ | ✗ |
| **Institutional / normative infrastructure** *(Gillian Hadfield — regulatory markets, normative infra)* | law-like institutions as the alignment substrate — **closest thesis peer** | ~ | ✗ | ✓ | ✗ | ✗ |
| **Crypto provenance / verifiable inference** — C2PA · Content Credentials; zkML *(EZKL, Giza, Modulus)* | attest *"this computation/provenance happened"* — not that a decision is governable | ✓ | ✓ | ~ | ~ | ✓ |
| **Agent protocols** — MCP *(Anthropic)*, A2A *(Google; CIRIS uses it)* | agent/tool interop + auth — no governance, conscience, or accountability layer | ✓ | ~ | ✓ | ~ | ✓ |
| **Decentralized identity / federation** — atproto/Bluesky, ActivityPub; Bittensor | decentralized *social* identity / *compute* markets — not AI decision accountability | ✓ | ✓ | ✓ | ~ | ✓ |
| **CIRIS** | recursive conscience pipeline → **signed reasoning artifacts** → runtime constitution → PQ federation that *independently verifies* them | ✓ | ✓ | ✓ | ✓ | ✓ |

¹ **Runtime** — enforced when the system acts, not baked in at training time.
² **Crypto accountability** — signed, non-forgeable identity / reasoning artifacts / hash-chained audit (not just transport auth).
³ **Federated / multi-party** — many independent humans, agents, orgs; no single party can capture it (the anti-singleton axis).
⁴ **Executable conformance** — an independent, cross-implementation suite that *proves* conformance (W3C/TLS-style), not a one-off eval or an internal test.
⁵ **Shipping** — running in production against real users, not a research artifact.

## How to read it

- **Value internalization** is the field's mainline and the thing CIRIS is *not* — it makes the model's cognition trustworthy; CIRIS makes the model's *actions* accountable regardless of the cognition.
- **AI control** and **guaranteed-safe AI** share CIRIS's core move (assume misalignment; verify externally) and are its closest *philosophical* kin — but neither carries cryptographic identity, federation, or an executable conformance standard, and GS-AI's externalization is a formal proof rather than institutional accountability.
- **Hadfield's institutional thesis** is the closest peer on the *idea* — that AI needs computational equivalents of law and institutions — but it is theory/policy, not a built cryptographic substrate with a conformance suite.
- **C2PA / zkML / atproto / MCP** each fill many columns, which is exactly why CIRIS is mistaken for "just distributed systems": they are the *components' near-neighbors* (provenance, verifiable compute, federation, agent plumbing) — but none target **aligned, governable, accountable decisions** as the unit, and none assemble the conscience-pipeline → signed-artifact → constitution → federation → conformance stack.

## The honest caveat

"No direct peer" cuts two ways. It reflects **genuine novelty** (the integration and the decision-level target), *and* a **contrarian bet** — the field's center of gravity is still model-internal alignment, so building institutions-not-weights is a minority position with serious but few intellectual allies (Hadfield, Redwood, the GS-AI group). That is precisely why the conformance suite matters: it converts "we believe institutions are where alignment is won" into *here are the constraints, independently checkable, passing today.* The novelty claim is **falsifiable** — if a project fills every column above with the same decision-accountability target, this row is no longer unique, and that should be recorded here.
