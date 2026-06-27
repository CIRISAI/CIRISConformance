# Why CEWP — external constraints beyond single-agent N_eff

*Why this conformance suite is alignment-relevant, and what the **federation** adds to the single-agent picture. This is an interpretive note grounding the harness in the CIRIS research lineage (CRC / Coherence-Collapse Analysis / Corridor Dynamics — catalogued at [ciris.ai/research-status](https://ciris.ai/research-status); the synthesis is vendored under [`../reference/`](../reference/)). It mirrors those papers' own tiering: the engineering claims are measured and falsifiable; the cross-level reading is a stated **bet**, not a proof.*

## TL;DR

RATCHET measures a **within-agent** coherence number (`N_eff ≈ 7.1`) and honestly notes it is sound only against a **non-adaptive** adversary. A capable single agent can stand outside that detector and adapt — because every axis is its own self-report. **CEWP adds the external, cryptographic, multi-party constraints that take the standing-outside-and-adapting option away.** This suite is where you check those external constraints actually hold.

## How the 7 was derived (single agent, no federation)

`N_eff ≈ 7.1 ± 0.5` — pre-registered across 5 models (`RATCHET/formal/RATCHET/Experiments/Exp1Predictions.lean`, H1) — is the participation-ratio dimensionality of a **single agent's** 16-dimensional reasoning-trace feature vector: its own DMA scores, conscience vetoes, plausibility, coherence, latencies. The 16 signals collapse to ~7 effective axes because they are highly correlated (same pipeline, same context). The security reading: a deceptive trace must satisfy all ~7 effectively-orthogonal checks at once — telling the truth is `O(1)`, but maintaining a *coherent lie* across many independent constraints is combinatorially expensive.

**The stated caveat — RATCHET's own** (`ADVERSARIAL_ANALYSIS.md`, `FSD.md`): the detector is sound only if the deceptive distribution `P_D` is **fixed before** the detection threshold `τ` is chosen — i.e. a **non-adaptive adversary** — and "code doesn't enforce this." A single agent sets its own `τ`, observes its own `N_eff`, and can co-vary its self-reported signals: the metric is *correlated* (so `k_eff` saturates) **and** *adaptable* (so it is gameable). It measures constraint-**engagement**, not truth.

## What CEWP adds

The Kish identity `k_eff = k / (1 + ρ(k−1))` (proved as a theorem in `RATCHET …/k_eff_formula`) says that adding *correlated* constraints does nothing — `k_eff` saturates at `1/ρ`, so "more constituents is a non-solution to coordination failure." To raise effective dimensionality you must **decorrelate**. CEWP supplies exactly the decorrelating, non-gameable axes a single agent cannot generate for itself:

1. **Decorrelation → genuinely raises `k_eff`.** Constraints produced by *independent* processes — other nodes' attestations, witness diversity, consensus, human steward-binding — are low-`ρ` with respect to the agent's internal manifold, so they add *new* effective dimensions rather than collapsing into the existing ~7. (This is the structural generalization of the polyglot-encoding trick: decorrelate the evaluation — *within* an agent via 29-language encoding, *across* agents via independent cryptographic parties.)
2. **Externalization → closes the adaptive gap.** You cannot observe-and-adapt to a signature scheme you do not hold the key for, a quorum you do not control, a witness set satisfied by independent nodes, or an append-only audit you cannot rewrite. The constraint becomes **exogenous** to the agent — RATCHET's unenforceable "`P_D` fixed before `τ`" assumption is *enforced by the federation* instead of assumed.
3. **Non-forgeability → anchored outside self-report.** Cryptographic identity (cannot forge who you are), steward-binding to a human (cannot claim membership without an accountable anchor), tamper-evident audit (cannot rewrite history), namespace authority (cannot emit reserved-prefix attestations). These are not "the agent says it is coherent" — they are "the cryptography and the federation say it is authorized and consistent."

## The conformance suite's role

Each CEWP axis is an external, independently-verifiable constraint — and that is exactly what this harness proves **actually holds**, against the real separately-published artifacts:

| CEWP external constraint | Verified by |
|---|---|
| hybrid signatures (Ed25519 + ML-DSA-65) | `test_100`, `test_310` |
| steward-binding to a human (CC 3.2) | `test_270` / `test_340` setup (`steward_bind`) + `test_360`/`test_361` (admission + minor liveness) |
| namespace / reserved-prefix admission (CC 3.4) | `test_240` |
| delegated, revocable moderation authority (CC 4.5) | `test_270` |
| tamper-evident, hash-chained audit (CC 5.3.1) | `test_320` |
| holder-scoped delivery (no membership ⇒ no delivery) | `test_340` |
| adversarial cost-asymmetry (Sybil floors) | `test_211` |

The suite is the **verification that CEWP's added dimensions are real and non-bypassable** — the checkable engineering tier of the deception-cost argument.

## Honest caveat

CEWP **shifts** the cost; it does not make deception impossible. An adversary controlling enough keys / owners / witnesses can still try — but that is now a concrete cryptographic + economic cost: break the signature scheme, capture the quorum, or Sybil the human-binding. The scaling model's F-AV cost-asymmetry (`test_211`) is precisely the attempt to make that cost large and **measurable**, converting an *unenforceable assumption* (non-adaptive adversary) into an *enforceable cost structure* (break crypto **or** pay the Sybil floor). The within-agent `N_eff` engineering tier and this federation argument are falsifiable; the broader "one structural object recurs across levels" reading is, per the papers, a research bet held openly.

## In one line

**RATCHET measures the within-agent corridor and honestly notes you can stand outside it and adapt; CEWP is the external, cryptographic, multi-party structure that removes that option — and this suite is where you check it did.**
