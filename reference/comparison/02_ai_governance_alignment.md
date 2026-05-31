# CEWP vs. AI governance & alignment approaches

CEWP treats alignment as **epistemic governance with cryptographic
accountability** — a runtime property of a federation, not a training-time
property of a model. This compares it against the standard alignment /
AI-governance framings. Source: CEWP.md §1, §6, §9.

## The framings, and what each lacks

| Approach | What it does | Structural gap CEWP fills |
|---|---|---|
| **RLHF / Constitutional AI** | Align at training time | The shipped model is the deployer's; alignment is opaque to everyone else; users/governments have no recourse post-deployment; one model for all contexts/jurisdictions |
| **Scalable oversight** (AI assists humans evaluating AI) | Stretch human review | The oversight has **no cryptographic accountability surface** — "AI evaluated AI" can be asserted, not proved; assistant misalignment is unobservable |
| **Mechanistic interpretability** | Understand model internals | Necessary for safety research, but understanding "why X" does not make "X was right" *enforceable*; produces no governance system |
| **Top-down regulation** (EU AI Act, UN advisory) | Set rules, require compliance | **No enforcement substrate** — audits produce text documents, not attestation chains; cross-jurisdiction enforcement is structurally weak |
| **Web3-AI** (compute/data marketplaces) | Decentralize compute/model access | Solves a different problem; produces no governance over the AI's *reasoning* or *outputs* |
| **CEWP** | Alignment as runtime epistemic governance | Every load-bearing claim is a signed wire artifact; trust is computed from the attestation graph; misaligned actions become slashable; deference + reconsideration are first-class |

## The mechanism, dimension by dimension

| Dimension | Centralized-lab / regulation default | CEWP |
|---|---|---|
| **Where alignment lives** | Inside pre-training (RLHF) / inside a regulator's text | In the federation's runtime trust graph (`weighted_aggregate` over `scores`) |
| **Identity** | Administrative / account-based | Cryptographic — every agent carries an Ed25519 + ML-DSA-65 federation key, same shape as humans |
| **Accountability of a claim** | Behavior is opaque; "it said X" | Epistemic claims are attestable: "I assert X, conf 0.8, these citations" is a checkable, scorable, disputable wire artifact |
| **Enforcement** | Deplatform (platform-internal) / fines (slow, jurisdictional) | `ModerationEvent` → witness aggregation → WA-quorum `SlashingAttestation` → trust drop → admission gate tightens → eviction sweeper drops content |
| **Reversibility** | Ad hoc appeals | `ReconsiderationRequest` → WA review → `ReconsiderationAttestation` — structural, the substrate doesn't ossify mistakes |
| **Human-in-the-loop** | Modal "press OK" / none | `DeferralRequest` routes to the collectively-recognized experts in the relevant (domain, language) cell, with audit trail + expertise-weighted routing |
| **Who decides** | 5–10 labs / one regulator | The federation collectively; no top of the oversight chain; every participant is reviewer-and-reviewed |
| **Drift detection** | Post-mortem, deployer-internal | LensCore detectors run continuously over the consented trace stream; misalignment shows up as measurable reasoning-shape regression, observable to any operator |

## The superalignment claim, against scalable oversight

Scalable oversight assumes a human reviewer at the top of the chain — the
oversight ratio craters as capability grows. CEWP's answer is **distributed
epistemic governance**: no top; capability growth doesn't break the ratio
because every participant (human or agent) is both reviewer and reviewed,
and more-capable agents *participate* more capably (better attestations,
better detection, better deferral judgment) — capability feeds governance
robustness rather than evasion. The bet is empirical:
[*Corridor Dynamics in Coordinated Systems*](../synthesis/Corridor_Dynamics.tex)
— that reasoning has a measurable shape (the ρ / k_eff corridor), so the
federation's collective measurement of that shape can substitute for a
centralized alignment authority.

## Where the prior art is genuinely better

The honest peer-strength admission — and the strongest objection a critic
will raise:

- **Training-time methods shape *capability and disposition*; runtime
  governance can only *sanction*.** RLHF / Constitutional AI / RLAIF act on
  the model's actual propensities before it ever emits a token. CEWP's trust
  graph + moderation + slashing operate on *emitted, attested* behavior —
  *after the fact*. Against a **competently-misaligned** system (one that
  models the governance layer and routes around it), post-hoc sanction is a
  weaker lever than having shaped the disposition in the first place. CEWP
  reduces the *value* of misbehaving and makes it *observable and
  reversible*, but it does not make a capable adversary *unable* to
  misbehave. Training-time alignment, where it works, is the stronger
  guarantee — and CEWP depends on it remaining a live input, not a replaced
  one.
- **Mechanistic interpretability** offers something CEWP structurally
  cannot: a window into *why*, not just *what was claimed*. A maturing
  interp toolkit could catch deceptive cognition that never surfaces as a
  flawed epistemic claim — exactly CEWP's blind spot (it governs claims, and
  a sufficiently capable deceiver emits clean-looking claims).
- **Centralized labs** ship faster and more coherently on frontier
  capability + first-pass safety tuning; a federation's distributed
  governance is slower to converge than a single team's decision.

CEWP's bet is that *at the population and time scales that matter*, an
observable, reversible, distributed governance layer beats an opaque,
unaccountable, centralized one — **not** that runtime governance dominates
training-time alignment head-to-head. The two are complementary; the
honest framing is "governance the field lacks," not "alignment solved."

## What CEWP does **not** claim (honest limits)

- It does **not** solve alignment. The substrate is necessary, not sufficient; bad actors still try, misalignment still occurs — the federation's *response* is the difference (CEWP §9).
- It does **not** replace training-time methods. RLHF/Constitutional AI become one historical *input*; the runtime trust graph becomes the live surface. Frontier-model *training* stays where it is.
- It does **not** claim capability and governance scale at the same rate forever — a capability discontinuity could outpace the governance signal; CEWP is part of an ongoing program, not its end.
- The distributed trace commons depends on **consented** traces (privacy-preserving schemas, scrub-before-store); it is not transcript surveillance.

## Sources

- CEWP.md §1 (the framings) · §6 (detection/moderation/reconsideration) · §9 (superalignment claims + non-claims)
- [Corridor Dynamics synthesis](../synthesis/research_status_entry.md) (DOI 10.5281/zenodo.20300774)
- Comparative analysis context: [CIRISAgent/docs/COMPARATIVE_ANALYSIS.md](https://github.com/CIRISAI/CIRISAgent/blob/main/docs/COMPARATIVE_ANALYSIS.md)
