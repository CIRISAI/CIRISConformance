# CEG is superseded by the CIRIS Constitution

**The CEG ("CIRIS Epistemic Grammar") reference vendored here has been removed
and replaced by the CIRIS Constitution (CC 0.1.3).** See
[`../CIRIS_Constitution/`](../CIRIS_Constitution/).

The Constitution is the canonical governance document: it *incorporates* CEG
1.0-RC29 (the wire grammar — the 1+4 attestation surface is conformance-FROZEN)
and the CIRIS Accord 1.3-RC2 (the ethical layer) into one document with one
version line. The old CEG sections were migrated into it **byte-exact,
intent-faithful, superior** — every wire-normative element is preserved
byte-for-byte (CC README: "C1 byte-exact 18/18 CEG chapters").

## Why this stub exists

This file is left in place (rather than deleting the directory outright) so that
existing in-repo links and test docstrings citing `reference/CEG/...` do not
404, and so the supersession is documented at the old path. New citations should
point at `../CIRIS_Constitution/` and use **CC** section numbers.

## CEG § → CC mapping

The Constitution renumbers every section with a decimal **CC** id and carries a
`legacy_ref` column in [`../CIRIS_Constitution/codebook.json`](../CIRIS_Constitution/codebook.json)
and [`../CIRIS_Constitution/toc.tsv`](../CIRIS_Constitution/toc.tsv) that maps
every CC section back to its CEG (or Accord) source — the renumber is lossless
and auditable. The `codebook.json` / `toc.tsv` bijection is the authoritative,
section-level map; the table below is the chapter-level orientation (CEG chapter
→ CC Part, from the CC README "what folds in" column):

| Old CEG chapter (vendored file)         | CC Part / location                                          |
|-----------------------------------------|-------------------------------------------------------------|
| `00_conformance.md` (§0 — profiles)     | Part II — The Grammar (`part_2_the_grammar.md`)             |
| `01_foundation.md` (§1)                  | Part I — Foundation (`part_1_foundation.md`)                |
| `02_grammar.md` (§2)                     | Part II — The Grammar (`part_2_the_grammar.md`)             |
| `03_primitives.md` (§3)                  | Part II — The Grammar (`part_2_the_grammar.md`)             |
| `04_envelope.md` (§4)                    | Part II — The Grammar (`part_2_the_grammar.md`)             |
| `05_namespace.md` (§5)                   | Part III — The Namespace (`part_3_the_namespace.md`)        |
| `06_relations.md` (§6)                   | Part III — The Namespace (`part_3_the_namespace.md`)        |
| `07_reserved.md` (§7)                    | Part III — The Namespace (`part_3_the_namespace.md`)        |
| `08_composition.md` (§8)                 | Part IV — Composition & Governance (`part_4_composition_governance.md`) |
| `09_humanity_accord.md` (§9)            | Part IV — Composition & Governance (`part_4_composition_governance.md`) |
| `10_endpoints.md` (§10)                  | Part V — Transport & Substrate (`part_5_transport_substrate.md`) |
| `11_governance.md` (§11)                 | Part IV — Composition & Governance (`part_4_composition_governance.md`) |
| `13_anti_patterns.md` (§13)             | Part IV — Composition & Governance (`part_4_composition_governance.md`) |
| `19` (coherence mathematics)            | Part VI — The Coherence Mathematics (`part_6_the_coherence_mathematics.md`) |
| `12_translation.md`, `14_glossaries.md`, `15_gaps.md`, `16_references.md`, `17_cadence.md` | Part VIII — Appendices (`part_8_appendices.md`) + the relevant body Part |

Section-precise example: CEG `§5.6.8.15` (directed-consent replication,
key registration / admission gate) → **CC 3.3.7** (`consent:replication`);
CEG `§5.6.8.8` (self-at-login / identity_occurrence) → **CC 3.3.6**
(`identity_occurrence`). For any other section, look up the CEG `legacy_ref`
in `../CIRIS_Constitution/codebook.json`.

> When updating a test that cites `CEG §X`, prefer the CC citation: find the CC
> section whose `legacy_ref` is `§X` in `codebook.json`, and cite `CC <decimal_id>`.
