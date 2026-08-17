#!/usr/bin/env python3
"""
Cross-wheel substrate benchmarks — the conformance benchmark tier.

We do NOT re-measure the substrate sisters' per-operation costs: CIRISVerify
(`federation_crypto`: hybrid_sign/hybrid_verify/AES-GCM/HKDF), CIRISPersist
(`canonicalize_python`/`ingest_pipeline`/`raw_sqlite_write`/`secrets_*`/`sign_*`)
and CIRISEdge (`envelope_canonicalize`/`dispatch_inbound`/`inline_text_pipeline`/
`content_fetch_roundtrip`) each own those in their own criterion suites, and
those numbers calibrate the CEWP scaling model (ciris.ai/cewp). See
`reference.json`.

What this tier measures that the per-crate criterion benches CANNOT: the
**cross-wheel, Python-boundary, cohabitation-inclusive** cost — what a real
caller pays when the independently-built wheels run together in one Python
process (the production shape: the Chaquopy/Android agent, the cohabiting
runtime). The delta between these and the sister criterion numbers is the
cohabitation + PyO3-FFI tax.

This is **not a pass/fail gate** — shared CI runners are too noisy. Like the
sister `bench.yml` suites, it answers "what are our numbers" and publishes a
JSON + markdown artifact that ciris.ai/cewp can ingest for real figures.

    python3 benchmarks/bench_substrate.py            # markdown to stdout
    python3 benchmarks/bench_substrate.py --json out.json
    python3 benchmarks/bench_substrate.py --quick    # fewer iters (smoke)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import secrets
import sys
import tempfile
import time
import uuid
from pathlib import Path

REFERENCE = json.loads((Path(__file__).resolve().parent / "reference.json").read_text())


def _versions() -> dict:
    import importlib.metadata as m
    out = {}
    for pkg in ("ciris-persist", "ciris-verify", "ciris-edge"):
        try:
            out[pkg] = m.version(pkg)
        except Exception:
            out[pkg] = None
    return out


def measure(fn, *, iters: int, warmup: int) -> dict:
    """Time `fn` over `iters` runs after `warmup`; return min/p50/p95 in ns."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return {
        "min_ns": samples[0],
        "p50_ns": samples[len(samples) // 2],
        "p95_ns": samples[min(int(iters * 0.95), iters - 1)],
        "iters": iters,
    }


def run(quick: bool) -> dict:
    # Import all three sisters so the process carries the real cohabiting
    # cdylibs — this is the production FFI environment we want to cost.
    import ciris_persist as cp
    import ciris_verify  # noqa: F401  (loaded for cohabitation realism)
    from ciris_edge.ciris_edge import init_edge_runtime

    iters_fast = 200 if quick else 5000
    iters_med = 50 if quick else 1000
    warmup = 20 if quick else 300

    d = tempfile.mkdtemp()
    seed = os.path.join(d, "s")
    open(seed, "wb").write(secrets.token_bytes(32))
    # edge v17 (CIRISEdge#458) will not stand up the Reticulum transport on an
    # Ed25519-only signer, and `cohab_init_edge_runtime` below is one of the
    # numbers this bench exists to report. A hybrid signer is also what a real
    # node carries, so the bootstrap cost measured here stays representative.
    pqc_seed = os.path.join(d, "p")
    open(pqc_seed, "wb").write(secrets.token_bytes(32))
    kid_label = "bench-" + secrets.token_hex(6)
    engine = cp.Engine("sqlite::memory:", kid_label, local_key_id=kid_label, local_key_path=seed,
                       local_pqc_key_id=kid_label + "-pqc", local_pqc_key_path=pqc_seed)
    key_id = engine.register_self_federation_key("agent", "bench-ref", None, None, None)
    pk = engine.local_public_key_b64()

    results: dict[str, dict] = {}

    # ── Ed25519 sign (the classical half of the hybrid signature) ──
    msg = secrets.token_bytes(256)
    results["ed25519_sign"] = {
        **measure(lambda: engine.local_sign(msg), iters=iters_fast, warmup=warmup),
        "unit": "per-call",
    }

    # ── hybrid verify (cross-wheel: persist Engine → verify crypto) ──
    sig = base64.b64encode(engine.local_sign(msg)).decode()
    results["hybrid_verify"] = {
        **measure(
            lambda: engine.verify_hybrid(msg, sig, None, pk, None, "ed25519_fallback", None, None),
            iters=iters_med, warmup=warmup,
        ),
        "unit": "per-call",
    }

    # ── canonicalize throughput (ns/byte slope at a representative size) ──
    env = json.dumps({"k%03d" % i: "v" * 64 for i in range(64)})  # ~5 KiB
    env_bytes = len(env.encode())
    canon = measure(lambda: engine.canonicalize_envelope(env), iters=iters_med, warmup=warmup)
    results["canonicalize"] = {
        **canon, "unit": "ns/byte", "payload_bytes": env_bytes,
        "ns_per_byte": round(canon["p50_ns"] / env_bytes, 3),
    }

    # (Raw AES-256-GCM / HKDF / the full hybrid_sign are per-op crypto costs
    # OWNED by CIRISVerify's `federation_crypto` criterion bench — we cite
    # those in reference.json rather than re-measure them through persist's
    # secrets-envelope pipeline, which would conflate per-call key derivation
    # with bulk throughput.)

    # ── put_blob_signing: the cross-wheel COMPOSITE (canonicalize + sign +
    #    store + holder-attestation) — a cohabitation cost no per-crate bench
    #    measures as one call. The headline conformance-tier number. ──
    body = secrets.token_bytes(1024)
    iters_blob = 5 if quick else 30

    def _put_blob():
        content = body + uuid.uuid4().bytes  # unique per call (no blob idempotency)
        sha = hashlib.sha256(content).hexdigest()
        engine.put_blob_signing(
            sha, base64.b64encode(content).decode(), None, None, key_id,
            "2026-05-28T13:45:09.000Z", str(uuid.uuid4()),
        )

    results["put_blob_signing_composite"] = {
        **measure(_put_blob, iters=iters_blob, warmup=2),
        "unit": "per-call",
    }

    # ── cohab init (one-shot bootstrap cost: init_edge_runtime over the real
    #    cohabiting engine). A single clean sample — it is a once-per-process
    #    bootstrap, and repeated init spins up accumulating Reticulum listeners.
    #    Done last (it resets the engine singleton). ──
    cp.reset_engine()
    e2 = cp.Engine("sqlite::memory:", kid_label, local_key_id=kid_label, local_key_path=seed,
                   local_pqc_key_id=kid_label + "-pqc", local_pqc_key_path=pqc_seed)
    idp = os.path.join(tempfile.mkdtemp(), "t.id")
    open(idp, "wb").write(b"\x00" * 64)
    t0 = time.perf_counter_ns()
    init_edge_runtime(e2, idp, listen_addr="127.0.0.1:0")
    dt = time.perf_counter_ns() - t0
    results["cohab_init_edge_runtime"] = {
        "min_ns": dt, "p50_ns": dt, "p95_ns": dt, "iters": 1, "unit": "one-shot",
    }

    return {
        "schema": "ciris-conformance/bench/1",
        "platform": {
            "system": platform.system(), "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "wheels": _versions(),
        "results": results,
        "reference": REFERENCE["per_op_reference"],
        "note": "results = cross-wheel Python-boundary cost (FFI + cohabitation "
                "inclusive); reference = sister-repo criterion per-op costs. The "
                "delta is the cohabitation/FFI tax. Not a pass/fail gate.",
    }


def to_markdown(report: dict) -> str:
    p = report["platform"]
    w = report["wheels"]
    lines = [
        "# CIRISConformance — cross-wheel substrate benchmarks",
        "",
        f"_{p['system']} {p['machine']} · Python {p['python']} · "
        f"persist {w['ciris-persist']} / verify {w['ciris-verify']} / edge {w['ciris-edge']}_",
        "",
        "Cross-wheel, Python-boundary cost (FFI + cohabitation inclusive). The "
        "per-op reference column is the sister-repo criterion number the CEWP "
        "model is calibrated against — the gap is the cohabitation/FFI tax. "
        "**Not a pass/fail gate.**",
        "",
        "| Operation | p50 | min | unit | sister reference |",
        "|---|---|---|---|---|",
    ]
    refmap = {
        "ed25519_sign": "hybrid_sign 466µs (full Ed25519+ML-DSA-65; this row is Ed25519-only)",
        "hybrid_verify": "276µs (full hybrid)",
        "canonicalize": "250 ns/KiB ≈ 0.244 ns/byte",
        "put_blob_signing_composite": "no per-crate equivalent — the cohabitation composite",
        "cohab_init_edge_runtime": "—",
    }
    for name, r in report["results"].items():
        if "unavailable" in r:
            lines.append(f"| `{name}` | _unavailable_ | — | — | {r['unavailable']} |")
            continue
        if "ns_per_byte" in r:
            p50 = f"{r['ns_per_byte']} ns/byte"
            mn = f"{round(r['min_ns'] / r['payload_bytes'], 4)} ns/byte"
        else:
            p50 = f"{r['p50_ns'] / 1000:.2f} µs"
            mn = f"{r['min_ns'] / 1000:.2f} µs"
        lines.append(f"| `{name}` | {p50} | {mn} | {r['unit']} | {refmap.get(name, '—')} |")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", metavar="PATH", help="write the JSON report to PATH")
    ap.add_argument("--quick", action="store_true", help="fewer iterations (smoke)")
    args = ap.parse_args()

    report = run(quick=args.quick)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        sys.stderr.write(f"wrote {args.json}\n")
    print(to_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
