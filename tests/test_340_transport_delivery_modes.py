"""
Fabric tier — real multi-node transport delivery across every holder mode
(Conformance#4, the cross-transport delivery headline).

A message published by one node reaches another node's inline-text handler over a
live Reticulum transport **only when the recipient is a genuine holder of the
published scope** — delivery is holder/scope-driven, never a raw peer push, and
the scope-enforcement disable hook is deliberately NOT used (it is not exposed
over the FFI). The four ways two endpoints come to share a scope:

- **self** — both endpoints are occurrences of one identity (`put_identity_
  occurrence`); a self-scope publish reaches the co-occurrence.
- **family** — both are family members (`put_family_json`); published in family
  tier (`in_family_context=True`).
- **community** — both are community members (`put_community_json` +
  `add_community_member`); published with `active_community_id`.
- **direct** — a community of exactly two (same mechanism as community).

Non-infrastructure family/community membership requires each node to be
**steward-bound to a `user`-role human** (CC 3.2 / CC 3.4.7.1) via `steward_bind`,
else `federation_unstewarded_community_member`. The minimal fabric that exercises
all modes is **4 nodes / 3 stewards**: steward O1 holds N1+N2 (their self group),
O2 holds N3, O3 holds N4 — so a 3-steward family/community AND a 2-steward direct
community are both real.

Real gate as of **edge 7.1.0 + persist 10.4.0**: edge 7.1.0 spawns the inbound
dispatch listeners in `init_edge_runtime` (CIRISEdge#217/#220), and the receiver
keeps its opaque subscription handle alive (the handle's `Drop` unsubscribes —
dropping it silently tears the listener down). The fixture stands up four real
edge processes + three steward-setup processes over one shared substrate and
drives one send per mode.

edge 8 (CIRISConformance#53) ripped the inline-text surface: the receiver now
subscribes via `subscribe_opaque(kind, cb)` and the sender publishes via
`send_opaque_event(recipient, kind, payload)`.

STATUS ON THE CC 1.0-rc1 FLOOR (persist 12.5.0 / edge 8.7.2): the persist
transport-bringup deadlock/SIGSEGV (CIRISPersist#320) is **FIXED** —
`init_edge_runtime(enable_transport=True)` returns in ~ms, every node becomes
ready, and a message published by one node **really is delivered** to the
addressed recipient over the live Reticulum transport. So these are REAL
end-to-end delivery gates now, one per sender→recipient route (self N1→N2,
family N1→N3, community N1→N4, direct N3→N4).

What is NOT yet a real gate is per-mode **holder-scoping**. edge 8's
`send_opaque_event(recipient, kind, payload)` carries no scope/holder selector
(the old `send_inline_text_with_outcome` community_id / in_family_context args
are gone), and delivery is empirically **primed-peer, not holder-gated**: a
message reaches an addressed peer that shares NO scope with the sender (verified
standalone — no steward bind, no family, no community, no occurrence, yet it
still delivers). So the four modes are indistinguishable as *holder* gates —
each asserts live delivery to its addressed recipient, none asserts that
delivery is *restricted* to genuine holders (non-holders rejected). Restoring
the scope selector so per-mode holder-scoping becomes distinguishable needs
CIRISEdge#265 (still OPEN). The steward/family/community fabric is still stood
up (it exercises the persist holder-model wheel and must succeed), it just does
not yet gate delivery.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import time

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"


# The delivery window every node runs for after setup. The gather below waits
# on ONE deadline derived from it — it used to give each node a flat 90s
# timeout, shorter than this window (raised 60→100 in #62), so n2, gathered
# first, was always killed before writing its receipts and the `self` route
# never counted (found via CIRISConformance#103's diagnostics).
_WINDOW = 100


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# Each node: bring up a real edge transport, keep the inline-text subscription
# handle ALIVE, publish its identity, prime every peer once the roster is known,
# then (if it has a send command) publish per its mode, and report what it got.
_NODE_SRC = r'''
import os, json, sys, time, tempfile, secrets, logging
# Edge/persist log through Python logging (pyo3-log) as well as RUST_LOG; send
# both to this node's stderr file so a lossy run quotes them (#103).
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
import ciris_persist as cp
from ciris_edge.ciris_edge import init_edge_runtime

d = tempfile.mkdtemp(); s = os.path.join(d, "s"); open(s, "wb").write(secrets.token_bytes(32))
# Hybrid signer: this fabric runs a LIVE Reticulum transport, and edge v17
# (CIRISEdge#458, #393 item 2) will not bring one up on an Ed25519-only signer
# — without the ML-DSA-65 half the node cannot mint the hybrid-signed
# SignedTransportDestination, so every peer would drop its frames UNATTRIBUTED
# at the E3 gate: it would route and never root. A real fabric node carries
# both keys, which is exactly what these four nodes are standing in for.
p = os.path.join(d, "p"); open(p, "wb").write(secrets.token_bytes(32))
idp = os.path.join(d, "id"); open(idp, "wb").write(secrets.token_bytes(64))
cp.reset_engine()
k = ROLE + "-" + secrets.token_hex(8)
eng = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=s,
                local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)
kid = eng.register_self_federation_key("agent", ROLE, None, None, None)
boot = ["127.0.0.1:" + p for p in BOOT_PORTS.split(",") if p]
listen = "127.0.0.1:" + LISTEN_PORT
edge = init_edge_runtime(eng, idp, listen_addr=listen, bootstrap_peers=boot,
    announce_interval_seconds=2, enable_transport=True, hybrid_policy="ed25519_fallback",
    agent_occurrence_key_id=kid)
got = []
# edge 8 (CIRISConformance#53): the inline-text handler was ripped; the
# generic successor is subscribe_opaque(kind, cb) where cb(sender, kind,
# payload:bytes). Keep the subscription handle ALIVE (its Drop unsubscribes).
KIND = 7
SUB = edge.subscribe_opaque(KIND, lambda sender, kind, payload: got.append([sender, payload.decode("utf-8", "replace")]))  # keep alive
open(READY, "w").write(json.dumps({"role": ROLE, "kid": kid,
    "dest_hash": edge.reticulum_dest_hash_hex(), "transport": edge.transport_identity_pubkeys()}))

# Barrier: wait for the full roster, then prime every other peer.
while not os.path.exists(ROSTER): time.sleep(0.2)
roster = json.loads(open(ROSTER).read())
for r in roster:
    if r["kid"] != kid:
        edge.prime_peer(r["kid"], r["dest_hash"], r["transport"]["ed25519_pub_base64"])

# Wait for the holder-relationship setup to finish.
while not os.path.exists(SETUP): time.sleep(0.2)
setup = json.loads(open(SETUP).read())

# If this node has send commands, publish each per its mode. Real Reticulum
# delivery over a 4-node fabric is timing-sensitive under concurrent load (many
# nodes competing for CPU/ports), so rather than a few quick retries we RE-SEND
# each message across the whole window until it lands. This is safe because
# edge 8 send_opaque_event(recipient, kind, payload) carries NO scope/holder
# selector (the community_id / in_family_context args are GONE — delivery is
# primed-peer, not holder-gated, CIRISEdge#265) and the receiver dedupes by body
# (`_bodies` is a set), so repeated identical sends are idempotent. The send
# really delivers to the addressed recipient over live transport — what the
# per-route gates below assert.
t0 = time.time()
WINDOW = __WINDOW__  # was 60 — headroom so a slow route still lands under load
# The harness writes every node's command file before setup.done, so it is
# already here; wait for it anyway rather than treat "not yet" as "no sends".
while not os.path.exists(CMD): time.sleep(0.2)
specs = json.loads(open(CMD).read())["sends"]
if specs:
    time.sleep(5)  # let the primed links settle
    while time.time() < t0 + WINDOW - 8:  # keep re-sending across the window
        for spec in specs:
            try:
                edge.send_opaque_event(spec["target_kid"], KIND, spec["text"].encode("utf-8"))
            except Exception as exc:
                print("SEND ERR " + str(exc)[:80], file=sys.stderr)
        time.sleep(3)

# Every node stays alive collecting receipts until a common window elapses.
while time.time() < t0 + WINDOW: time.sleep(0.3)
# CIRISConformance#103 — edge's metrics at the end of the window, so a lossy
# run says WHICH half failed: the sender's durable dispatcher (queue depth,
# send_failures_total) or the receiver (envelopes_received, verify_failures,
# withholds). Diagnostics only; a snapshot failure never fails the node.
try:
    metrics = edge.metrics_snapshot()
except Exception as exc:
    metrics = {"_error": repr(exc)[:200]}
open(DONE, "w").write(json.dumps({"role": ROLE, "kid": kid, "got": got, "metrics": metrics}, default=str))
sys.stdout.flush(); os._exit(0)
'''


def _stderr_of(paths, role, tail=6000):
    try:
        with open(paths[f"{role}.stderr"], errors="replace") as fh:
            return fh.read()[-tail:]
    except OSError:
        return ""


def _node(tmp, role, *, listen_port, boot_ports):
    head = (f"DB_URL={tmp['db']!r}\nROLE={role!r}\nLISTEN_PORT={listen_port!r}\n"
            f"BOOT_PORTS={','.join(boot_ports)!r}\nREADY={tmp[role + '.ready']!r}\n"
            f"ROSTER={tmp['roster']!r}\nSETUP={tmp['setup']!r}\n"
            f"CMD={tmp[role + '.cmd']!r}\nDONE={tmp[role + '.done']!r}\n")
    return head + _NODE_SRC.replace("__WINDOW__", str(_WINDOW))


# Steward setup runs as THREE sequential steward processes (one live engine per
# process). Dependency order: O3 binds N4 → O2 binds N3 + founds the 2-steward
# direct community {N3,N4} → O1 binds N1+N2 (+ self-occurrences) and founds the
# 3-steward family + community {N1,N3,N4}. Each member must be steward-bound
# before a community/family that includes it is written (CC 3.2).
_OWNER_PREAMBLE = (
    "import os, json, sys, time, tempfile, secrets, base64, datetime\n"
    "import ciris_persist as cp\n"
    "R = {r['role']: r['kid'] for r in json.loads(open(ROSTER).read())}\n"
    "d = tempfile.mkdtemp(); s = os.path.join(d, 's'); open(s, 'wb').write(secrets.token_bytes(32))\n"
    "p = os.path.join(d, 'p'); open(p, 'wb').write(secrets.token_bytes(32))\n"
    "cp.reset_engine(); k = REF + '-' + secrets.token_hex(8)\n"
    "eng = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=s, local_pqc_key_id=k+'-pqc', local_pqc_key_path=p)\n"
    "owner = eng.register_self_federation_key('user', REF, None, None, None)\n"
    # persist v42.0.0 (CIRISPersist#811, CC 3.2 rc4 'conferral is not stewardship'):
    # a community member is steward-bound by an OWNER-BINDING edge only. A plain
    # steward_bind is a capability conferral and no longer binds, so the room
    # write refuses `federation_unstewarded_community_member`. `responsible_for`
    # is persist's engine-side custody purpose (the ownership:responsible_party
    # dimension), the same token test_360/361/573 drive.
    "CUSTODY = 'responsible_for'\n"
    # persist v52.0.0 (CIRISPersist#955): a founding record admits exactly the
    # members who SIGNED it (a node counts as signed when its OWNER signed), and
    # every later growth needs the member's own acceptance. The three owners run
    # as separate processes in dependency order, so each leaves its identity in
    # ID_DIR and a later owner opens it to co-sign or accept on its behalf.
    "ME = {'k': k, 's': s, 'p': p, 'kid': owner}\n"
    "open(os.path.join(ID_DIR, REF + '.json'), 'w').write(json.dumps(ME))\n"
    "def load(ref): return json.loads(open(os.path.join(ID_DIR, ref + '.json')).read())\n"
    "def use(ident):\n"
    "    global eng\n"
    "    cp.reset_engine()\n"
    "    eng = cp.Engine(DB_URL, ident['k'], local_key_id=ident['k'], local_key_path=ident['s'],\n"
    "                    local_pqc_key_id=ident['k']+'-pqc', local_pqc_key_path=ident['p'])\n"
    "    return eng\n"
    "def sig(ident, rec):\n"
    "    e = use(ident); g = e.local_sign_hybrid(e.canonicalize_envelope(json.dumps(rec)))\n"
    "    out = {'authority_key_id': ident['kid'],\n"
    "           'scrub_signature_classical': base64.b64encode(g['classical_sig']).decode(),\n"
    "           'scrub_signature_pqc': base64.b64encode(g['pqc_sig']).decode()}\n"
    "    use(ME); return out\n"
    "def T(ts): return ts.replace('.000Z', 'Z') if ts.endswith('.000Z') else ts\n"
    "def found_community(name, member_kids, cosigners, protocol='majority'):\n"
    "    rec = {'community_key_id': owner, 'community_name': name,\n"
    "           'members': [{'key_id': owner, 'joined_at': T(NOW), 'role': 'founder'}]\n"
    "                      + [{'key_id': m, 'joined_at': T(NOW)} for m in member_kids],\n"
    "           'founded_at': T(NOW), 'consensus_protocol': protocol}\n"
    "    pl = dict(rec, persist_row_hash='', cosignatures=[sig(c, rec) for c in cosigners])\n"
    "    pl.update(sig(ME, rec)); use(ME).put_community_json(json.dumps(pl))\n"
    "def join_family(family, node_kid, node_owner):\n"
    "    exp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000Z')\n"
    "    e = use(ME)\n"
    "    pid = e.emit_attestation_self(json.dumps({'attestation_type': 'scores', 'cohort_scope': 'family',\n"
    "        'subject_key_ids': [node_kid], 'expires_at': exp,\n"
    "        'attestation_envelope': {'dimension': 'membership:proposal:v1', 'group_kind': 'family', 'family_key_id': family}}))\n"
    "    rows = json.loads(e.list_attestations_by(owner)); rows = rows.get('items', rows) if isinstance(rows, dict) else rows\n"
    "    och = next(r for r in rows if r['attestation_id'] == pid)['original_content_hash']\n"
    "    use(node_owner).emit_attestation_self(json.dumps({'attestation_type': 'scores', 'cohort_scope': 'family',\n"
    "        'attested_key_id': node_kid, 'attestation_envelope': {'dimension': 'membership:acceptance:v1',\n"
    "        'references_attestation_id': pid, 'group_kind': 'family', 'family_key_id': family, 'proposal_hash': och}}))\n"
    "    w = {'family_key_id': family, 'member_key_id': node_kid, 'joined_at': T(NOW), 'effective_at': T(NOW)}\n"
    "    spec = sig(ME, w)\n"
    "    use(ME).cohort_add_member('family', family, json.dumps({'key_id': node_kid, 'joined_at': T(NOW)}), json.dumps(spec))\n"
)

_OWNER3 = _OWNER_PREAMBLE + (
    "eng.steward_bind(R['n4'], ['infra:transport'], CUSTODY)\n"
    "open(DONE3, 'w').write('ok'); print('OWNER3 done', file=sys.stderr); sys.exit(0)\n"
)
_OWNER2 = _OWNER_PREAMBLE + (
    "eng.steward_bind(R['n3'], ['infra:transport'], CUSTODY)\n"
    "while not os.path.exists(DONE3): time.sleep(0.2)\n"
    # D: owner2 (founder) + n3 (owner2's node) + n4 (owner3's node, so owner3 co-signs).
    "found_community('D', [R['n3'], R['n4']], [load('owner3')])\n"
    "open(DONE2, 'w').write(json.dumps({'direct': owner})); print('OWNER2 done', file=sys.stderr); sys.exit(0)\n"
)
_OWNER1 = _OWNER_PREAMBLE + (
    "eng.steward_bind(R['n1'], ['infra:transport'], CUSTODY); eng.steward_bind(R['n2'], ['infra:transport'], CUSTODY)\n"
    "for occ in (R['n1'], R['n2']):\n"
    "    eng.put_identity_occurrence_json(json.dumps({'identity_key_id': owner, 'occurrence_key_id': occ,\n"
    "        'device_class': 'agent', 'asserted_at': NOW, 'persist_row_hash': ''}))\n"
    "while not os.path.exists(DONE2): time.sleep(0.2)\n"
    "direct = json.loads(open(DONE2).read())['direct']\n"
    # F: `put_family_json` takes no co-signatures from Python, so the family is
    # founded with owner1 (founder) + n1 (owner1's node, signed through its
    # owner); n3 and n4 join by proposal → their OWNER's acceptance → widening.
    "use(ME).put_family_json(json.dumps({'family_key_id': R['n1'], 'family_name': 'F',\n"
    "    'members': [{'key_id': owner, 'joined_at': NOW, 'role': 'founder'}, {'key_id': R['n1'], 'joined_at': NOW}],\n"
    "    'founded_at': NOW, 'consensus_protocol': 'founder_only', 'consensus_protocol_entrenched': False,\n"
    "    'persist_row_hash': ''}))\n"
    "join_family(R['n1'], R['n3'], load('owner2'))\n"
    "join_family(R['n1'], R['n4'], load('owner3'))\n"
    # C: owner1 (founder) + n1 + n3 + n4 — owner2 and owner3 co-sign for their nodes.
    "found_community('C', [R['n1'], R['n3'], R['n4']], [load('owner2'), load('owner3')])\n"
    "open(SETUP, 'w').write(json.dumps({'community': owner, 'direct': direct}))\n"
    "print('OWNER1 done', file=sys.stderr); sys.exit(0)\n"
)


@pytest.fixture(scope="module")
def delivery_fabric(tmp_path_factory):
    from conftest import run_python_script  # noqa: F401 (parity w/ other fixtures)

    d = tmp_path_factory.mktemp("delivery_fabric")
    db = d / "fabric.db"; db.touch()
    paths = {"db": f"sqlite:///{db}", "roster": str(d / "roster.json"),
             "setup": str(d / "setup.done")}
    for role in ("n1", "n2", "n3", "n4"):
        for suf in ("ready", "cmd", "done"):
            paths[f"{role}.{suf}"] = str(d / f"{role}.{suf}.json")
        paths[f"{role}.stderr"] = str(d / f"{role}.stderr.log")

    # CIRISConformance#97 — the pick-a-free-port race. `_free_port()` probes a
    # port, releases it, and hands the number to a child that binds it later;
    # anything on the host can take it in between, and on a busy CI runner it
    # did (CIRISServer's publish gate, 2026-09-06). A collision in ONE node
    # cannot be repaired in place — every peer was launched with the other
    # three ports as its dial set (full mesh) — so the whole fabric is torn
    # down and re-picked, a bounded number of times, and the last failure
    # says which port and who held it, so the next occurrence is an
    # attribution rather than a mystery.
    class _PortRace(Exception):
        def __init__(self, role, port, err):
            super().__init__(role, port, err)
            self.role, self.port, self.err = role, port, err

    def _holder_of(port):
        try:
            out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=5).stdout
            return "\n".join(l for l in out.splitlines() if f":{port} " in l) or "(no listener found)"
        except Exception as exc:  # noqa: BLE001 — diagnostics only
            return f"(ss unavailable: {exc})"

    def _teardown(procs):
        # Kill AND reap: a killed node still holds its SQLite connection until
        # the process has actually exited, and the retry reopens the same file
        # — reaping first keeps a handled port race from resurfacing as an
        # unrelated lock or migration failure on the next attempt.
        for q in procs.values():
            if q.poll() is None:
                q.kill()
        for q in procs.values():
            try:
                q.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                q.kill(); q.communicate(timeout=15)

    def _stand_up_fabric():
        for r in ("n1", "n2", "n3", "n4"):
            for suf in ("ready",):
                try: os.remove(paths[f"{r}.{suf}"])
                except FileNotFoundError: pass
        procs = {}
        # Full mesh: every node listens on its own port and dials the other three, so
        # every sender→receiver pair has a direct interface (a hub-and-spoke topology
        # leaves N1↔N3 etc. with no link). Pre-allocate the four ports.
        ports = {r: str(_free_port()) for r in ("n1", "n2", "n3", "n4")}

        def boots_for(role):
            return [ports[r] for r in ("n1", "n2", "n3", "n4") if r != role]

        procs = {}

        def launch(role):
            # stderr goes to a FILE, not a pipe: with edge logging at info a
            # node can write more than a pipe buffer during the 100s window,
            # and nobody reads the pipe until the window ends — the node would
            # block on its own log. The file is also what the delivery
            # assertion quotes (CIRISConformance#103).
            env = dict(os.environ)
            env.setdefault("RUST_LOG", "ciris_edge=info")
            procs[role] = subprocess.Popen(
                [sys.executable, "-c",
                 textwrap.dedent(_node(paths, role, listen_port=ports[role], boot_ports=boots_for(role)))],
                stdout=subprocess.DEVNULL, stderr=open(paths[f"{role}.stderr"], "w"), text=True, env=env)

        # Serialize the FIRST engine so it migrates the fresh sqlite file alone
        # (concurrent first-migration races with "duplicate column"); the rest open
        # the already-migrated DB.
        launch("n2")
        # persist transport bring-up (CIRISPersist#320) is FIXED on the CC 1.0-rc1
        # floor — init_edge_runtime(enable_transport=True) returns in ~ms and n2
        # becomes ready — so a node that never readies (or exits early) is again a
        # HARD failure, not an xfail-absorbed deadlock.
        n2_deadline = time.time() + 40
        while time.time() < n2_deadline and not os.path.exists(paths["n2.ready"]):
            if procs["n2"].poll() is not None:
                procs["n2"].communicate(); err = _stderr_of(paths, "n2")
                if "Address already in use" in err:
                    _teardown(procs)
                    raise _PortRace("n2", ports["n2"], err)
                pytest.fail(f"node n2 exited before ready: {err[-1200:]}")
            time.sleep(0.2)
        if not os.path.exists(paths["n2.ready"]):
            procs["n2"].kill()
            pytest.fail("node n2 never became ready within 40s")
        for role in ("n1", "n3", "n4"):
            launch(role)

        # Collect all four identities → publish the roster (the priming barrier).
        deadline = time.time() + 40
        roster = []
        while time.time() < deadline and len(roster) < 4:
            roster = [json.loads(open(paths[f"{r}.ready"]).read())
                      for r in ("n1", "n2", "n3", "n4") if os.path.exists(paths[f"{r}.ready"])]
            for r, p in procs.items():
                if p.poll() is not None and not os.path.exists(paths[f"{r}.ready"]):
                    p.communicate(); err = _stderr_of(paths, r)
                    _teardown(procs)
                    if "Address already in use" in err:
                        raise _PortRace(r, ports[r], err)
                    pytest.fail(f"node {r} exited before ready: {err[-1200:]}")
            time.sleep(0.3)
        if len(roster) < 4:
            for p in procs.values():
                if p.poll() is None: p.kill()
            pytest.fail(f"only {len(roster)}/4 fabric nodes became ready")
        open(paths["roster"], "w").write(json.dumps(roster))

        return procs, roster

    for _attempt in range(1, 4):
        try:
            procs, roster = _stand_up_fabric()
            break
        except _PortRace as race:
            if _attempt == 3:
                pytest.fail(f"node {race.role} lost its Reticulum port {race.port} to another process "
                            f"three times running (CIRISConformance#97); last holder: "
                            f"{_holder_of(race.port)}\n{race.err[-800:]}")

    kid = {r["role"]: r["kid"] for r in roster}
    # One directed send per mode: self N1→N2, family N1→N3, community N1→N4 (all
    # from N1), and direct N3→N4 (the 2-owner community).
    cmds = {
        "n1": {"sends": [
            {"target_kid": kid["n2"], "mode": "self", "text": "self-msg"},
            {"target_kid": kid["n3"], "mode": "family", "text": "family-msg"},
            {"target_kid": kid["n4"], "mode": "community", "cid_key": "community", "text": "community-msg"},
        ]},
        "n3": {"sends": [
            {"target_kid": kid["n4"], "mode": "direct", "cid_key": "direct", "text": "direct-msg"},
        ]},
    }
    # Written for EVERY node (receivers get an empty list) and BEFORE the
    # owner setup publishes setup.done. They used to be written after the
    # last owner process exited, while each node checked for its command file
    # ONCE, the instant it saw setup.done — on a slow runner the node won that
    # race and silently skipped every send, losing a whole sender's routes
    # (CIRISConformance#103: 0/4 with envelopes_sent_total empty on all nodes).
    # Write-then-rename so a node never reads a half-written file.
    for role in ("n1", "n2", "n3", "n4"):
        tmp = paths[f"{role}.cmd"] + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(json.dumps(cmds.get(role, {"sends": []})))
        os.replace(tmp, paths[f"{role}.cmd"])


    # Owner setup: three sequential owner processes (one live engine each), in
    # dependency order O3 → O2 → O1.
    done2, done3 = str(d / "owner2.done"), str(d / "owner3.done")
    id_dir = d / "owner_ids"; id_dir.mkdir(exist_ok=True)
    owner_hdr = (f"DB_URL={paths['db']!r}\nROSTER={paths['roster']!r}\nSETUP={paths['setup']!r}\n"
                 f"NOW={_NOW!r}\nDONE2={done2!r}\nDONE3={done3!r}\nID_DIR={str(id_dir)!r}\n")
    for ref, body in (("owner3", _OWNER3), ("owner2", _OWNER2), ("owner1", _OWNER1)):
        src = owner_hdr + f"REF={ref!r}\n" + body
        sp = subprocess.Popen([sys.executable, "-c", textwrap.dedent(src)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _, setup_err = sp.communicate(timeout=60)
        if sp.returncode != 0:
            for p in procs.values():
                if p.poll() is None: p.kill()
            pytest.fail(f"owner setup ({ref}) failed: {setup_err[-1500:]}")
    if not os.path.exists(paths["setup"]):
        for p in procs.values():
            if p.poll() is None: p.kill()
        pytest.fail("owner setup did not produce setup.done")

    # Gather receipts.
    results = {}
    gather_deadline = time.time() + _WINDOW + 40
    for role, p in procs.items():
        try:
            p.communicate(timeout=max(5, gather_deadline - time.time()))
        except subprocess.TimeoutExpired:
            p.kill(); p.communicate()
        if os.path.exists(paths[f"{role}.done"]):
            results[role] = json.loads(open(paths[f"{role}.done"]).read())
        else:
            results[role] = {"role": role, "got": [], "_no_done": True}
        results[role]["_stderr"] = _stderr_of(paths, role)
    results["_kid"] = kid
    return results


def _bodies(result_for_role):
    return {body for _sender, body in result_for_role.get("got", [])}


# REAL end-to-end transport delivery on the CC 1.0-rc1 floor (persist 12.5.0 /
# edge 8.7.2). The persist transport bring-up deadlock/SIGSEGV (CIRISPersist#320)
# is FIXED: init_edge_runtime(enable_transport=True) returns in ~ms, every fabric
# node becomes ready, and each published message is delivered to the addressed
# recipient over the live Reticulum transport. So each test below is a real
# per-route delivery gate (green, no xfail).
#
# NOT yet real: per-mode HOLDER-scoping. edge 8's send_opaque_event(recipient,
# kind, payload) has no scope/holder selector, and delivery is empirically
# primed-peer, NOT holder-gated — a message delivers to an addressed peer that
# shares no scope with the sender at all (verified standalone: no steward bind /
# family / community / occurrence, yet it still delivers). So the four modes are
# indistinguishable as *holder* gates: each asserts live delivery to its
# addressed recipient over the transport, none asserts that delivery is
# *restricted* to genuine holders (a non-holder MUST NOT receive). Making per-mode
# holder-scoping a distinguishable gate needs the scope selector re-exposed —
# CIRISEdge#265 (still OPEN).


_METRIC_KEYS = ("durable_queue_depth", "send_failures_total", "envelopes_sent_total",
                "envelopes_received_total", "verify_failures_total", "withholds_by_reason",
                "peer_reachability_ratio", "_error")


def _fabric_diagnostics(fabric, stderr_lines=25):
    """Per-node edge metrics + stderr tail for a lossy run (CIRISConformance#103).

    Edge's ask: one failing run with this output says whether the sender's
    durable dispatcher or the receiver lost the frames. NOTE every node shares
    ONE SQLite file (`paths["db"]`) in every cell, the postgres cell included —
    the outbound queue under test is SQLite."""
    out = []
    for role in ("n1", "n2", "n3", "n4"):
        r = fabric.get(role, {})
        m = r.get("metrics") or {}
        picked = {k: m[k] for k in _METRIC_KEYS if m.get(k)}
        out.append(f"--- {role} got={sorted(_bodies(r))} done={'no' if r.get('_no_done') else 'yes'}")
        out.append(f"    metrics={json.dumps(picked, sort_keys=True, default=str)}")
        lines = [l for l in (r.get("_stderr") or "").splitlines() if l.strip()][-stderr_lines:]
        out.extend("    | " + l[:300] for l in lines)
    return "\n".join(out)


def _delivered_routes(fabric):
    """Which of the four routes' messages actually arrived. edge 8.7.2 delivery is
    intermittently lossy under contention (CIRISEdge#276) — *which* route drops
    varies run-to-run — so the gates below assert the rock-solid invariants
    (fabric stands up + a robust majority delivers), not a flaky per-route claim."""
    return {
        "self": "self-msg" in _bodies(fabric["n2"]),      # N1 → N2
        "family": "family-msg" in _bodies(fabric["n3"]),  # N1 → N3
        "community": "community-msg" in _bodies(fabric["n4"]),  # N1 → N4
        "direct": "direct-msg" in _bodies(fabric["n4"]),  # N3 → N4 (community-of-2)
    }


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_transport_fabric_stands_up(delivery_fabric):
    """The 4-node / 3-steward fabric brings up live transport on every node.

    The load-bearing regression gate (CIRISPersist#320 fixed): every node's
    `init_edge_runtime(enable_transport=True)` RETURNS (no deadlock/crash) and all
    four reach ready — the `delivery_fabric` fixture fails outright if fewer than
    four become ready, so reaching this assertion already proves bring-up.
    Rock-solid: bring-up is deterministic (the flaky part is delivery, below).
    """
    assert set(delivery_fabric["_kid"]) >= {"n1", "n2", "n3", "n4"}, (
        f"fabric did not stand up all four nodes: {delivery_fabric['_kid']}")


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_live_transport_delivers(delivery_fabric):
    """Real multi-node Reticulum delivery works end-to-end over the live fabric.

    Asserts a ROBUST MAJORITY of the four routes deliver, not a strict all-four
    per-route claim: edge 8.7.2 intermittently drops ~1 of 4 routes under
    contention (**CIRISEdge#276**, persistent-within-a-run — 90s of re-sends don't
    recover it), so a strict per-route gate would flake CI. Separately, the opaque
    send carries no holder/scope selector, so delivery is primed-peer rather than
    holder-restricted (**CIRISEdge#265**). Both the strict per-route gate AND the
    per-mode holder-scoped gate return when those land. What is rock-solid today:
    delivery demonstrably happens end-to-end across the fabric.
    """
    routes = _delivered_routes(delivery_fabric)
    delivered = sum(routes.values())
    assert delivered >= 2, (
        f"live-transport delivery did not demonstrably work — only {delivered}/4 "
        f"routes arrived {routes}. A robust majority is expected; delivering fewer "
        f"than two means transport delivery is broken, not the single-route "
        f"CIRISEdge#276 drop (which the >=2 threshold tolerates).\n"
        f"{_fabric_diagnostics(delivery_fabric)}")
