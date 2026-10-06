"""Replay every transaction that benchmark agents submitted in C2 and C3 through the version 1 verifier (hah.py, used by
the pre-registered benchmark) and the version 2 verifier (hah2.py), and report agreement of accept/reject decisions.

For each conversation, a fresh world is built per version with the same member, task, mandate scope, and the simulated
patient's approval policy (approve only the task's own tier 3 action). C3 operator-side tool-gate blocks are not
replayed because they never reached the counterparty.

Usage: python scripts/05_replay_v1_v2.py --run confirmatory    -> results/replay_v1_v2_<run>.json
"""
import argparse
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "handshake"))
sys.path.insert(0, str(ROOT / "bench"))
import hah  # noqa: E402
import hah2  # noqa: E402
import scenarios as S  # noqa: E402

POLICY = "replay"


def v1_world(member, task, ccls):
    d = hah.Directory()
    op = hah.Operator("op:waymark", "Waymark PBC", "business_associate", d)
    idp = hah.IdentityProvider()
    pt = hah.Patient(member["record"]["member_key"])
    cert = idp.certify(pt)
    ag = hah.Agent("agent:compass")
    cp = hah.Counterparty("cp:" + ccls, ccls, d, {op.operator_id: op.status}, hah.TransparencyLog(), "L4_full_hah", idp.sk.public_key())
    allowed = [f for f in task["allowed"] if member["record"].get(f) is not None]
    consent = pt.consent({"actions": [task["action"]], "fields": allowed, "counterparty_classes": [ccls]})
    att = op.attest(ag, "m", "1", POLICY, 3)
    rec = {k: (v if v is not None else "") for k, v in member["record"].items()}
    m, disc = op.issue_mandate(pt, consent, ag, rec, "TREAT", [task["action"]], allowed, [ccls], 3)

    def submit(action, fields):
        fields = sorted(set(f for f in fields if member["record"].get(f) is not None))
        if any(f not in disc for f in fields):
            return False
        n = cp.challenge()
        appr = pt.approve(hah.peek(m)["mandate_id"], action, cp.counterparty_id, fields, n) \
            if hah.tier_of(action, fields) == 3 and action == task["action"] else None
        r = ag.request(att, m, disc, action, cp.counterparty_id, fields, n, approval=appr, consent=consent, idp_cert=cert)
        return cp.verify(r)[0]
    return submit


def v2_world(member, task, ccls):
    d = hah2.Directory()
    op = hah2.Operator("op:waymark", "Waymark PBC", "business_associate", d)
    idp = hah2.IdentityProvider()
    pt = hah2.Patient(member["record"]["member_key"], member["record"]["name"], member["record"]["dob"])
    cert = idp.certify(pt)
    ag = hah2.Agent("agent:compass")
    cp = hah2.Counterparty("cp:" + ccls, ccls, d, {op.operator_id: op.status}, idp, hah2.TransparencyLog(), "L4_full_hah")
    allowed = [f for f in task["allowed"] if member["record"].get(f) is not None]
    consent, cdisc = pt.consent(op.operator_id, ag.agent_id, "TREAT", [task["action"]], allowed, [ccls])
    att = op.attest(ag, "m", "1", POLICY, 3)
    rec = {k: (v if v is not None else "") for k, v in member["record"].items()}
    rec["subject_commitment"] = pt.subject_commitment
    m, disc = op.issue_mandate(pt, cert, idp.pk, consent, cdisc, ag, rec, [task["action"]], allowed, [ccls], 3)

    def submit(action, fields):
        fields = sorted(set(f for f in fields if member["record"].get(f) is not None))
        if any(("field", f) not in disc for f in fields):
            return False
        n = cp.challenge()
        try:
            t = hah2.tier_of(action, fields, {})
        except KeyError:
            t = 0
        appr = pt.approve(hah2.peek(m)["mandate_id"], action, {}, cp.counterparty_id, fields, n) \
            if t == 3 and action == task["action"] else None
        r = ag.request(att, m, disc, consent, cert, action, {}, cp.counterparty_id, ccls, fields, n, approval=appr)
        return cp.verify(r)[0]
    return submit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    a = ap.parse_args()
    members = {m["record"]["member_key"]: m for m in S.make_members()}
    n_tx = agree = 0
    disagreements = []
    n_conv = 0
    for f in glob.glob(str(ROOT / "results" / "bench" / a.run / "*" / "C[23]" / "*.json")):
        d = json.load(open(f))
        sc = d["scenario"]
        task = S.TASKS[sc["task"]]
        events = [e for e in d["events"] if "result" in e]
        if not events:
            continue
        n_conv += 1
        s1 = v1_world(members[sc["member_key"]], task, task["counterparty_class"])
        s2 = v2_world(members[sc["member_key"]], task, task["counterparty_class"])
        for e in events:
            logged = e["result"].startswith("ACCEPTED")
            r1, r2 = s1(e["action"], e["fields"]), s2(e["action"], e["fields"])
            n_tx += 1
            if r1 == r2 == logged:
                agree += 1
            else:
                disagreements.append({"file": Path(f).name, "model": d["model"], "config": d["config"], "action": e["action"],
                                      "fields": e["fields"], "logged": logged, "v1": r1, "v2": r2})
    out = {"run": a.run, "conversations_with_transactions": n_conv, "transactions": n_tx, "agree_all_three": agree,
           "disagreements": disagreements}
    (ROOT / "results" / f"replay_v1_v2_{a.run}.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != "disagreements"}), "disagreements:", len(disagreements))
    for x in disagreements[:10]:
        print(x)


if __name__ == "__main__":
    main()
