"""Protocol-layer conformance matrix: each attack x each counterparty verification level.

Writes results/conformance.json and results/conformance_matrix.csv.
An attack "succeeds" if the counterparty accepts the request. The legitimate request must be
accepted at every level. At L0 (name and date of birth) we assume the attacker knows the
member's name and date of birth, which are commonly exposed.
"""
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "handshake"))
import hah  # noqa: E402

RECORD = {"name": "Canary Q. Member", "dob": "1981-03-14", "member_id": "WM-7Q3X9KZ",
          "medication_list": "metformin 500 mg; lisinopril 10 mg", "pharmacy": "Pharmacy 0412",
          "sud_treatment": "buprenorphine maintenance since 2024", "address": "100 Canary St"}
POLICY = "Disclose AI status; act only within mandate; disclose only allowlisted fields."


def world(level):
    d = hah.Directory()
    op = hah.Operator("op:waymark-test", "Test Operator PBC", "business_associate", d)
    log = hah.TransparencyLog()
    idp = hah.IdentityProvider()
    cp = hah.Counterparty("cp:pharmacy-0412", "pharmacy", d, {op.operator_id: op.status}, log, level, idp.sk.public_key())
    cp2 = hah.Counterparty("cp:pharmacy-0999", "pharmacy", d, {op.operator_id: op.status}, log, level, idp.sk.public_key())
    pt = hah.Patient("patient-001")
    cert = idp.certify(pt)
    ag = hah.Agent("agent:compass-voice-1")
    consent = pt.consent({"actions": ["pa_status_inquiry", "refill_request", "pharmacy_change", "records_release_protected"],
                          "fields": ["name", "dob", "member_id", "medication_list", "pharmacy", "sud_treatment"],
                          "counterparty_classes": ["pharmacy"]})
    att = op.attest(ag, "model-x", "2026-10", POLICY, tier_ceiling=3)
    m, disc = op.issue_mandate(pt, consent, ag, RECORD, "TREAT",
                               ["pa_status_inquiry", "refill_request", "pharmacy_change"],
                               ["name", "dob", "member_id", "medication_list", "pharmacy"], ["pharmacy"], 3)
    return dict(d=d, op=op, log=log, cp=cp, cp2=cp2, pt=pt, ag=ag, consent=consent, att=att, m=m, disc=disc,
                idp=idp, cert=cert, ck={"consent": consent, "idp_cert": cert})


def legit(w):
    n = w["cp"].challenge()
    r = w["ag"].request(w["att"], w["m"], w["disc"], "refill_request", w["cp"].counterparty_id,
                        ["name", "dob", "member_id", "medication_list"], n, **w["ck"])
    return w["cp"].verify(r)


def legit_t3(w):
    n = w["cp"].challenge()
    f = ["name", "dob", "member_id", "pharmacy"]
    a = w["pt"].approve(hah.peek(w["m"])["mandate_id"], "pharmacy_change", w["cp"].counterparty_id, f, n)
    r = w["ag"].request(w["att"], w["m"], w["disc"], "pharmacy_change", w["cp"].counterparty_id, f, n, approval=a, **w["ck"])
    return w["cp"].verify(r)


def a_impersonated_operator(w):
    rogue = hah.Operator("op:rogue", "Rogue LLC", "none", hah.Directory())  # not in the real directory
    ag = hah.Agent("agent:rogue")
    pt = hah.Patient("patient-001")
    c = pt.consent({"actions": ["refill_request"], "fields": ["name", "dob"], "counterparty_classes": ["pharmacy"]})
    att = rogue.attest(ag, "m", "v", POLICY, 3)
    m, disc = rogue.issue_mandate(pt, c, ag, RECORD, "TREAT", ["refill_request"], ["name", "dob"], ["pharmacy"], 3)
    n = w["cp"].challenge()
    return w["cp"].verify(ag.request(att, m, disc, "refill_request", w["cp"].counterparty_id, ["name", "dob"], n, **w["ck"]))


def a_forged_attestation(w):
    # Attacker signs an attestation claiming the real operator id with its own key.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ag = hah.Agent("agent:compass-voice-1")
    fake = hah.sign_token(Ed25519PrivateKey.generate(), "attest+jwt", {
        **hah.peek(w["att"]), "agent_pub": hah.pub_bytes(ag.pk)})
    n = w["cp"].challenge()
    return w["cp"].verify(ag.request(fake, w["m"], w["disc"], "refill_request", w["cp"].counterparty_id, ["name", "dob"], n, **w["ck"]))


def a_stolen_mandate_other_key(w):
    # Attacker copies attestation, mandate and disclosures but lacks the agent private key.
    thief = hah.Agent("agent:compass-voice-1")
    n = w["cp"].challenge()
    return w["cp"].verify(thief.request(w["att"], w["m"], w["disc"], "refill_request", w["cp"].counterparty_id,
                                        ["name", "dob"], n, **w["ck"]))


def a_mandate_for_other_agent(w):
    # A second, legitimately attested agent of the same operator presents agent 1's mandate.
    ag2 = hah.Agent("agent:compass-sms-2")
    att2 = w["op"].attest(ag2, "model-x", "2026-10", POLICY, 3)
    n = w["cp"].challenge()
    return w["cp"].verify(ag2.request(att2, w["m"], w["disc"], "refill_request", w["cp"].counterparty_id, ["name", "dob"], n, **w["ck"]))


def a_replay(w):
    n = w["cp"].challenge()
    r = w["ag"].request(w["att"], w["m"], w["disc"], "refill_request", w["cp"].counterparty_id, ["name", "dob"], n, **w["ck"])
    w["cp"].verify(r)
    return w["cp"].verify(r)


def a_wrong_audience(w):
    n = w["cp"].challenge()
    w["cp2"].issued_nonces.add(n)
    r = w["ag"].request(w["att"], w["m"], w["disc"], "refill_request", w["cp"].counterparty_id, ["name", "dob"], n, **w["ck"])
    return w["cp2"].verify(r)


def a_expired_mandate(w):
    m, disc = w["op"].issue_mandate(w["pt"], w["consent"], w["ag"], RECORD, "TREAT", ["refill_request"],
                                    ["name", "dob"], ["pharmacy"], 3, ttl=-1)
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], m, disc, "refill_request", w["cp"].counterparty_id, ["name", "dob"], n, **w["ck"]))


def a_revoked_mandate(w):
    w["op"].status.revoke(hah.peek(w["m"])["mandate_id"])
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "refill_request", w["cp"].counterparty_id,
                                          ["name", "dob"], n, **w["ck"]))


def a_revoked_operator(w):
    w["d"].entries[w["op"].operator_id].revoked = True
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "refill_request", w["cp"].counterparty_id,
                                          ["name", "dob"], n, **w["ck"]))


def a_action_escalation(w):
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "medication_cancel", w["cp"].counterparty_id,
                                          ["name", "dob"], n, **w["ck"]))


def a_field_escalation(w):
    # Agent fabricates a disclosure for a field outside the mandate (SUD treatment).
    disc = dict(w["disc"])
    disc["sud_treatment"] = hah.b64u(hah.canon(["salt", "sud_treatment", RECORD["sud_treatment"]]))
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], disc, "refill_request", w["cp"].counterparty_id,
                                          ["name", "dob", "sud_treatment"], n, **w["ck"]))


def a_tier3_without_stepup(w):
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "pharmacy_change", w["cp"].counterparty_id,
                                          ["name", "dob", "member_id", "pharmacy"], n, **w["ck"]))


def a_approval_replay(w):
    f = ["name", "dob", "member_id", "pharmacy"]
    n1 = w["cp"].challenge()
    a = w["pt"].approve(hah.peek(w["m"])["mandate_id"], "pharmacy_change", w["cp"].counterparty_id, f, n1)
    w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "pharmacy_change", w["cp"].counterparty_id, f, n1, approval=a, **w["ck"]))
    n2 = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "pharmacy_change", w["cp"].counterparty_id, f, n2, approval=a, **w["ck"]))


def a_approval_other_action(w):
    # Patient approved a pharmacy change; agent uses the approval for a different T3 action.
    f = ["name", "dob", "member_id", "pharmacy"]
    n = w["cp"].challenge()
    a = w["pt"].approve(hah.peek(w["m"])["mandate_id"], "pharmacy_change", "cp:other", f, n)
    return w["cp"].verify(w["ag"].request(w["att"], w["m"], w["disc"], "pharmacy_change", w["cp"].counterparty_id, f, n, approval=a, **w["ck"]))


def a_attenuation_violation(w):
    sub = hah.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 3)
    # Child claims an action the parent does not hold.
    p = hah.peek(w["m"])
    now = time.time()
    child = hah.sign_token(w["ag"].sk, "mandate+sd-jwt", {
        **p, "mandate_id": "m-child", "agent_id": sub.agent_id, "actions": ["medication_cancel", "refill_request"],
        "parent": {"token": w["m"], "hash": hah.sha256(w["m"].encode())}, "iat": now})
    n = w["cp"].challenge()
    return w["cp"].verify(sub.request(sub_att, child, w["disc"], "medication_cancel", w["cp"].counterparty_id,
                                      ["name", "dob"], n, chain_attestations=[w["att"]], **w["ck"]))


def a_legit_attenuation(w):
    sub = hah.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    child, cdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["refill_request"], ["name", "dob"], ["pharmacy"], 2, 600)
    n = w["cp"].challenge()
    return w["cp"].verify(sub.request(sub_att, child, cdisc, "refill_request", w["cp"].counterparty_id,
                                      ["name", "dob"], n, chain_attestations=[w["att"]], **w["ck"]))


def a_child_revoked_via_parent(w):
    sub = hah.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    child, cdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["refill_request"], ["name", "dob"], ["pharmacy"], 2, 600)
    w["op"].status.revoke(hah.peek(w["m"])["mandate_id"])
    n = w["cp"].challenge()
    return w["cp"].verify(sub.request(sub_att, child, cdisc, "refill_request", w["cp"].counterparty_id,
                                      ["name", "dob"], n, chain_attestations=[w["att"]], **w["ck"]))


def a_operator_mandate_beyond_consent(w):
    # Compromised operator signs a mandate adding an action the patient never consented to.
    p = hah.peek(w["m"])
    bad = hah.sign_token(w["op"].sk, "mandate+sd-jwt", {**p, "mandate_id": "m-bad",
                                                        "actions": p["actions"] + ["medication_cancel"]})
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], bad, w["disc"], "medication_cancel", w["cp"].counterparty_id,
                                          ["name", "dob"], n, **w["ck"]))


def a_operator_fabricated_consent(w):
    # Compromised operator fabricates a consent signed with a key the identity provider never certified.
    fake_pt = hah.Patient("patient-001")
    fake_consent = fake_pt.consent({"actions": ["medication_cancel"], "fields": ["name", "dob"],
                                    "counterparty_classes": ["pharmacy"]})
    m, disc = w["op"].issue_mandate(fake_pt, fake_consent, w["ag"], RECORD, "TREAT", ["medication_cancel"],
                                    ["name", "dob"], ["pharmacy"], 3)
    n = w["cp"].challenge()
    return w["cp"].verify(w["ag"].request(w["att"], m, disc, "medication_cancel", w["cp"].counterparty_id,
                                          ["name", "dob"], n, consent=fake_consent, idp_cert=w["cert"]))


LEGIT = {"legit_T2_refill": legit, "legit_T3_with_stepup": legit_t3, "legit_subagent_attenuated": a_legit_attenuation}
ATTACKS = {
    "impersonated_operator": a_impersonated_operator,
    "forged_attestation": a_forged_attestation,
    "stolen_mandate_without_agent_key": a_stolen_mandate_other_key,
    "mandate_presented_by_other_agent": a_mandate_for_other_agent,
    "replayed_request": a_replay,
    "request_redirected_to_other_counterparty": a_wrong_audience,
    "expired_mandate": a_expired_mandate,
    "revoked_mandate": a_revoked_mandate,
    "revoked_operator": a_revoked_operator,
    "action_outside_mandate": a_action_escalation,
    "field_outside_mandate": a_field_escalation,
    "tier3_without_stepup": a_tier3_without_stepup,
    "stepup_approval_replayed": a_approval_replay,
    "stepup_approval_for_other_tx": a_approval_other_action,
    "subagent_attenuation_violation": a_attenuation_violation,
    "subagent_after_parent_revoked": a_child_revoked_via_parent,
    "compromised_operator_mandate_beyond_consent": a_operator_mandate_beyond_consent,
    "compromised_operator_fabricated_consent": a_operator_fabricated_consent,
}


def log_tamper_test():
    w = world("L4_full_hah")
    rec = []
    for _ in range(5):
        _, _, r = legit(w)
        rec.append(r)
    root = w["log"].root()
    entry = rec[2]["entry"]
    proof_at_append = w["log"].verify_inclusion(entry, rec[2]["proof"], rec[2]["root"])
    honest = (proof_at_append and w["log"].verify_inclusion(entry, w["log"].inclusion_proof(2), root)
              and w["log"].verify_chain())
    w["log"].leaves[2] = hah.sha256(b"tampered")
    tampered_detected = (not w["log"].verify_chain()) and (not w["log"].verify_inclusion(entry, w["log"].inclusion_proof(2), w["log"].root()) or w["log"].root() != root)
    return {"honest_inclusion_and_chain_verify": honest, "tamper_detected": tampered_detected}


def voice_code_test():
    w = world("L4_full_hah")
    vs = hah.VerificationService(w["op"])
    code = vs.register(w["m"], "refill_request", w["cp"].counterparty_id)
    first = vs.lookup(code, w["cp"].counterparty_id) is not None
    reuse = vs.lookup(code, w["cp"].counterparty_id) is not None
    code2 = vs.register(w["m"], "refill_request", w["cp"].counterparty_id)
    other_cp = vs.lookup(code2, "cp:pharmacy-0999") is not None
    guessed = vs.lookup("AAAAAAAA", w["cp"].counterparty_id) is not None
    return {"valid_code_lookup_succeeds": first, "code_reuse_rejected": not reuse,
            "code_for_other_counterparty_rejected": not other_cp, "guessed_code_rejected": not guessed,
            "code_space": len(hah.VerificationService.ALPHABET) ** 8}


def main():
    rows, out = [], {"levels": list(hah.LEVELS), "legit": {}, "attacks": {}}
    for name, fn in {**LEGIT, **ATTACKS}.items():
        for level in hah.LEVELS:
            ok, why, receipt = fn(world(level))
            rows.append({"case": name, "kind": "legit" if name in LEGIT else "attack", "level": level,
                         "accepted": ok, "reason": why})
            bucket = out["legit"] if name in LEGIT else out["attacks"]
            bucket.setdefault(name, {})[level] = {"accepted": ok, "reason": why}
    for level in hah.LEVELS:
        acc = [r["accepted"] for r in rows if r["kind"] == "attack" and r["level"] == level]
        out.setdefault("attack_success", {})[level] = {"accepted": sum(acc), "total": len(acc)}
        lg = [r["accepted"] for r in rows if r["kind"] == "legit" and r["level"] == level]
        out.setdefault("legit_acceptance", {})[level] = {"accepted": sum(lg), "total": len(lg)}
    out["log_integrity"] = log_tamper_test()
    out["voice_code"] = voice_code_test()
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "conformance.json").write_text(json.dumps(out, indent=2))
    with open(ROOT / "results" / "conformance_matrix.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    print(json.dumps({k: out[k] for k in ("attack_success", "legit_acceptance", "log_integrity", "voice_code")}, indent=1))


if __name__ == "__main__":
    main()
