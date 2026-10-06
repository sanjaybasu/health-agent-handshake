"""Conformance matrix for the version 2 reference implementation (handshake/hah2.py).

Each case runs against five verification levels. An attack succeeds if the counterparty accepts the request.
Legitimate requests must be accepted at every level. At L0 we assume the attacker knows the patient's name and
date of birth. Writes results/conformance_v2.json and results/conformance_v2_matrix.csv.
"""
import csv
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "handshake"))
import hah2 as H  # noqa: E402

POLICY = "Disclose AI status; act only within mandate; disclose only allowlisted fields."
ACTIONS = ["refill_request", "pharmacy_change", "pa_status_inquiry"]
FIELDS = ["name", "dob", "member_id", "medication_list", "pharmacy"]


def record_for(pt, name="Canary Q. Member", dob="1981-03-14"):
    return {"name": name, "dob": dob, "member_id": "WM-7Q3X9KZ", "medication_list": "metformin 500 mg",
            "pharmacy": "Pharmacy 0412", "sud_treatment": "buprenorphine maintenance", "subject_commitment": pt.subject_commitment}


def world(level):
    w = {}
    w["d"] = H.Directory()
    w["op"] = H.Operator("op:waymark-test", "Test Operator PBC", "business_associate", w["d"])
    w["idp"] = H.IdentityProvider()
    w["log"] = H.TransparencyLog()
    st = {w["op"].operator_id: w["op"].status}
    w["pt"] = H.Patient("patient-001", "Canary Q. Member", "1981-03-14")
    held = {("canary q. member", "1981-03-14", "sertraline")}   # this pharmacy already dispenses the member's sertraline
    w["cp"] = H.Counterparty("cp:pharmacy-0412", "pharmacy", w["d"], st, w["idp"], w["log"], level, held_prescriptions=held)
    w["cp2"] = H.Counterparty("cp:pharmacy-0999", "pharmacy", w["d"], st, w["idp"], w["log"], level)
    w["cert"] = w["idp"].certify(w["pt"])
    w["ag"] = H.Agent("agent:compass-voice-1")
    w["consent"], w["cdisc"] = w["pt"].consent(w["op"].operator_id, w["ag"].agent_id, "TREAT", ACTIONS, FIELDS, ["pharmacy"])
    w["att"] = w["op"].attest(w["ag"], "model-x", "2026-10", POLICY, 3)
    w["m"], w["disc"] = w["op"].issue_mandate(w["pt"], w["cert"], w["idp"].pk, w["consent"], w["cdisc"], w["ag"],
                                              record_for(w["pt"]), ACTIONS, FIELDS, ["pharmacy"], 3)
    return w


def req(w, action, fields, params=None, approval=None, agent=None, att=None, mandate=None, disc=None, cp=None,
        consent=None, cert=None, chain=None, nonce=None):
    cp = cp or w["cp"]
    n = nonce or cp.challenge()
    if params is None:
        params = {"drug": "metformin 500 mg"} if action in H.DRUG_ACTIONS else {}
    return (agent or w["ag"]).request(att or w["att"], mandate or w["m"], disc or w["disc"], consent or w["consent"],
                                     cert or w["cert"], action, params, w["cp"].counterparty_id, "pharmacy",
                                     fields, n, approval=approval, chain_attestations=chain), n


def approve(w, action, fields, params, nonce, cp=None):
    return w["pt"].approve(H.peek(w["m"])["mandate_id"], action, params, (cp or w["cp"]).counterparty_id, fields, nonce)


# ---------------------------------------------------------------- legitimate cases

def legit_t2(w):
    r, _ = req(w, "refill_request", ["name", "dob", "medication_list"], {"drug": "metformin 500 mg"})
    return w["cp"].verify(r)


def legit_t2_protected_refill_at_holding_pharmacy(w):
    # Sertraline is protected, but this pharmacy already holds the prescription: no new disclosure, so tier 2.
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "sertraline 50 mg"})
    return w["cp"].verify(r)


def legit_t2_routine_ride_cancel_from_record(w):
    w["cp"].object_records["R-100"] = ("canary q. member", "1981-03-14", "routine follow-up")
    return _cancel(w, {"ride_id": "R-100"})


def legit_t0_hours_without_phi(w):
    n = w["cp"].challenge()
    r = w["ag"].request(w["att"], w["m"], w["disc"], w["consent"], w["cert"], "info_hours", {}, w["cp"].counterparty_id,
                        "pharmacy", [], n)
    return w["cp"].verify(r)


def legit_t3_approval_after_ten_minutes(w):
    # A tier 3 transaction challenge stays open for 24 hours; the patient approves ten minutes later.
    f, p = ["name", "dob", "pharmacy"], {"to_pharmacy": "cp:pharmacy-0412", "drug": "metformin 500 mg"}
    n = w["cp"].challenge(ttl=H.TIER3_TRANSACTION_TTL)
    t0, ttl = w["cp"].issued_nonces[n]
    w["cp"].issued_nonces[n] = (t0 - 600, ttl)
    r, _ = req(w, "pharmacy_change", f, p, approval=approve(w, "pharmacy_change", f, p, n), nonce=n)
    return w["cp"].verify(r)


def legit_t3_controlled_refill_with_stepup(w):
    f, p = ["name", "dob"], {"drug": "oxycodone 10 mg"}
    n = w["cp"].challenge()
    r, _ = req(w, "refill_request", f, p, approval=approve(w, "refill_request", f, p, n), nonce=n)
    return w["cp"].verify(r)


def legit_t3(w):
    f, p = ["name", "dob", "pharmacy"], {"to_pharmacy": "cp:pharmacy-0412"}
    n = w["cp"].challenge()
    r, _ = req(w, "pharmacy_change", f, p, approval=approve(w, "pharmacy_change", f, p, n), nonce=n)
    return w["cp"].verify(r)


def legit_sub(w):
    sub = H.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    child, cdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["refill_request"], ["name", "dob"], ["pharmacy"], 2, 600)
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "metformin 500 mg"}, agent=sub, att=sub_att, mandate=child,
               disc=cdisc, chain=[w["att"]])
    return w["cp"].verify(r)


# ---------------------------------------------------------------- attacks carried over from version 1

def a_impersonated_operator(w):
    rogue_dir = H.Directory()
    rogue = H.Operator("op:rogue", "Rogue LLC", "business_associate", rogue_dir)
    ag = H.Agent("agent:rogue")
    pt = H.Patient("patient-001", "Canary Q. Member", "1981-03-14")
    cert = w["idp"].certify(pt)
    c, cd = pt.consent(rogue.operator_id, ag.agent_id, "TREAT", ["refill_request"], ["name", "dob"], ["pharmacy"])
    att = rogue.attest(ag, "m", "v", POLICY, 3)
    m, d = rogue.issue_mandate(pt, cert, w["idp"].pk, c, cd, ag, record_for(pt), ["refill_request"], ["name", "dob"], ["pharmacy"], 3)
    r, _ = req(w, "refill_request", ["name", "dob"], agent=ag, att=att, mandate=m, disc=d, consent=c, cert=cert)
    return w["cp"].verify(r)


def a_forged_attestation(w):
    ag = H.Agent("agent:compass-voice-1")
    fake = H.sign_token(Ed25519PrivateKey.generate(), "attest+jwt", {**H.peek(w["att"]), "agent_pub": H.pub_bytes(ag.pk)})
    r, _ = req(w, "refill_request", ["name", "dob"], agent=ag, att=fake)
    return w["cp"].verify(r)


def a_stolen_mandate(w):
    r, _ = req(w, "refill_request", ["name", "dob"], agent=H.Agent("agent:compass-voice-1"))
    return w["cp"].verify(r)


def a_other_agent(w):
    ag2 = H.Agent("agent:compass-sms-2")
    r, _ = req(w, "refill_request", ["name", "dob"], agent=ag2, att=w["op"].attest(ag2, "m", "v", POLICY, 3))
    return w["cp"].verify(r)


def a_replay(w):
    r, _ = req(w, "refill_request", ["name", "dob"])
    w["cp"].verify(r)
    return w["cp"].verify(r)


def a_wrong_audience(w):
    r, n = req(w, "refill_request", ["name", "dob"])
    w["cp2"].issued_nonces[n] = (time.time(), H.NONCE_TTL)
    return w["cp2"].verify(r)


def a_expired_mandate(w):
    m, d = w["op"].issue_mandate(w["pt"], w["cert"], w["idp"].pk, w["consent"], w["cdisc"], w["ag"], record_for(w["pt"]),
                                 ["refill_request"], ["name", "dob"], ["pharmacy"], 3, ttl=-1)
    r, _ = req(w, "refill_request", ["name", "dob"], mandate=m, disc=d)
    return w["cp"].verify(r)


def a_revoked_mandate(w):
    w["op"].status.revoked_mandates.add(H.peek(w["m"])["mandate_id"])
    r, _ = req(w, "refill_request", ["name", "dob"])
    return w["cp"].verify(r)


def a_revoked_operator(w):
    w["d"].entries[w["op"].operator_id].revoked = True
    r, _ = req(w, "refill_request", ["name", "dob"])
    return w["cp"].verify(r)


def a_action_escalation(w):
    disc = dict(w["disc"])
    disc[("action", "medication_cancel")] = H.disclosure("action", "medication_cancel")
    r, _ = req(w, "medication_cancel", ["name", "dob"], disc=disc)
    return w["cp"].verify(r)


def a_field_escalation(w):
    disc = dict(w["disc"])
    disc[("field", "sud_treatment")] = H.disclosure("sud_treatment", "buprenorphine maintenance")
    r, _ = req(w, "refill_request", ["name", "dob", "sud_treatment"], disc=disc)
    return w["cp"].verify(r)


def a_t3_without_stepup(w):
    r, _ = req(w, "pharmacy_change", ["name", "dob", "pharmacy"], {"to_pharmacy": "cp:pharmacy-0412"})
    return w["cp"].verify(r)


def a_approval_replay(w):
    f, p = ["name", "dob", "pharmacy"], {"to_pharmacy": "cp:pharmacy-0412"}
    n1 = w["cp"].challenge()
    a = approve(w, "pharmacy_change", f, p, n1)
    w["cp"].verify(req(w, "pharmacy_change", f, p, approval=a, nonce=n1)[0])
    r, _ = req(w, "pharmacy_change", f, p, approval=a)
    return w["cp"].verify(r)


def a_approval_other_counterparty(w):
    f, p = ["name", "dob", "pharmacy"], {"to_pharmacy": "cp:pharmacy-0412"}
    n = w["cp"].challenge()
    r, _ = req(w, "pharmacy_change", f, p, approval=approve(w, "pharmacy_change", f, p, n, cp=w["cp2"]), nonce=n)
    return w["cp"].verify(r)


def a_attenuation_violation(w):
    sub = H.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 3)
    p = H.peek(w["m"])
    extra = H.disclosure("action", "medication_cancel")
    child = H.sign_token(w["ag"].sk, "mandate+sd-jwt", {**p, "mandate_id": "m-child", "agent_id": sub.agent_id,
                                                        "_sd": sorted(p["_sd"] + [H.digest(extra)]),
                                                        "parent": {"token": w["m"], "hash": H.sha256(w["m"].encode())}})
    disc = dict(w["disc"])
    disc[("action", "medication_cancel")] = extra
    r, _ = req(w, "medication_cancel", ["name", "dob"], agent=sub, att=sub_att, mandate=child, disc=disc, chain=[w["att"]])
    return w["cp"].verify(r)


def a_sub_after_parent_revoked(w):
    sub = H.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    child, cdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["refill_request"], ["name", "dob"], ["pharmacy"], 2, 600)
    w["op"].status.revoked_mandates.add(H.peek(w["m"])["mandate_id"])
    r, _ = req(w, "refill_request", ["name", "dob"], agent=sub, att=sub_att, mandate=child, disc=cdisc, chain=[w["att"]])
    return w["cp"].verify(r)


def a_operator_beyond_consent(w):
    # Compromised operator adds an action the patient never consented to.
    disc = dict(w["disc"])
    extra = H.disclosure("action", "medication_cancel")
    disc[("action", "medication_cancel")] = extra
    p = H.peek(w["m"])
    bad = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**p, "mandate_id": "m-bad", "_sd": sorted(p["_sd"] + [H.digest(extra)])})
    r, _ = req(w, "medication_cancel", ["name", "dob"], mandate=bad, disc=disc)
    return w["cp"].verify(r)


def a_operator_fabricated_consent(w):
    # Compromised operator fabricates consent with a key the identity provider never certified.
    fake = H.Patient("patient-001", "Canary Q. Member", "1981-03-14")
    c, cd = fake.consent(w["op"].operator_id, w["ag"].agent_id, "TREAT", ["medication_cancel"], ["name", "dob"], ["pharmacy"])
    rec = record_for(fake)
    fake_cert = H.sign_token(Ed25519PrivateKey.generate(), "idp-cert+jwt", {"patient_pub": H.pub_bytes(fake.pk),
                                                                             "subject_commitment": fake.subject_commitment, "ial": 2})
    p_m = H.peek(w["m"])
    disc = {("action", "medication_cancel"): H.disclosure("action", "medication_cancel"),
            ("field", "name"): H.disclosure("name", rec["name"]), ("field", "dob"): H.disclosure("dob", rec["dob"]),
            ("subject", "pharmacy"): H.disclosure("subject:pharmacy", "s"), **{("consent", k): v for k, v in cd.items()}}
    m = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**p_m, "mandate_id": "m-fab", "_sd": sorted(H.digest(v) for k, v in disc.items() if k[0] != "consent"),
                                                    "consent_hash": H.sha256(c.encode()), "patient_pub": H.pub_bytes(fake.pk)})
    r, _ = req(w, "medication_cancel", ["name", "dob"], mandate=m, disc=disc, consent=c, cert=fake_cert)
    return w["cp"].verify(r)


# ---------------------------------------------------------------- new attacks from adversarial review

def a_consent_replayed_by_other_operator(w):
    op2 = H.Operator("op:second", "Second Operator", "business_associate", w["d"])
    w["cp"].operator_status[op2.operator_id] = op2.status
    ag2 = H.Agent("agent:second")
    att2 = op2.attest(ag2, "m", "v", POLICY, 3)
    p = H.peek(w["m"])
    m2 = H.sign_token(op2.sk, "mandate+sd-jwt", {**p, "mandate_id": "m-op2", "operator_id": op2.operator_id, "agent_id": ag2.agent_id})
    r, _ = req(w, "refill_request", ["name", "dob"], agent=ag2, att=att2, mandate=m2)
    return w["cp"].verify(r)


def a_third_party_revokes_consent(w):
    # A counterparty that holds the consent token tries to revoke it without the patient's key.
    forged = H.sign_token(Ed25519PrivateKey.generate(), "consent-revocation+jwt", {"consent_hash": H.sha256(w["consent"].encode()), "iat": time.time()})
    try:
        w["idp"].revoke_consent(forged, w["consent"])
    except Exception as e:
        return False, f"revocation_refused: {type(e).__name__}", None
    return True, "revoked", None


def a_consent_attached_to_other_record(w):
    other = H.Patient("patient-002", "Other Person", "1990-01-01")
    try:
        w["op"].issue_mandate(w["pt"], w["cert"], w["idp"].pk, w["consent"], w["cdisc"], w["ag"], record_for(other, "Other Person"),
                              ["refill_request"], ["name", "dob"], ["pharmacy"], 3)
    except ValueError as e:
        return False, f"issuer_refused: {e}", None
    return True, "issued", None


def a_self_delegation_fake_patient_key(w):
    # Agent with a stolen key delegates to itself, replaces the patient key, and self-approves a tier 3 action.
    fake = Ed25519PrivateKey.generate()
    p = H.peek(w["m"])
    child = H.sign_token(w["ag"].sk, "mandate+sd-jwt", {**p, "mandate_id": "m-self", "patient_pub": H.pub_bytes(fake.public_key()),
                                                        "parent": {"token": w["m"], "hash": H.sha256(w["m"].encode())}})
    f, prm = ["name", "dob", "pharmacy"], {"to_pharmacy": "cp:attacker"}
    n = w["cp"].challenge()
    tx = {"mandate_id": p["mandate_id"], "action": "pharmacy_change", "params_hash": H.sha256(H.canon(prm)),
          "counterparty_id": w["cp"].counterparty_id, "fields": sorted(f), "nonce": n}
    appr = H.sign_token(fake, "approval+jwt", {"tx_hash": H.sha256(H.canon(tx)), **tx})
    r, _ = req(w, "pharmacy_change", f, prm, approval=appr, mandate=child, nonce=n)
    return w["cp"].verify(r)


def a_approval_param_swap(w):
    # Patient approves transfer to one pharmacy; agent submits transfer to another.
    f = ["name", "dob", "pharmacy"]
    n = w["cp"].challenge()
    a = approve(w, "pharmacy_change", f, {"to_pharmacy": "cp:pharmacy-0412"}, n)
    r, _ = req(w, "pharmacy_change", f, {"to_pharmacy": "cp:attacker-pharmacy"}, approval=a, nonce=n)
    return w["cp"].verify(r)


def a_controlled_refill_without_stepup(w):
    # The agent also asserts controlled_substance=False; the counterparty ignores agent flags.
    r, _ = req(w, "refill_request", ["name", "dob", "medication_list"], {"drug": "oxycodone 10 mg", "controlled_substance": False})
    return w["cp"].verify(r)


def a_brand_protected_drug_without_stepup(w):
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "Sublocade 300 mg"})
    return w["cp"].verify(r)


def a_unknown_drug_without_stepup(w):
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "NDC 12496-1208-1"})
    return w["cp"].verify(r)


def a_drug_hidden_under_other_key(w):
    r, _ = req(w, "refill_request", ["name", "dob"], {"medication": "oxycodone 10 mg"})
    return w["cp"].verify(r)


def a_refill_without_drug_identifier(w):
    r, _ = req(w, "refill_request", ["name", "dob"], {})
    return w["cp"].verify(r)


def a_protected_refill_at_new_pharmacy_without_stepup(w):
    # Same drug at a pharmacy that does not hold the prescription: the request discloses it, so tier 3.
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "sertraline 50 mg"}, cp=w["cp2"])
    r2 = w["ag"].request(w["att"], w["m"], w["disc"], w["consent"], w["cert"], "refill_request", {"drug": "sertraline 50 mg"},
                         w["cp2"].counterparty_id, "pharmacy", ["name", "dob"], w["cp2"].challenge())
    return w["cp2"].verify(r2)


def a_operator_attaches_other_persons_consent(w):
    # Compromised operator holds a real consent from certified person Q and issues a mandate over victim X's record.
    q = H.Patient("patient-Q", "Quinn Q. Other", "1975-05-05")
    q_cert = w["idp"].certify(q)
    qc, qcd = q.consent(w["op"].operator_id, w["ag"].agent_id, "TREAT", ["refill_request", "pharmacy_change"], ["name", "dob"], ["pharmacy"])
    victim = {"name": "Canary Q. Member", "dob": "1981-03-14"}
    disc = {("action", "refill_request"): H.disclosure("action", ["refill_request", 2]),
            ("field", "name"): H.disclosure("name", victim["name"]), ("field", "dob"): H.disclosure("dob", victim["dob"]),
            ("subject", "pharmacy"): H.disclosure("subject:pharmacy", "x"), **{("consent", k): v for k, v in qcd.items()}}
    p_m = H.peek(w["m"])
    m = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**p_m, "mandate_id": "m-mix", "_sd": sorted(H.digest(v) for k, v in disc.items() if k[0] in ("action", "field", "subject")),
                                                    "consent_hash": H.sha256(qc.encode()), "patient_pub": H.pub_bytes(q.pk)})
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "metformin 500 mg"}, mandate=m, disc=disc, consent=qc, cert=q_cert)
    return w["cp"].verify(r)


def _quinn_mandate(w, disc_extra, fields_override=None):
    q = H.Patient("patient-Q", "Quinn Q. Other", "1975-05-05")
    q_cert = w["idp"].certify(q)
    qc, qcd = q.consent(w["op"].operator_id, w["ag"].agent_id, "TREAT", ["refill_request"], ["name", "dob"], ["pharmacy"])
    disc = {("action", "refill_request"): H.disclosure("action", ["refill_request", 2]),
            ("subject", "pharmacy"): disc_extra.pop("subject"), **disc_extra, **{("consent", k): v for k, v in qcd.items()}}
    p_m = H.peek(w["m"])
    sd = set()
    for k, v in disc.items():
        if k[0] in ("action", "subject"):
            sd.add(H.digest(v))
        elif k[0] == "field" or k[0] == "dupfield":
            sd.add(H.digest(v))
    m = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**p_m, "mandate_id": "m-q", "_sd": sorted(sd),
                                                    "consent_hash": H.sha256(qc.encode()), "patient_pub": H.pub_bytes(q.pk)})
    return q, q_cert, qc, m, disc


def a_duplicate_identity_fields(w):
    # Victim's name and DOB first, certified person's second; only one copy per field may be accepted.
    v_name, v_dob = H.disclosure("name", "Canary Q. Member"), H.disclosure("dob", "1981-03-14")
    q_name, q_dob = H.disclosure("name", "Quinn Q. Other"), H.disclosure("dob", "1975-05-05")
    q, q_cert, qc, m, disc = _quinn_mandate(w, {"subject": H.disclosure("subject:pharmacy", "x"),
                                                ("field", "name"): q_name, ("field", "dob"): q_dob,
                                                ("dupfield", "name"): v_name, ("dupfield", "dob"): v_dob})
    n = w["cp"].challenge()
    r = w["ag"].request(w["att"], m, disc, qc, q_cert, "refill_request", {"drug": "metformin 500 mg"}, w["cp"].counterparty_id,
                        "pharmacy", ["name", "dob"], n)
    r["fields"] = ["dob", "dob", "name", "name"]
    r["disclosures"] = [v_dob, q_dob, v_name, q_name]
    r["consent_disclosures"] = [r["consent_disclosures"][0], r["consent_disclosures"][1], r["consent_disclosures"][1],
                                r["consent_disclosures"][2], r["consent_disclosures"][2]]
    r["sig"] = H.b64u(w["ag"].sk.sign(H.canon({k: v for k, v in r.items() if k != "sig"})))
    return w["cp"].verify(r)


def a_victim_pseudonym_with_certified_identity(w):
    # Certified person's name and DOB with the victim's pharmacy pseudonym, for a protected refill the victim's
    # pharmacy holds: the counterparty must not treat it as held (records match on certified identity only).
    victim_pseud = w["op"].pseudonym(w["pt"], "pharmacy")
    q, q_cert, qc, m, disc = _quinn_mandate(w, {"subject": H.disclosure("subject:pharmacy", victim_pseud),
                                                ("field", "name"): H.disclosure("name", "Quinn Q. Other"),
                                                ("field", "dob"): H.disclosure("dob", "1975-05-05")})
    r = w["ag"].request(w["att"], m, disc, qc, q_cert, "refill_request", {"drug": "sertraline 50 mg"}, w["cp"].counterparty_id,
                        "pharmacy", ["name", "dob"], w["cp"].challenge())
    return w["cp"].verify(r)


def a_ambiguous_identity_steered_by_member_id(w):
    # Two certified people share a name and date of birth in this counterparty's records; the operator tries to steer
    # the request with a member identifier the patient never certified.
    w["cp"].identity_counts[("canary q. member", "1981-03-14")] = 2
    r, _ = req(w, "refill_request", ["name", "dob", "member_id"], {"drug": "metformin 500 mg"})
    return w["cp"].verify(r)


def a_dialysis_ride_cancel_mislabelled(w):
    # The broker's record says ride R-555 is dialysis transport for this member; the agent labels it primary care.
    w["cp"].object_records["R-555"] = ("canary q. member", "1981-03-14", "dialysis")
    return _cancel(w, {"ride_id": "R-555", "service": "primary care"})


def a_dialysis_ride_cancel_unlabelled(w):
    w["cp"].object_records["R-555"] = ("canary q. member", "1981-03-14", "dialysis")
    return _cancel(w, {"ride_id": "R-555"})


def a_ride_cancel_unresolved_id(w):
    return _cancel(w, {"ride_id": "R-UNKNOWN", "service": "primary care"})


def _cancel(w, params):
    # Mandate and consent that permit nemt_ride_cancel (base tier 2) for this member.
    c, cd = w["pt"].consent(w["op"].operator_id, w["ag"].agent_id, "TREAT", ["nemt_ride_cancel"], ["name", "dob"], ["pharmacy"])
    m, d = w["op"].issue_mandate(w["pt"], w["cert"], w["idp"].pk, c, cd, w["ag"], record_for(w["pt"]), ["nemt_ride_cancel"],
                                 ["name", "dob"], ["pharmacy"], 3)
    r, _ = req(w, "nemt_ride_cancel", ["name", "dob"], params, mandate=m, disc=d, consent=c)
    return w["cp"].verify(r)


def a_protected_drugs_in_field_value_at_new_pharmacy(w):
    # medication_list is an ordinary field name, but its value names HIV and opioid-treatment drugs.
    disc = dict(w["disc"])
    disc[("field", "medication_list")] = H.disclosure("medication_list", "biktarvy; suboxone 8 mg film")
    p_m = H.peek(w["m"])
    m = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**p_m, "mandate_id": "m-ml", "_sd": sorted(set(p_m["_sd"]) | {H.digest(disc[("field", "medication_list")])})})
    r = w["ag"].request(w["att"], m, disc, w["consent"], w["cert"], "pa_status_inquiry", {"drug": "metformin 500 mg"},
                        w["cp2"].counterparty_id, "pharmacy", ["name", "dob", "medication_list"], w["cp2"].challenge())
    return w["cp2"].verify(r)


def a_benign_drug_masks_controlled(w):
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "metformin oxycodone 10 mg"})
    return w["cp"].verify(r)


def a_benign_drug_masks_protected_at_new_pharmacy(w):
    r = w["ag"].request(w["att"], w["m"], w["disc"], w["consent"], w["cert"], "refill_request", {"drug": "lisinopril sertraline"},
                        w["cp2"].counterparty_id, "pharmacy", ["name", "dob"], w["cp2"].challenge())
    return w["cp2"].verify(r)


def a_request_without_identity_fields(w):
    r, _ = req(w, "refill_request", ["medication_list"], {"drug": "metformin 500 mg"})
    return w["cp"].verify(r)


def a_expired_parent_attestation(w):
    sub = H.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    child, cdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["refill_request"], ["name", "dob"], ["pharmacy"], 2, 600)
    old_parent_att = w["op"].attest(w["ag"], "model-x", "2026-10", POLICY, 3, ttl=-86400)
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "metformin 500 mg"}, agent=sub, att=sub_att, mandate=child,
               disc=cdisc, chain=[old_parent_att])
    return w["cp"].verify(r)


def a_chain_attestation_overrides_presenter(w):
    sub = H.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    child, cdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["refill_request"], ["name", "dob"], ["pharmacy"], 2, 600)
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "metformin 500 mg"}, agent=sub, att=sub_att, mandate=child,
               disc=cdisc, chain=[w["att"], w["op"].attest(sub, "model-y", "old", POLICY, 3)])
    return w["cp"].verify(r)


def a_protected_drug_in_params_without_stepup(w):
    r, _ = req(w, "pa_status_inquiry", ["name", "dob"], {"drug": "buprenorphine-naloxone 8-2 mg"})
    return w["cp"].verify(r)


def a_patient_revoked_consent_operator_ignores(w):
    w["idp"].revoke_consent(w["pt"].revoke(w["consent"]), w["consent"])
    r, _ = req(w, "refill_request", ["name", "dob"])
    return w["cp"].verify(r)


def a_revoked_agent_key(w):
    w["op"].status.revoked_agents.add(w["ag"].agent_id)
    r, _ = req(w, "refill_request", ["name", "dob"])
    return w["cp"].verify(r)


def a_stale_request(w):
    r, n = req(w, "refill_request", ["name", "dob"])
    w["cp"].issued_nonces[n] = (time.time() - 10_000, H.NONCE_TTL)
    return w["cp"].verify(r)


def a_unknown_action(w):
    disc = dict(w["disc"])
    disc[("action", "transfer_funds")] = H.disclosure("action", "transfer_funds")
    r, _ = req(w, "transfer_funds", ["name", "dob"], disc=disc)
    return w["cp"].verify(r)


def a_receipt_subject_swap(w):
    # Child mandate tries to change the subject; fixed claims must match along the chain.
    sub = H.Agent("agent:sub-scheduler")
    sub_att = w["op"].attest(sub, "model-y", "2026-10", POLICY, 2)
    p = H.peek(w["m"])
    child = H.sign_token(w["ag"].sk, "mandate+sd-jwt", {**p, "mandate_id": "m-swap", "agent_id": sub.agent_id,
                                                        "consent_hash": "deadbeef",
                                                        "parent": {"token": w["m"], "hash": H.sha256(w["m"].encode())}})
    r, _ = req(w, "refill_request", ["name", "dob"], agent=sub, att=sub_att, mandate=child, chain=[w["att"]])
    return w["cp"].verify(r)


LEGIT = {"legit_T0_hours_without_phi": legit_t0_hours_without_phi, "legit_T3_approval_after_ten_minutes": legit_t3_approval_after_ten_minutes, "legit_T2_refill": legit_t2, "legit_T2_routine_ride_cancel_from_record": legit_t2_routine_ride_cancel_from_record, "legit_T2_protected_refill_at_holding_pharmacy": legit_t2_protected_refill_at_holding_pharmacy, "legit_T3_controlled_refill_with_stepup": legit_t3_controlled_refill_with_stepup, "legit_T3_pharmacy_change_with_stepup": legit_t3, "legit_subagent_attenuated": legit_sub}
ATTACKS = {
    "impersonated_operator": a_impersonated_operator, "forged_attestation": a_forged_attestation,
    "stolen_mandate_without_agent_key": a_stolen_mandate, "mandate_presented_by_other_agent": a_other_agent,
    "replayed_request": a_replay, "request_redirected_to_other_counterparty": a_wrong_audience,
    "expired_mandate": a_expired_mandate, "revoked_mandate": a_revoked_mandate, "revoked_operator": a_revoked_operator,
    "action_outside_mandate": a_action_escalation, "field_outside_mandate": a_field_escalation,
    "tier3_without_stepup": a_t3_without_stepup, "stepup_approval_replayed": a_approval_replay,
    "stepup_approval_for_other_counterparty": a_approval_other_counterparty,
    "subagent_attenuation_violation": a_attenuation_violation, "subagent_after_parent_revoked": a_sub_after_parent_revoked,
    "compromised_operator_mandate_beyond_consent": a_operator_beyond_consent,
    "compromised_operator_fabricated_consent": a_operator_fabricated_consent,
    "consent_replayed_by_other_operator": a_consent_replayed_by_other_operator,
    "self_delegation_with_fake_patient_key": a_self_delegation_fake_patient_key,
    "approval_parameters_swapped": a_approval_param_swap,
    "controlled_substance_refill_without_stepup_agent_flag_false": a_controlled_refill_without_stepup,
    "brand_name_protected_drug_without_stepup": a_brand_protected_drug_without_stepup,
    "unknown_drug_without_stepup": a_unknown_drug_without_stepup,
    "expired_parent_attestation": a_expired_parent_attestation,
    "compromised_operator_attaches_other_persons_consent": a_operator_attaches_other_persons_consent,
    "benign_drug_name_masks_controlled_drug": a_benign_drug_masks_controlled,
    "protected_drugs_in_ordinary_field_value_at_new_pharmacy": a_protected_drugs_in_field_value_at_new_pharmacy,
    "dialysis_ride_cancel_labelled_primary_care": a_dialysis_ride_cancel_mislabelled,
    "dialysis_ride_cancel_without_label_without_stepup": a_dialysis_ride_cancel_unlabelled,
    "ride_cancel_with_unresolved_id_without_stepup": a_ride_cancel_unresolved_id,
    "ambiguous_identity_steered_by_member_id": a_ambiguous_identity_steered_by_member_id,
    "duplicate_identity_fields": a_duplicate_identity_fields,
    "victim_pseudonym_with_certified_identity_without_stepup": a_victim_pseudonym_with_certified_identity,
    "benign_drug_name_masks_protected_drug_at_new_pharmacy": a_benign_drug_masks_protected_at_new_pharmacy,
    "request_without_identity_fields": a_request_without_identity_fields,
    "drug_hidden_under_other_parameter_key": a_drug_hidden_under_other_key,
    "refill_without_drug_identifier_without_stepup": a_refill_without_drug_identifier,
    "protected_refill_at_new_pharmacy_without_stepup": a_protected_refill_at_new_pharmacy_without_stepup,
    "chain_attestation_overrides_presenting_agent": a_chain_attestation_overrides_presenter,
    "protected_drug_named_in_parameters_without_stepup": a_protected_drug_in_params_without_stepup,
    "patient_revoked_consent_operator_ignores": a_patient_revoked_consent_operator_ignores,
    "revoked_agent_key": a_revoked_agent_key, "stale_request": a_stale_request, "unknown_action": a_unknown_action,
    "subagent_changes_fixed_claim": a_receipt_subject_swap,
}
ISSUER_SIDE = {"consent_attached_to_other_record": a_consent_attached_to_other_record,
               "third_party_revokes_consent": a_third_party_revokes_consent}


def log_tests():
    log = H.TransparencyLog()
    hashes = [H.sha256(f"r{i}".encode()) for i in range(13)]
    for h in hashes[:7]:
        log.append(h)
    old = H.peek(log.sth())
    for h in hashes[7:]:
        log.append(h)
    new = H.peek(log.sth())
    inc = all(H.TransparencyLog.verify_inclusion(hashes[i], i, new["size"], log.inclusion_proof(i), new["root"]) for i in range(13))
    cons = H.TransparencyLog.verify_consistency(old["size"], new["size"], log.consistency_proof(old["size"]), old["root"], new["root"])
    log.leaves[3] = H._leaf(H.sha256(b"tampered"))
    tampered_root = H._mth(log.leaves).hex()
    tamper_detected = (tampered_root != new["root"]
                       and not H.TransparencyLog.verify_consistency(old["size"], new["size"], log.consistency_proof(old["size"]), old["root"], new["root"]))
    return {"inclusion_proofs_verify": inc, "consistency_proof_verifies": cons, "tamper_detected": tamper_detected,
            "domain_separated_rfc9162": True}


def voice_tests():
    w = world("L4_full_hah")
    cpid = w["cp"].counterparty_id
    vs = H.VerificationService(w["op"], w["idp"], {cpid: w["cp"].pk, "cp:pharmacy-0999": w["cp2"].pk, "cp:payer-77": w["cp2"].pk},
                               {cpid: "pharmacy", "cp:pharmacy-0999": "pharmacy", "cp:payer-77": "payer"})
    rx = {"drug": "metformin 500 mg"}
    subj = "canary q. member 1981-03-14"   # full proofed name and date of birth

    def look(code, cp=None, subject=subj, params=rx, sk=None, nonce=None, sign_subject=None):
        cp = cp or w["cp"]
        n = nonce or vs.lookup_challenge()
        body = {"nonce": n, "code": code, "counterparty_id": cp.counterparty_id,
                "subject_hash": H.sha256((sign_subject or subject).strip().lower().encode()), "params_hash": H.sha256(H.canon(params))}
        sig = H.b64u((sk or cp.sk).sign(H.canon(body)))
        return vs.lookup(code, cp.counterparty_id, subject, params, n, sig), (n, sig)

    def refused(fn):
        try:
            fn()
            return False
        except ValueError:
            return True

    def reg(action, params, target=None, signer=None, signed_subject=None, mandate=None, disc=None, **kw):
        target = target or cpid
        n_reg = vs.registration_challenge()
        sig = (signer or w["ag"]).sign_code_registration(n_reg, mandate or w["m"], action, params, target, signed_subject or subj)
        return vs.register(mandate or w["m"], disc or w["disc"], w["consent"], w["cert"], w["att"], action, params, target, n_reg, sig, **kw)

    c1 = reg("refill_request", rx)
    first, _ = look(c1)
    reuse, _ = look(c1)
    c2 = reg("refill_request", rx)
    other, _ = look(c2, cp=w["cp2"])
    c3 = reg("refill_request", rx)
    mismatch, (mn, msig) = look(c3, subject="someone else 1990-01-01")
    replayed_lookup = vs.lookup(c3, cpid, subj, rx, mn, msig)
    after_mismatch, _ = look(c3)
    c4 = reg("refill_request", rx)
    unauth, _ = look(c4, sk=Ed25519PrivateKey.generate())
    c5 = reg("refill_request", rx)
    wrong_params, _ = look(c5, params={"drug": "oxycodone 10 mg"})
    after_wrong_params, _ = look(c5)
    limited = [look("AAAAAAAA", cp=w["cp2"])[0] for _ in range(25)]
    t3 = {"to_pharmacy": cpid, "drug": "metformin 500 mg"}
    no_appr = refused(lambda: reg("pharmacy_change", t3))
    out_of_mandate = refused(lambda: reg("medication_cancel", {"drug": "metformin 500 mg"}))
    n = vs.phone_challenge()
    appr = w["pt"].approve(H.peek(w["m"])["mandate_id"], "pharmacy_change", t3, cpid, [], n)
    c6 = reg("pharmacy_change", t3, approval=appr, phone_nonce=n)
    t3_lookup, _ = look(c6, params=t3)
    reused_approval = refused(lambda: reg("pharmacy_change", t3, approval=appr, phone_nonce=n))
    relayed_mint = refused(lambda: reg("refill_request", rx, signer=H.Agent(w["ag"].agent_id)))
    low = H.Agent("agent:compass-voice-1")
    low_att = w["op"].attest(low, "m", "v", POLICY, 1)
    def reg_low():
        n_reg = vs.registration_challenge()
        return vs.register(w["m"], w["disc"], w["consent"], w["cert"], low_att, "refill_request", rx, cpid, n_reg,
                           low.sign_code_registration(n_reg, w["m"], "refill_request", rx, cpid, subj))
    above_ceiling = refused(reg_low)
    # Agent signs a different subject than the certified person in the mandate.
    relabelled = refused(lambda: reg("refill_request", rx, signed_subject="other person 1990-01-01"))
    # Mandate whose name and date of birth do not open the certified commitment (operator mislabels the subject).
    p_m = H.peek(w["m"])
    bad_disc = dict(w["disc"])
    bad_disc[("field", "name")] = H.disclosure("name", "Other Person")
    bad_disc[("field", "dob")] = H.disclosure("dob", "1990-01-01")
    bad_m = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**p_m, "mandate_id": "m-other",
                         "_sd": sorted(set(p_m["_sd"]) | {H.digest(bad_disc[("field", "name")]), H.digest(bad_disc[("field", "dob")])})})
    wrong_person = refused(lambda: reg("refill_request", rx, signed_subject="other person 1990-01-01", mandate=bad_m, disc=bad_disc))
    # An in-mandate action's disclosure filed under an out-of-mandate action name.
    swapped = dict(w["disc"])
    swapped[("action", "appointment_cancel")] = w["disc"][("action", "pa_status_inquiry")]
    swapped[("consent", ("action", "appointment_cancel"))] = w["disc"][("consent", ("action", "pa_status_inquiry"))]
    swapped_action = refused(lambda: reg("appointment_cancel", {"service": "primary care"}, disc=swapped))
    # Patient sets refill_request to tier 3; a tier 1 disclosure filed under refill_request must not lower it.
    w3 = world("L4_full_hah")
    c3t, c3d = w3["pt"].consent(w3["op"].operator_id, w3["ag"].agent_id, "TREAT",
                                {"refill_request": 3, "pa_status_inquiry": 1}, ["name", "dob"], ["pharmacy"])
    m3, d3 = w3["op"].issue_mandate(w3["pt"], w3["cert"], w3["idp"].pk, c3t, c3d, w3["ag"], record_for(w3["pt"]),
                                    ["refill_request", "pa_status_inquiry"], ["name", "dob"], ["pharmacy"], 3)
    vs3 = H.VerificationService(w3["op"], w3["idp"], {w3["cp"].counterparty_id: w3["cp"].pk}, {w3["cp"].counterparty_id: "pharmacy"})
    d3s = dict(d3)
    d3s[("action", "refill_request")] = d3[("action", "pa_status_inquiry")]
    d3s[("consent", ("action", "refill_request"))] = d3[("consent", ("action", "pa_status_inquiry"))]
    def reg3(dd):
        n_reg = vs3.registration_challenge()
        sig = w3["ag"].sign_code_registration(n_reg, m3, "refill_request", rx, w3["cp"].counterparty_id, subj)
        return vs3.register(m3, dd, c3t, w3["cert"], w3["att"], "refill_request", rx, w3["cp"].counterparty_id, n_reg, sig)
    patient_tier3_honest = refused(lambda: reg3(d3))
    patient_tier3_swapped = refused(lambda: reg3(d3s))
    other_class = refused(lambda: reg("refill_request", rx, target="cp:payer-77"))
    # revocations and expiry, at registration and at lookup
    c7 = reg("refill_request", rx)
    w["idp"].revoke_consent(w["pt"].revoke(w["consent"]), w["consent"])
    revoked_at_lookup, _ = look(c7)
    consent_revoked_at_register = refused(lambda: reg("refill_request", rx))
    w2 = world("L4_full_hah")
    cp2id = w2["cp"].counterparty_id
    vs2 = H.VerificationService(w2["op"], w2["idp"], {cp2id: w2["cp"].pk}, {cp2id: "pharmacy"})

    def reg2(m, d):
        n_reg = vs2.registration_challenge()
        sig = w2["ag"].sign_code_registration(n_reg, m, "refill_request", rx, cp2id, subj)
        return vs2.register(m, d, w2["consent"], w2["cert"], w2["att"], "refill_request", rx, cp2id, n_reg, sig)
    w2["op"].status.revoked_mandates.add(H.peek(w2["m"])["mandate_id"])
    mandate_revoked_at_register = refused(lambda: reg2(w2["m"], w2["disc"]))
    m_exp, d_exp = w2["op"].issue_mandate(w2["pt"], w2["cert"], w2["idp"].pk, w2["consent"], w2["cdisc"], w2["ag"],
                                          record_for(w2["pt"]), ["refill_request"], ["name", "dob"], ["pharmacy"], 3, ttl=-1)
    expired_at_register = refused(lambda: reg2(m_exp, d_exp))
    return {"valid_code_lookup_succeeds_with_subject_and_params_match": bool(first) and first.get("subject_match") is True and first.get("params_match") is True,
            "lookup_returns_agent": bool(first) and first.get("agent") == w["ag"].agent_id,
            "lookup_returns_no_parameters": bool(first) and "params" not in first and "params_hash" not in first,
            "code_reuse_rejected": reuse is None, "code_for_other_counterparty_rejected": other is None,
            "subject_mismatch_reported": mismatch == {"subject_match": False},
            "subject_mismatch_does_not_consume_code": bool(after_mismatch) and after_mismatch.get("subject_match") is True,
            "unauthenticated_counterparty_lookup_rejected": unauth == {"error": "counterparty_not_authenticated"},
            "captured_lookup_replay_with_other_subject_rejected": replayed_lookup == {"error": "counterparty_not_authenticated"},
            "stated_parameter_mismatch_reported": bool(wrong_params) and wrong_params.get("params_match") is False,
            "parameter_mismatch_does_not_consume_code": bool(after_wrong_params) and after_wrong_params.get("params_match") is True,
            "tier3_without_patient_approval_refused": no_appr, "action_outside_mandate_refused": out_of_mandate,
            "tier3_with_approval_reports_verified": bool(t3_lookup) and t3_lookup.get("patient_approval_verified") is True,
            "phone_approval_reuse_refused": reused_approval,
            "code_minted_without_agent_key_refused": relayed_mint,
            "code_above_attested_tier_ceiling_refused": above_ceiling,
            "code_with_subject_other_than_signed_refused": relabelled,
            "action_disclosure_filed_under_other_action_refused": swapped_action,
            "patient_set_tier3_requires_approval_by_telephone": patient_tier3_honest,
            "patient_set_tier3_not_lowered_by_substituted_disclosure": patient_tier3_swapped,
            "code_for_person_other_than_certified_refused": wrong_person,
            "code_for_counterparty_class_outside_mandate_refused": other_class,
            "consent_revoked_after_issue_blocks_lookup": revoked_at_lookup == {"error": "revoked_or_expired"},
            "consent_revoked_blocks_registration": consent_revoked_at_register,
            "mandate_revoked_blocks_registration": mandate_revoked_at_register,
            "expired_mandate_blocks_registration": expired_at_register,
            "enumeration_rate_limited": any(isinstance(x, dict) and x.get("error") == "rate_limited" for x in limited),
            "code_space": len(H.VerificationService.ALPHABET) ** 8}


def receipt_and_gate_tests():
    w = world("L4_full_hah")
    before = len(w["log"].leaves)
    r, _ = req(w, "refill_request", ["name", "dob"], {"drug": "buprenorphine 8 mg"}, cp=w["cp2"])
    r = w["ag"].request(w["att"], w["m"], w["disc"], w["consent"], w["cert"], "refill_request", {"drug": "buprenorphine 8 mg"},
                        w["cp2"].counterparty_id, "pharmacy", ["name", "dob"], w["cp2"].challenge())
    ok, why, rec = w["cp2"].verify(r)
    refusal_logged = (not ok) and bool(rec) and "refusal_receipt" in rec and len(w["log"].leaves) == before + 1
    refusal_has_no_values = bool(rec) and "buprenorphine" not in H.b64u_dec(rec["refusal_receipt"].split(".")[1]).decode()
    gate_t3 = H.operator_gate("refill_request", ["name", "dob"], {"drug": "buprenorphine 8 mg"}, ["Canary Q. Member", "1981-03-14"], 2) == 3
    gate_t2 = H.operator_gate("refill_request", ["name", "dob"], {"drug": "metformin 500 mg"}, ["Canary Q. Member", "1981-03-14"], 2) == 2
    gate_value = H.operator_gate("pa_status_inquiry", ["name", "dob", "medication_list"], {"drug": "metformin 500 mg"},
                                 ["biktarvy; metformin"], 1) == 3
    return {"rejected_authenticated_request_gets_signed_refusal_receipt": refusal_logged,
            "refusal_receipt_carries_no_field_values": refusal_has_no_values,
            "operator_gate_requires_approval_before_sending_protected_refill": gate_t3,
            "operator_gate_allows_routine_refill": gate_t2,
            "operator_gate_classifies_field_values": gate_value}


def main():
    rows, out = [], {"levels": list(H.LEVELS), "legit": {}, "attacks": {}, "issuer_side": {}}
    for name, fn in {**LEGIT, **ATTACKS}.items():
        for level in H.LEVELS:
            ok, why, _ = fn(world(level))
            kind = "legit" if name in LEGIT else "attack"
            rows.append({"case": name, "kind": kind, "level": level, "accepted": ok, "reason": why})
            out["legit" if kind == "legit" else "attacks"].setdefault(name, {})[level] = {"accepted": ok, "reason": why}
    for name, fn in ISSUER_SIDE.items():
        ok, why, _ = fn(world("L4_full_hah"))
        out["issuer_side"][name] = {"issued": ok, "reason": why}
    for level in H.LEVELS:
        acc = [r["accepted"] for r in rows if r["kind"] == "attack" and r["level"] == level]
        out.setdefault("attack_success", {})[level] = {"accepted": sum(acc), "total": len(acc)}
        lg = [r["accepted"] for r in rows if r["kind"] == "legit" and r["level"] == level]
        out.setdefault("legit_acceptance", {})[level] = {"accepted": sum(lg), "total": len(lg)}
    out["log_integrity"] = log_tests()
    out["voice_code"] = voice_tests()
    out["receipts_and_gate"] = receipt_and_gate_tests()
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "conformance_v2.json").write_text(json.dumps(out, indent=2))
    with open(ROOT / "results" / "conformance_v2_matrix.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    print(json.dumps({k: out[k] for k in ("attack_success", "legit_acceptance", "issuer_side", "log_integrity", "voice_code")}, indent=1))


if __name__ == "__main__":
    main()
