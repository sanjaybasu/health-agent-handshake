"""Conformance suite for the permission-carrying (redemption) mode, handshake/hah2_redeem.py.

Legitimate requests must be verified, redeemed, and opened, and the counterparty must receive exactly the requested
fields. Every attack must be refused at the counterparty, the data holder, or both, and each refusal must give the
expected reason. Malformed inputs must be refused, never raised. A separate check confirms that the tokens the agent holds
or sends carry no field value and no opening of the identity commitment. Writes results/redemption_conformance.json.
"""
import copy
import json
import math
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "handshake"))
import hah2 as H  # noqa: E402
import hah2_redeem as R  # noqa: E402

POLICY = "Disclose AI status; act only within mandate; disclose only allowlisted fields."
ACTIONS = ["pa_status_inquiry", "refill_request", "pharmacy_change"]
FIELDS = ["name", "dob", "member_id", "medication_list", "pharmacy"]
NAME, DOB = "Canary Q. Member", "1981-03-14"
RECORD = {"name": NAME, "dob": DOB, "member_id": "WM-7Q3X9KZ", "medication_list": "metformin 500 mg; lisinopril 10 mg",
          "pharmacy": "Pharmacy 0412", "address": "88 Canary Lane", "ssn_last4": "8392",
          "sud_treatment": "buprenorphine maintenance"}
HOLDER, HOLDER2 = "holder:health-plan-01", "holder:health-plan-02"
P = {"drug": "metformin 500 mg"}
F = ["dob", "member_id", "name"]
T3 = {"drug": "metformin 500 mg", "to_pharmacy": "Pharmacy 0412", "from_pharmacy": "Pharmacy 0001"}


def world(record=None):
    w = {"d": H.Directory(), "cps": R.CounterpartyDirectory(), "idp": H.IdentityProvider(), "log": H.TransparencyLog()}
    w["op"] = H.Operator("op:test", "Test Operator PBC", "business_associate", w["d"])
    st = {w["op"].operator_id: w["op"].status}
    w["st"] = st
    w["holder"] = R.DataHolder(HOLDER, w["d"], st, w["idp"], w["cps"], log=w["log"])
    w["holder2"] = R.DataHolder(HOLDER2, w["d"], st, w["idp"], w["cps"])
    holders = {HOLDER: w["holder"].pk, HOLDER2: w["holder2"].pk}
    for key, cid, cls in [("cp", "cp:pharmacy-0412", "pharmacy"), ("cp2", "cp:pharmacy-0999", "pharmacy"),
                          ("broker", "cp:broker-01", "transport_broker")]:
        w[key] = R.RedeemingCounterparty(cid, cls, w["d"], st, w["idp"], w["log"], holders=holders)
        w["cps"].register(w[key].directory_entry())        # the trust framework registers vetted counterparties
    w["pt"] = H.Patient("patient-001", NAME, DOB)
    w["holder"].add_record(w["pt"].subject_commitment, record or RECORD)
    w["cert"] = w["idp"].certify(w["pt"])
    w["ag"] = H.Agent("agent:voice-1")
    w["consent"], w["cdisc"] = w["pt"].consent(w["op"].operator_id, w["ag"].agent_id, "TREAT", ACTIONS, FIELDS, ["pharmacy"])
    w["att"] = w["op"].attest(w["ag"], "model-x", "2026-10", POLICY, 3)
    w["m"], w["disc"] = R.issue_reference_mandate(w["op"], w["pt"], w["cert"], w["idp"].pk, w["consent"], w["cdisc"],
                                                  w["ag"], HOLDER, ACTIONS, FIELDS, ["pharmacy"], 3)
    return w


def make_req(w, action, fields, params, cp=None, approval=None, disc=None, mandate=None, att=None, agent=None, chain=None):
    cp = cp or w["cp"]
    n = cp.challenge(H.TIER3_TRANSACTION_TTL if approval else H.NONCE_TTL)
    if approval == "auto":
        approval = w["pt"].approve(H.peek(mandate or w["m"])["mandate_id"] if chain is None else H.peek(w["m"])["mandate_id"],
                                   action, params, cp.counterparty_id, fields, n)
    return (agent or w["ag"]).request(att or w["att"], mandate or w["m"], disc or w["disc"], w["consent"], w["cert"], action,
                                      params, cp.counterparty_id, cp.cls, fields, n, approval=approval,
                                      chain_attestations=chain)


def resign(w, req, agent=None, **changes):
    """The agent (or a compromised agent) re-signs a modified request."""
    r = {k: v for k, v in req.items() if k != "sig"}
    r.update(changes)
    r["sig"] = H.b64u((agent or w["ag"]).sk.sign(H.canon(r)))
    return r


def full_flow(w, req, cp=None, holder=None):
    cp = cp or w["cp"]
    ok, why, ctx = cp.verify_reference(req)
    if not ok:
        return {"stage": "counterparty", "ok": False, "why": why}
    ok, why, rel = (holder or w["holder"]).redeem(cp.redemption(req, ctx["holder_id"]))
    if not ok:
        return {"stage": "holder", "ok": False, "why": why}
    ok, why, vals = cp.open_release(req, ctx, rel)
    return {"stage": "open", "ok": ok, "why": why, "values": vals, "release": rel}


# ---------------------------------------------------------------- legitimate

def legit_cases():
    out = {}
    w = world()
    r = full_flow(w, make_req(w, "pa_status_inquiry", F, P))
    out["tier1_pa_status"] = r["ok"] and r["values"] == {k: RECORD[k] for k in F}
    out["release_logged_in_transparency_log"] = r["ok"] and isinstance(r["release"].get("log_index"), int)
    w = world()
    r = full_flow(w, make_req(w, "refill_request", ["dob", "medication_list", "name"], P))
    out["tier2_refill"] = r["ok"] and set(r["values"]) == {"dob", "medication_list", "name"}
    w = world()
    r = full_flow(w, make_req(w, "pharmacy_change", ["dob", "name", "pharmacy"], T3, approval="auto"))
    out["tier3_pharmacy_change_with_approval"] = r["ok"]
    # A protected drug in a released value raises the tier at the holder; with the patient's approval it is released.
    w = world({**RECORD, "medication_list": "buprenorphine 8 mg film; metformin 500 mg"})
    r = full_flow(w, make_req(w, "refill_request", ["dob", "medication_list", "name"], P, approval="auto"))
    out["protected_value_released_with_approval"] = r["ok"]
    # Delegation: a sub-agent with a narrower mandate is verified through the chain at the counterparty and the holder.
    w = world()
    sub = H.Agent("agent:sub-1")
    sub_att = w["op"].attest(sub, "model-x", "2026-10", POLICY, 3)
    sm, sdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["pa_status_inquiry"], F, ["pharmacy"], 3, 3600)
    r = full_flow(w, make_req(w, "pa_status_inquiry", F, P, mandate=sm, disc=sdisc, att=sub_att, agent=sub, chain=[w["att"]]))
    out["delegated_subagent_via_chain"] = r["ok"]
    return out


# ---------------------------------------------------------------- attacks: (refused?, reason, expected reason prefix)

def attacks():
    out = {}

    def rec(name, ok, why, expect):
        out[name] = {"refused": not ok, "reason": why, "expected": expect, "reason_as_expected": (not ok) and why.startswith(expect)}

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    w["cp"].verify_reference(req)
    ok, why, _ = w["holder"].redeem(w["cp2"].redemption(req, HOLDER))
    rec("other_pharmacy_redeems_captured_request", ok, why, "P1_wrong_audience")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    rogue = R.RedeemingCounterparty("cp:rogue", "pharmacy", w["d"], w["st"], w["idp"], w["log"])  # never registered
    ok, why, _ = w["holder"].redeem(rogue.redemption(req, HOLDER))
    rec("unregistered_party_redeems", ok, why, "R_unknown_redeemer")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    red = w["cp2"].redemption(req, HOLDER)
    red["counterparty_id"] = w["cp"].counterparty_id          # claims the addressed pharmacy's identity, own key
    ok, why, _ = w["holder"].redeem(red)
    rec("redemption_signed_with_another_key", ok, why, "R_bad_redeemer_signature")

    w = world()
    impostor = R.RedeemingCounterparty("cp:pharmacy-0412", "pharmacy", w["d"], w["st"], w["idp"], w["log"])
    try:
        w["cps"].register(impostor.directory_entry())
        rec("impostor_overwrites_directory_entry", True, "registered", "R_duplicate")
    except ValueError:
        rec("impostor_overwrites_directory_entry", False, "R_duplicate_registration_refused", "R_duplicate")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    w["cps"].entries[w["cp"].counterparty_id].revoked = True
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("revoked_counterparty_redeems", ok, why, "R_unknown_redeemer")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    red = w["cp"].redemption(req, HOLDER)
    ok1, _, _ = w["holder"].redeem(red)
    ok, why, _ = w["holder"].redeem(red)
    rec("replayed_redemption", ok or not ok1, why if ok1 else "first_redemption_failed", "R_already_redeemed")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    ok1, _, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    again = resign(w, req, ts=req["ts"] + 1)                    # same challenge, re-signed with a new timestamp
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(again, HOLDER))
    rec("same_challenge_resigned_and_redeemed_again", ok or not ok1, why, "R_already_redeemed")

    w = world()
    req = resign(w, make_req(w, "pa_status_inquiry", F, P), nonce=None)
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("request_without_challenge", ok, why, "malformed")

    w = world()
    req = resign(w, make_req(w, "pa_status_inquiry", F, P), ts=float("nan"))
    ok_c, why_c, _ = w["cp"].verify_reference(req)
    red = {"request": req, "counterparty_id": w["cp"].counterparty_id, "holder_id": HOLDER, "sig": "AA"}
    ok, why, _ = w["holder"].redeem(red)
    rec("nan_timestamp_at_counterparty", ok_c, why_c, "malformed")
    rec("nan_timestamp_at_holder", ok, why, "malformed")

    w = world()
    fresh = make_req(w, "pa_status_inquiry", F, P)
    req = resign(w, fresh, ts=fresh["ts"] - 3600)
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("stale_request", ok, why, "P4_stale_request")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    t = copy.deepcopy(req)
    t["fields"] = sorted(F + ["medication_list"])
    t["disclosures"] = [w["disc"][("field", f)] for f in t["fields"]]
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(t, HOLDER))
    rec("counterparty_alters_signed_request_fields", ok, why, "P1_P2_bad_signature")

    # A compromised operator issues a mandate for a field the patient never consented to (sud_treatment).
    w = world()
    root = H.peek(w["m"])
    bad_disc = dict(w["disc"])
    bad_disc[("field", "sud_treatment")] = H.disclosure("sud_treatment", {R.REF_KEY: HOLDER})
    bad_m = H.sign_token(w["op"].sk, "mandate+sd-jwt",
                         {**root, "_sd": sorted(set(root["_sd"]) | {H.digest(bad_disc[("field", "sud_treatment")])})})
    bad_disc[("consent", ("field", "sud_treatment"))] = H.disclosure("field", "sud_treatment")  # not in consent _sd
    req = make_req(w, "pa_status_inquiry", sorted(F + ["sud_treatment"]), P, disc=bad_disc, mandate=bad_m)
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("compromised_operator_adds_unconsented_field", ok, why, "P3_mandate_exceeds_consent")

    # A compromised operator puts a value, not a reference, into a disclosure; refused at the counterparty and the holder.
    w = world()
    vd = dict(w["disc"])
    vd[("field", "member_id")] = H.disclosure("member_id", RECORD["member_id"])
    root = H.peek(w["m"])
    vm = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**root, "_sd": sorted(set(root["_sd"]) | {H.digest(vd[("field", "member_id")])})})
    req = make_req(w, "pa_status_inquiry", F, P, disc=vd, mandate=vm)
    ok_c, why_c, _ = w["cp"].verify_reference(req)
    ok_h, why_h, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("value_instead_of_reference_at_counterparty", ok_c, why_c, "R_field_value_carried_by_agent")
    rec("value_instead_of_reference_at_holder", ok_h, why_h, "R_field_value_carried_by_agent")

    # A compromised operator names an unknown holder (a covert channel in the holder name).
    w = world()
    cd = dict(w["disc"])
    root = H.peek(w["m"])
    newd = {f: H.disclosure(f, {R.REF_KEY: "ssn=8392;addr=88 Canary Lane"}) for f in F}
    cd.update({("field", f): d for f, d in newd.items()})
    cm = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**root, "_sd": sorted(set(root["_sd"]) | {H.digest(d) for d in newd.values()})})
    ok, why, _ = w["cp"].verify_reference(make_req(w, "pa_status_inquiry", F, P, disc=cd, mandate=cm))
    rec("unknown_holder_named_in_mandate", ok, why, "R_unknown_holder")

    w = world()
    req = resign(w, make_req(w, "pa_status_inquiry", F, P), subject_opening="0" * 32)
    ok, why, _ = w["cp"].verify_reference(req)
    rec("request_carries_identity_opening", ok, why, "R_identity_opening_carried_by_agent")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    w["idp"].revoke_consent(w["pt"].revoke(w["consent"]), w["consent"])
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("consent_revoked_before_redemption", ok, why, "P4_consent_revoked_by_patient")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    w["op"].status.revoked_mandates.add(H.peek(w["m"])["mandate_id"])
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("mandate_revoked_before_redemption", ok, why, "P4_mandate_or_agent_revoked")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    w["op"].status.revoked_agents.add(w["ag"].agent_id)
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("agent_revoked_before_redemption", ok, why, "P4_mandate_or_agent_revoked")

    w = world()
    req = make_req(w, "pharmacy_change", ["dob", "name", "pharmacy"], T3)            # no approval
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("tier3_without_approval_at_holder", ok, why, "P5_stepup_required")

    w = world()
    n = w["cp"].challenge(H.TIER3_TRANSACTION_TTL)
    appr = w["pt"].approve(H.peek(w["m"])["mandate_id"], "pharmacy_change", T3, w["cp2"].counterparty_id,
                           ["dob", "name", "pharmacy"], n)
    req = w["ag"].request(w["att"], w["m"], w["disc"], w["consent"], w["cert"], "pharmacy_change", T3,
                          w["cp"].counterparty_id, "pharmacy", ["dob", "name", "pharmacy"], n, approval=appr)
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("tier3_approval_for_other_counterparty", ok, why, "P5_approval_not_bound_to_tx")

    w = world({**RECORD, "medication_list": "buprenorphine 8 mg film; metformin 500 mg"})
    r = full_flow(w, make_req(w, "refill_request", ["dob", "medication_list", "name"], P))
    rec("protected_value_without_approval", r["ok"], r["why"], "P5_stepup_required_protected_content")

    w = world()
    sub = H.Agent("agent:sub-2")
    sub_att = w["op"].attest(sub, "model-x", "2026-10", POLICY, 3)
    sm, sdisc = w["ag"].attenuate(w["m"], w["disc"], sub, ["pa_status_inquiry"], F, ["pharmacy"], 3, 3600)
    p_ = H.peek(sm)
    extra = H.disclosure("medication_list", {R.REF_KEY: HOLDER})
    wide = H.sign_token(w["ag"].sk, "mandate+sd-jwt", {**p_, "_sd": sorted(set(p_["_sd"]) | {H.digest(extra)})})
    req = make_req(w, "pa_status_inquiry", F, P, mandate=wide, disc=sdisc, att=sub_att, agent=sub, chain=[w["att"]])
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    rec("subagent_mandate_wider_than_parent", ok, why, "P3_attenuation_violation")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    ok, why, _ = w["holder2"].redeem(w["cp"].redemption(req, HOLDER))
    rec("redemption_sent_to_wrong_holder", ok, why, "R_wrong_holder")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    ok, why, _ = w["holder2"].redeem(w["cp"].redemption(req, HOLDER2))
    rec("fields_held_elsewhere_redeemed_here", ok, why, "R_fields_not_held_here")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    ok, _, ctx = w["cp"].verify_reference(req)
    _, _, rel = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    forged = dict(rel)
    forged["box"] = R.seal(R._x_pub_bytes(w["cp"].xsk.public_key()), H.canon({k: "forged" for k in F}), b"x")
    ok, why, _ = w["cp"].open_release(req, ctx, forged)
    rec("forged_release", ok, why, "R_bad_holder_signature")

    w = world()
    r1 = make_req(w, "pa_status_inquiry", F, P)
    r2 = make_req(w, "pa_status_inquiry", F, P)
    _, _, ctx1 = w["cp"].verify_reference(r1)
    _, _, ctx2 = w["cp"].verify_reference(r2)
    _, _, rel1 = w["holder"].redeem(w["cp"].redemption(r1, HOLDER))
    ok, why, _ = w["cp"].open_release(r2, ctx2, rel1)
    rec("release_for_another_request", ok, why, "R_release_not_for_this_request")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P)
    ok, _, ctx = w["cp"].verify_reference(req)
    _, _, rel = w["holder"].redeem(w["cp"].redemption(req, HOLDER))
    aad = R._canon({"holder_id": HOLDER, "counterparty_id": w["cp"].counterparty_id, "request_hash": rel["request_hash"],
                    "subject_commitment": rel["subject_commitment"]})
    try:
        R.unseal(w["cp2"].xsk, rel["box"], aad)
        rec("intercepted_release_read_by_another_party", True, "decrypted", "InvalidTag")
    except InvalidTag:
        rec("intercepted_release_read_by_another_party", False, "InvalidTag", "InvalidTag")

    w = world()
    req = make_req(w, "pa_status_inquiry", F, P, cp=w["broker"])
    ok, why, _ = w["holder"].redeem(w["broker"].redemption(req, HOLDER))
    rec("counterparty_class_without_subject_disclosure", ok, why, "P3_subject_not_disclosed")

    # A compromised operator adds the broker class to the mandate; the patient's consent does not include it.
    w = world()
    root = H.peek(w["m"])
    bd = dict(w["disc"])
    bd[("subject", "transport_broker")] = H.disclosure("subject:transport_broker", "pseudo")
    bm = H.sign_token(w["op"].sk, "mandate+sd-jwt", {**root, "counterparty_classes": ["pharmacy", "transport_broker"],
                                                     "_sd": sorted(set(root["_sd"]) | {H.digest(bd[("subject", "transport_broker")])})})
    req = make_req(w, "pa_status_inquiry", F, P, cp=w["broker"], disc=bd, mandate=bm)
    ok, why, _ = w["holder"].redeem(w["broker"].redemption(req, HOLDER))
    rec("counterparty_class_not_in_consent", ok, why, "P3_counterparty_class_not_in_mandate")

    w = world()
    other = H.Patient("patient-002", "Other Person", "1990-01-01")
    w["holder"].records.pop(w["pt"].subject_commitment)
    w["holder"].add_record(other.subject_commitment, {**RECORD, "name": "Other Person", "dob": "1990-01-01"})
    ok, why, _ = w["holder"].redeem(w["cp"].redemption(make_req(w, "pa_status_inquiry", F, P), HOLDER))
    rec("holder_has_no_record_for_certified_subject", ok, why, "R_no_record_for_certified_subject")
    return out


# ---------------------------------------------------------------- malformed input must be refused, never raised

def malformed():
    w = world()
    good = make_req(w, "pa_status_inquiry", F, P)
    red = w["cp"].redemption(good, HOLDER)
    cases = {
        "redemption_none": None, "redemption_list": [], "request_list": {**red, "request": [1, 2]},
        "counterparty_id_list": {**red, "counterparty_id": ["x"]}, "sig_int": {**red, "sig": 5},
        "request_with_set": {**red, "request": {**good, "params": {1, 2}}},
    }
    for field in ["ts", "counterparty_id", "disclosures", "fields", "mandate", "attestation"]:
        r = {k: v for k, v in good.items() if k not in (field, "sig")}
        r["sig"] = H.b64u(w["ag"].sk.sign(H.canon(r)))
        cases[f"agent_signed_missing_{field}"] = {**red, "request": r}
    for field, val in [("ts", "now"), ("disclosures", [5, 6, 7]), ("chain_attestations", [5]), ("mandate", "a.b"),
                       ("attestation", 5)]:
        cases[f"agent_signed_{field}_{type(val).__name__}"] = {**red, "request": resign(w, good, **{field: val})}
    out = {}
    for name, red_ in cases.items():
        try:
            ok, why, _ = w["holder"].redeem(red_)
            out[name] = {"refused": not ok, "reason": why, "raised": None}
        except Exception as e:  # noqa: BLE001
            out[name] = {"refused": False, "reason": None, "raised": type(e).__name__}
    for name, req in [("verify_none", None), ("verify_attestation_int", {**good, "attestation": 5})]:
        try:
            ok, why, _ = w["cp"].verify_reference(req)
            out[name] = {"refused": not ok, "reason": why, "raised": None}
        except Exception as e:  # noqa: BLE001
            out[name] = {"refused": False, "reason": None, "raised": type(e).__name__}
    return out


# ---------------------------------------------------------------- what the agent holds

def _decoded(material: dict) -> str:
    import re
    held = H.canon(material).decode()
    decoded = held
    for seg in re.findall(r"[A-Za-z0-9_-]{16,}", held):
        try:
            decoded += H.b64u_dec(seg).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            pass
    return decoded


def agent_material():
    """Searches the tokens the agent holds or sends for one refill request (attestation, consent, mandate, field and
    consent disclosures, request), including the decoded contents of every token and disclosure, for record values and
    for the opening of the identity commitment."""
    w = world()
    req = make_req(w, "refill_request", ["dob", "medication_list", "name"], P)
    mat = _decoded({"mandate": w["m"], "disc": {str(k): v for k, v in w["disc"].items()}, "consent": w["consent"],
                    "attestation": w["att"], "request": req})
    salt = w["cdisc"][("opening",)]
    m, disc = w["op"].issue_mandate(w["pt"], w["cert"], w["idp"].pk, w["consent"], w["cdisc"], w["ag"],
                                    {**RECORD, "subject_commitment": w["pt"].subject_commitment}, ACTIONS, FIELDS,
                                    ["pharmacy"], 3)
    base = _decoded({"mandate": m, "disc": {str(k): v for k, v in disc.items()}})
    return {"fields_checked": sorted(RECORD), "values_found_in_agent_material": sorted(k for k, v in RECORD.items() if v in mat),
            "identity_opening_in_agent_material": salt in mat,
            "data_carrying_baseline_values_found": sorted(k for k, v in RECORD.items() if v in base),
            "data_carrying_baseline_identity_opening": salt in base}


def main():
    legit = legit_cases()
    att = attacks()
    mal = malformed()
    am = agent_material()
    res = {"legit": legit, "attacks": att, "malformed": mal, "agent_material": am,
           "summary": {"legit_ok": sum(legit.values()), "legit_total": len(legit),
                       "attacks_refused": sum(v["refused"] for v in att.values()), "attacks_total": len(att),
                       "attacks_refused_for_expected_reason": sum(v["reason_as_expected"] for v in att.values()),
                       "malformed_refused_without_exception": sum(v["refused"] and v["raised"] is None for v in mal.values()),
                       "malformed_total": len(mal),
                       "values_in_agent_material": len(am["values_found_in_agent_material"]),
                       "identity_opening_in_agent_material": am["identity_opening_in_agent_material"]}}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "redemption_conformance.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res["summary"], indent=1))
    for k, v in att.items():
        if not v["reason_as_expected"]:
            print("UNEXPECTED", k, v)
    for k, v in mal.items():
        if not (v["refused"] and v["raised"] is None):
            print("MALFORMED NOT HANDLED", k, v)
    s = res["summary"]
    if (s["legit_ok"] != s["legit_total"] or s["attacks_refused_for_expected_reason"] != s["attacks_total"]
            or s["malformed_refused_without_exception"] != s["malformed_total"] or s["values_in_agent_material"]
            or s["identity_opening_in_agent_material"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
