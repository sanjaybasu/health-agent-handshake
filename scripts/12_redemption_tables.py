"""Supplementary Tables 10 and 11 (permission-carrying mode) from results/formal_redeem.json and results/redemption_conformance.json.

Writes results/tables/table_formal_redeem.md and table_conformance_redeem.md.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "tables"
OUT.mkdir(parents=True, exist_ok=True)
PROPS = [
    ("E1_exec", "Executable: a legitimate release can complete", "None (sanity check)"),
    ("E2_exec_agent_and_operator_compromised", "Executable with the agent and operator compromised", "None (sanity check)"),
    ("E3_exec_leak_via_compromised_counterparty", "A compromised, consented counterparty can learn a value", "None (sanity check)"),
    ("R1_release_requires_patient_consent", "Consent: the holder releases a field only under the patient's consent for that counterparty class", "Release without the patient's consent"),
    ("R2_release_only_to_addressed_counterparty", "Audience: the holder releases only to the counterparty that the request names", "Redemption of a captured request by another party"),
    ("R3_redeemer_authentication_injective", "Redeemer authentication: the named counterparty signed the redemption, once per challenge", "Forged or repeated redemption"),
    ("R4_release_requires_mandate_naming_holder", "Mandate: the holder releases only under a mandate that names it", "Release under a forged or unrelated mandate"),
    ("R5_data_reaches_adversary_only_via_permitted_compromised_counterparty", "Confidentiality: compromise of the agent or operator alone reveals no record value", "Theft of record values through the agent"),
    ("R6_received_data_from_holder", "Release integrity: accepted data came from the holder", "Forged release"),
]
CTRL = {
    "VR1_holder_skips_consent_check": "no consent check",
    "VR2_holder_ignores_audience": "no audience check",
    "VR3_holder_skips_redeemer_signature": "no redeemer signature check",
    "VR4_bearer_redemption": "bearer redemption",
    "VR5_no_single_redemption": "no single-use check",
    "VR6_holder_skips_mandate_check": "no mandate check",
    "VR7_holder_skips_class_check": "no counterparty-class check",
    "VR8_agent_carries_data": "agent carries the data",
    "VR9_unsigned_release": "unsigned release",
}


def plain(s):
    return s.replace("_", " ")


def main():
    f = json.load(open(ROOT / "results" / "formal_redeem.json"))
    models = {Path(m["model"]).stem: m for m in f["models"]}
    cols = ["hah2_redeem"] + list(CTRL)
    assert set(cols) == set(models), sorted(models)
    tv = f["tamarin_version"].split(",")[0].replace("tamarin-prover", "Tamarin")
    head = (f"Prover: {tv}; Maude {f['maude_version']}. Controls VR1 to VR9: "
            + "; ".join(f"VR{i}, {d}" for i, d in enumerate(CTRL.values(), 1))
            + ". VR4 and VR8 replace the design; the other controls each remove one check. For the sanity checks (E1 to E3), "
            "'found' means that the prover found the expected trace.")
    rows = [head, "", "| Property | Attack prevented | Full | " + " | ".join(f"VR{i}" for i in range(1, 10)) + " |",
            "|---|---|---|" + "---|" * 9]
    for key, label, atk in PROPS:
        cells = []
        for c in cols:
            st = models[c]["lemmas"][key]["status"]
            cells.append(("found" if st == "verified" else "not found") if key.startswith("E") else ("holds" if st == "verified" else "attack"))
        rows.append(f"| {label} | {atk} | " + " | ".join(cells) + " |")
    (OUT / "table_formal_redeem.md").write_text("\n".join(rows) + "\n")

    c = json.load(open(ROOT / "results" / "redemption_conformance.json"))
    s, am = c["summary"], c["agent_material"]
    rows = [f"Legitimate cases completed: {s['legit_ok']} of {s['legit_total']}. Attacks refused: {s['attacks_refused']} of {s['attacks_total']}, "
            f"{s['attacks_refused_for_expected_reason']} for the expected reason. Malformed inputs refused without error: "
            f"{s['malformed_refused_without_exception']} of {s['malformed_total']}. Record values found in the tokens that the agent holds or sends: "
            f"{len(am['values_found_in_agent_material'])} of {len(am['fields_checked'])} fields checked; identity opening present: "
            f"{'yes' if am['identity_opening_in_agent_material'] else 'no'}. Same permissions in the data-carrying design: "
            f"{len(am['data_carrying_baseline_values_found'])} values found ({', '.join(plain(x) for x in am['data_carrying_baseline_values_found'])}); "
            f"identity opening present: {'yes' if am['data_carrying_baseline_identity_opening'] else 'no'}.", "",
            "| Case | Result | Reason for refusal |", "|---|---|---|"]
    for k, ok in c["legit"].items():
        rows.append(f"| (legitimate) {plain(k)} | {'completed' if ok else 'FAILED'} | |")
    for k, v in c["attacks"].items():
        assert v["reason_as_expected"], k
        rows.append(f"| (attack) {plain(k)} | {'refused' if v['refused'] else 'ACCEPTED'} | {plain(v['reason'])} |")
    for k, v in c["malformed"].items():
        rows.append(f"| (malformed) {plain(k)} | {'refused' if v['refused'] and not v['raised'] else 'ERROR'} | {plain(v['reason'])} |")
    (OUT / "table_conformance_redeem.md").write_text("\n".join(rows) + "\n")
    print("redemption tables written")


if __name__ == "__main__":
    main()
