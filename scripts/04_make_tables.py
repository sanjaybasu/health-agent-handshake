"""Build manuscript and supplement tables from results/ (no hand-entered values). Formal and conformance tables use version 2.

Writes markdown tables to results/tables/.
  table_formal_lemmas.md        lemma x model status (main model, voice model, negative controls)
  table_conformance.md          attack x verification level (accepted / rejected with reason)
  table_bench_<run>.md          per model x configuration E1-E4 with Wilson 95% CIs (if a bench summary exists)
"""
import glob
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "tables"
OUT.mkdir(parents=True, exist_ok=True)

LEMMA_LABEL = {
    "L2_agent_authentication_injective": "Agent authentication (injective agreement with operator, patient, counterparty, nonce, action, parameters, fields)",
    "L2b_subagent_authentication_injective": "Sub-agent authentication (injective agreement)",
    "L3_consent_binding": "Consent binding (tolerates operator compromise; defeated only by patient key compromise)",
    "L3b_mandate_issued": "Mandate issued by the operator",
    "L4_nonce_single_use": "Nonce single use",
    "L5_stepup_binding": "Transaction-bound approval for tier 3, direct and through a sub-agent (action and parameters)",
    "L7_delegation_integrity": "Delegation integrity (sub-agent scope equals delegated scope)",
    "L8_receipt_integrity": "Receipt integrity",
    "V1_lookup_authenticates_registration": "Telephone, with lookup: operator, agent, patient, counterparty and action match a registration",
    "V1b_code_requested_by_agent": "Telephone: a code is registered only on the named agent's signed request",
    "V2_lookup_single_use": "Telephone, with lookup: code single use (holds by construction: linear code fact and uniqueness restriction)",
    "V3_no_lookup_authenticates_operator": "Telephone, without lookup: operator authenticated",
    "V4_lookup_authenticates_caller": "Telephone, with lookup: caller authenticated (relay)",
}


def pct(x):
    return "" if x is None else f"{100 * x:.1f}"


def formal_table():
    f = json.load(open(ROOT / "results" / "formal_v2.json"))
    models = f["models"]
    main = next(m for m in models if m["model"].endswith("hah2.spthy"))
    voice = next(m for m in models if m["model"].endswith("hah2_voice.spthy"))
    variants = [m for m in models if "/variants/" in m["model"]]
    vvariants = [m for m in models if "/variants_voice/" in m["model"]]
    vnames = [Path(m["model"]).stem for m in variants]
    lines = [f"Prover: {f['tamarin_version']}; Maude {f['maude_version']}.", "",
             "| Property | Full model | " + " | ".join(vnames) + " |",
             "|---|---|" + "---|" * len(vnames)]
    for k, lab in LEMMA_LABEL.items():
        if not k.startswith("L"):
            continue
        row = [lab, main["lemmas"][k]["status"]] + [v["lemmas"][k]["status"] for v in variants]
        lines.append("| " + " | ".join(row) + " |")
    vnames2 = [Path(m["model"]).stem for m in vvariants]
    lines += ["", "| Telephone property | Full model | " + " | ".join(vnames2) + " |", "|---|---|" + "---|" * len(vnames2)]
    for k, lab in LEMMA_LABEL.items():
        if k.startswith("V") and k in voice["lemmas"]:
            lines.append(f"| {lab} | {voice['lemmas'][k]['status']} | " + " | ".join(v["lemmas"].get(k, {}).get("status", "") for v in vvariants) + " |")
    lines += ["", "Executability lemmas (honest runs reach each acceptance with no key compromise): " +
              ", ".join(f"{k} {v['status']}" for k, v in main["lemmas"].items() if k.startswith("L1")) + ".",
              f"Wall time for the full model: {main['wall_seconds']} s. All models passed Tamarin wellformedness checks: "
              f"{all(m['wellformedness_ok'] for m in models)}."]
    (OUT / "table_formal_lemmas.md").write_text("\n".join(lines) + "\n")


def conformance_table():
    c = json.load(open(ROOT / "results" / "conformance_v2.json"))
    levels = c["levels"]
    head = "| Case | " + " | ".join(levels) + " |"
    lines = [head, "|---|" + "---|" * len(levels)]
    for kind in ("legit", "attacks"):
        for name, v in c[kind].items():
            cells = [("accepted" if v[l]["accepted"] else "rejected: " + v[l]["reason"]) for l in levels]
            lines.append(f"| {'(legitimate) ' if kind == 'legit' else ''}{name.replace('_', ' ')} | " + " | ".join(cells) + " |")
    lines += ["", "| Level | Attacks accepted | Legitimate requests accepted |", "|---|---|---|"]
    for l in levels:
        a, g = c["attack_success"][l], c["legit_acceptance"][l]
        lines.append(f"| {l} | {a['accepted']} of {a['total']} | {g['accepted']} of {g['total']} |")
    li, vc = c["log_integrity"], c["voice_code"]
    lines += [""] + [f"Issuer-side test, {k.replace('_', ' ')}: accepted = {v['issued']} ({v['reason']})." for k, v in c["issuer_side"].items()]
    lines += [
              f"Receipt log (RFC 9162-style): inclusion proofs verify = {li['inclusion_proofs_verify']}; consistency proof verifies = "
              f"{li['consistency_proof_verifies']}; tampering detected = {li['tamper_detected']}.",
              "Telephone code: " + "; ".join(f"{k.replace('_', ' ')} = {v:,}" if isinstance(v, int) and not isinstance(v, bool) else f"{k.replace('_', ' ')} = {v}" for k, v in vc.items()) + "."]
    (OUT / "table_conformance.md").write_text("\n".join(lines) + "\n")


def bench_tables():
    for f in glob.glob(str(ROOT / "results" / "bench_*_summary.json")):
        s = json.load(open(f))
        run = s["run"]
        lines = [f"Run: {run}; conversations: {s['n_conversations']}.", "",
                 "| Model | Configuration | Conversations | E1 attack success, % (95% CI) | E2 over-disclosure, % (95% CI) | "
                 "E3 completion (benign), % (95% CI) | Protected attribute disclosed | Out-of-mandate action accepted |",
                 "|---|---|---|---|---|---|---|---|"]
        for model, m in s["by_model"].items():
            for cfg, v in m["by_config"].items():
                def cell(r):
                    p, lo, hi = r["rate_ci"]
                    return f"{r['k']} of {r['n']} ({pct(p)}; {pct(lo)} to {pct(hi)})" if r["n"] else "n/a"
                lines.append(f"| {model} | {cfg} | {v['n']} | {cell(v['E1_attack_success'])} | {cell(v['E2_over_disclosure_all'])} | "
                             f"{cell(v['E3_completion_benign'])} | {v['protected_disclosed']['k']} of {v['protected_disclosed']['n']} | "
                             f"{v['out_of_mandate_action_accepted']['k']} of {v['out_of_mandate_action_accepted']['n']} |")
        lines += ["", "| Model | Contrast | Outcome | Paired scenarios | Clusters | Difference, percentage points (95% CI) |",
                  "|---|---|---|---|---|---|"]
        for model, m in s["by_model"].items():
            for name, d in m["contrasts"].items():
                for o, r in d.items():
                    if r:
                        lines.append(f"| {model} | {name.replace('_minus_', ' minus ')} | {o} | {r['n_pairs']} | {r['n_clusters']} | "
                                     f"{100 * r['diff']:.1f} ({100 * r['ci'][0]:.1f} to {100 * r['ci'][1]:.1f}) |")
        (OUT / f"table_bench_{run}.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    formal_table()
    conformance_table()
    bench_tables()
    print("tables written to", OUT)
