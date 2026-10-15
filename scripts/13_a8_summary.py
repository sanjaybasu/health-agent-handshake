"""Amendment A8: permission-carrying mode (C4) and information-flow-control baseline (IFC).

Reads results/bench/a8/<model>/<arm>/ and, for the same scenarios, C1 and C3 (confirmatory or xvendor runs) and the
data-minimisation arm D (ablation run). For each agent and condition: over-disclosure overall and by channel, attack success,
out-of-mandate actions accepted, request acceptance (benign), and component activations; paired differences of C4 and IFC
against C1, C3, and D with the registered cluster bootstrap. Writes results/a8_summary.json.
"""
import glob
import importlib.util
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("abl", ROOT / "scripts" / "07_ablation.py")
abl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abl)
score = abl.score

ARMS = ["C4", "IFC"]
BASE = ["C1", "C3", "D"]


def load(model, cond):
    run = "a8" if cond in ARMS else ("ablation" if cond == "D" else abl.RUN_OF[model])
    return [abl.row(json.load(open(f))) for f in sorted(glob.glob(str(ROOT / "results" / "bench" / run / model / cond / "*.json")))]


def main():
    adv = lambda r: r["condition"] != "benign"
    benign = lambda r: r["condition"] == "benign"
    out = {"arms": {"C4": "permission-carrying mode", "IFC": "information-flow-control baseline"}, "by_model": {}}
    for model in abl.RUN_OF:
        rows = {c: load(model, c) for c in ARMS + BASE}
        if not rows["C4"] or not rows["IFC"]:
            continue
        common = set.intersection(*[{r["scenario_id"] for r in rows[c]} for c in ARMS + ["D"]])
        rows = {c: [r for r in rs if r["scenario_id"] in common] for c, rs in rows.items()}
        m = {}
        for c, rs in rows.items():
            m[c] = {"n": len(rs),
                    "over_disclosure": score.rate(rs, "over_disclosure"),
                    "speech_disclosure": score.rate(rs, "speech_disclosure"),
                    "transaction_disclosure": score.rate(rs, "transaction_disclosure"),
                    "attack_success": score.rate(rs, "attack_success", adv),
                    "out_of_mandate_action_accepted": score.rate(rs, "out_of_mandate_action_accepted"),
                    "acceptance": score.rate(rs, "completed", benign),
                    "verifier_rejection": score.rate(rs, "verifier_rejection"),
                    "gate_block": score.rate(rs, "gate_block"),
                    "filter_redaction": score.rate(rs, "filter_redaction")}
        diffs = {}
        for a in ARMS:
            for b in BASE:
                rng = np.random.default_rng(score.SEED)
                diffs[f"{a}_minus_{b}"] = {k: score.paired_diff(rows[b] + rows[a], k, b, a, f, rng) for k, f in
                                           (("over_disclosure", lambda r: True), ("attack_success", adv),
                                            ("completed", benign))}
        out["by_model"][model] = {"n_scenarios": len(common), "by_condition": m, "contrasts": diffs}
    (ROOT / "results" / "a8_summary.json").write_text(json.dumps(out, indent=1))
    f = lambda x: f"{x['k']}/{x['n']}"
    for model, v in out["by_model"].items():
        print(model, v["n_scenarios"])
        for c in BASE + ARMS:
            b = v["by_condition"][c]
            print(f"  {c:3} disc {f(b['over_disclosure']):>9} speech {f(b['speech_disclosure']):>9} tx {f(b['transaction_disclosure']):>9} "
                  f"attack {f(b['attack_success']):>8} ooma {f(b['out_of_mandate_action_accepted']):>8} accept {f(b['acceptance']):>7} "
                  f"| rej {b['verifier_rejection']['k']} gate {b['gate_block']['k']} filter {b['filter_redaction']['k']}")
        for k, d in v["contrasts"].items():
            c = d["completed"]
            print(f"  {k:14} accept diff {100 * c['diff']:+.1f} ({100 * c['ci'][0]:.1f} to {100 * c['ci'][1]:.1f})")


if __name__ == "__main__":
    main()
