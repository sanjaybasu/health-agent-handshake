"""Amendment A5: compare outcomes under the alternative counterparty simulator (gpt-6.1-sol) with the registered simulator
(claude-sonnet-5-5) on the same scenarios (simulated human or AI-agent counterparty; configurations C1 and C3).

Reads results/bench_cpswap_conversations.csv (from scripts/03_score_bench.py --run cpswap) and the confirmatory and xvendor
conversation files. Writes results/cpswap_comparison.json.
"""
import csv
import importlib.util
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("score", ROOT / "scripts" / "03_score_bench.py")
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)

INT = ("completed", "over_disclosure", "protected_disclosed", "out_of_mandate_action_accepted")


def load(name):
    rows = list(csv.DictReader(open(ROOT / "results" / f"bench_{name}_conversations.csv")))
    for r in rows:
        for k in INT:
            r[k] = int(r[k])
        r["attack_success"] = None if r["attack_success"] in ("", "None") else int(r["attack_success"])
    return rows


def main():
    alt = load("cpswap")
    keep = {(r["model"], r["config"], r["scenario_id"]) for r in alt}
    orig = [r for r in load("confirmatory") + load("xvendor") if (r["model"], r["config"], r["scenario_id"]) in keep]
    out = {"counterparty_original": "claude-sonnet-5-5", "counterparty_alternative": "gpt-6.1-sol", "by_model": {}}
    benign = lambda r: r["condition"] == "benign"
    adv = lambda r: r["condition"] != "benign"
    for model in sorted({r["model"] for r in alt}):
        m = {}
        for label, rows in (("original", orig), ("alternative", alt)):
            rng = np.random.default_rng(score.SEED)
            mr = [r for r in rows if r["model"] == model]
            m[label] = {
                "n_per_config": {c: sum(1 for r in mr if r["config"] == c) for c in ("C1", "C3")},
                "E2": {c: score.rate([r for r in mr if r["config"] == c], "over_disclosure") for c in ("C1", "C3")},
                "E1": {c: score.rate([r for r in mr if r["config"] == c], "attack_success", adv) for c in ("C1", "C3")},
                "E3": {c: score.rate([r for r in mr if r["config"] == c], "completed", benign) for c in ("C1", "C3")},
                "C3_minus_C1": {"E2": score.paired_diff(mr, "over_disclosure", "C1", "C3", lambda r: True, rng),
                                "E1": score.paired_diff(mr, "attack_success", "C1", "C3", adv, rng),
                                "E3": score.paired_diff(mr, "completed", "C1", "C3", benign, rng)},
            }
        out["by_model"][model] = m
    (ROOT / "results" / "cpswap_comparison.json").write_text(json.dumps(out, indent=1))
    for model, m in out["by_model"].items():
        f = lambda x: f"{x['k']}/{x['n']}"
        o, a = m["original"], m["alternative"]
        d = lambda x: "n/a" if x is None else f"{100 * x['diff']:.1f} ({100 * x['ci'][0]:.1f} to {100 * x['ci'][1]:.1f})"
        print(f"{model}: E2 C1 {f(o['E2']['C1'])} -> {f(a['E2']['C1'])}; C3 {f(o['E2']['C3'])} -> {f(a['E2']['C3'])}; "
              f"C3-C1 {d(o['C3_minus_C1']['E2'])} -> {d(a['C3_minus_C1']['E2'])}; E3 C3 {f(o['E3']['C3'])} -> {f(a['E3']['C3'])}")


if __name__ == "__main__":
    main()
