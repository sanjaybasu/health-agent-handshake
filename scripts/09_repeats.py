"""Amendment A7: run-to-run variation. Compares the original run with replicates rep2 and rep3 on the registered stratified sample
of 198 scenarios (C1 and C3). Writes results/repeats_summary.json.
"""
import glob
import importlib.util
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("score", ROOT / "scripts" / "03_score_bench.py")
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)
RUN_OF = {"claude-opus-5-5": "confirmatory", "claude-sonnet-5-5": "confirmatory", "claude-haiku-4-5": "confirmatory",
          "gpt-6.1-sol": "xvendor", "gemini-3.1-pro-preview": "xvendor"}


def fleiss_kappa(table):
    """table: n_items x n_categories counts, equal raters per item."""
    t = np.asarray(table, dtype=float)
    n = t.sum(axis=1)[0]
    p_j = t.sum(axis=0) / t.sum()
    p_i = ((t * t).sum(axis=1) - n) / (n * (n - 1))
    pbar, pe = p_i.mean(), (p_j ** 2).sum()
    return float((pbar - pe) / (1 - pe)) if pe < 1 else 1.0


def main():
    out = {}
    for model, orig in RUN_OF.items():
        m = {}
        reps = {}
        for rep in ("rep2", "rep3"):
            reps[rep] = {Path(f).name: f for f in glob.glob(str(ROOT / "results" / "bench" / rep / model / "*" / "*.json"))}
        for cfg in ("C1", "C3"):
            names = sorted({Path(f).name for f in glob.glob(str(ROOT / "results" / "bench" / "rep2" / model / cfg / "*.json"))} &
                           {Path(f).name for f in glob.glob(str(ROOT / "results" / "bench" / "rep3" / model / cfg / "*.json"))})
            rows = {r: [] for r in ("original", "rep2", "rep3")}
            for nm in names:
                for r, base in (("original", ROOT / "results" / "bench" / orig / model / cfg),
                                ("rep2", ROOT / "results" / "bench" / "rep2" / model / cfg),
                                ("rep3", ROOT / "results" / "bench" / "rep3" / model / cfg)):
                    rows[r].append(score.score(json.load(open(base / nm))))
            if not names:
                continue
            od = np.array([[r["over_disclosure"] for r in rows[k]] for k in ("original", "rep2", "rep3")]).T
            same = int(sum(1 for x in od if len(set(x)) == 1))
            table = [[int((x == 0).sum()), int((x == 1).sum())] for x in od]
            m[cfg] = {"n_scenarios": len(names),
                      "over_disclosure": {k: score.rate(rows[k], "over_disclosure") for k in rows},
                      "attack_success": {k: score.rate(rows[k], "attack_success", lambda r: r["condition"] != "benign") for k in rows},
                      "completion": {k: score.rate(rows[k], "completed", lambda r: r["condition"] == "benign") for k in rows},
                      "identical_over_disclosure_all_three": {"k": same, "n": len(names)},
                      "fleiss_kappa_over_disclosure": fleiss_kappa(table) if od.sum() not in (0, od.size) else None}
        contrasts = {}
        for r in ("original", "rep2", "rep3"):
            base = ROOT / "results" / "bench" / (RUN_OF[model] if r == "original" else r) / model
            names = sorted({Path(f).name for f in glob.glob(str(ROOT / "results" / "bench" / "rep2" / model / "C1" / "*.json"))})
            rs = []
            for cfg in ("C1", "C3"):
                for nm in names:
                    p = base / cfg / nm
                    if p.exists():
                        rs.append(score.score(json.load(open(p))))
            rng = np.random.default_rng(score.SEED)
            contrasts[r] = score.paired_diff(rs, "over_disclosure", "C1", "C3", lambda x: True, rng)
        m["C3_minus_C1"] = contrasts
        out[model] = m
    (ROOT / "results" / "repeats_summary.json").write_text(json.dumps(out, indent=1))
    for model, m in out.items():
        for cfg in ("C1", "C3"):
            if cfg not in m:
                continue
            v = m[cfg]; f = lambda x: f"{x['k']}/{x['n']}"
            print(model, cfg, "od", [f(v["over_disclosure"][k]) for k in ("original", "rep2", "rep3")],
                  "identical", f(v["identical_over_disclosure_all_three"]), "kappa", v["fleiss_kappa_over_disclosure"],
                  "compl", [f(v["completion"][k]) for k in ("original", "rep2", "rep3")])
        print("  C3-C1", {k: (None if c is None else round(100 * c["diff"], 1)) for k, c in m["C3_minus_C1"].items()})


if __name__ == "__main__":
    main()
