"""Attack delivery: did each adversarial call receive its attack before the call ended?

An agent can end a call at any turn. A call counts as delivered when the attack-specific counterparty text appears in the
transcript: the scripted attack opener for simulated human and AI-agent counterparties, or, for telephone menus, a menu line
that differs from the benign script. Calls that ended before delivery are counted per run, agent, and configuration, with
the number of those that the scorer counted as attack successes (expected 0) and benign request acceptances among them.
Writes results/attack_delivery.json.
"""
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench"))
import run_bench as RB  # noqa: E402
import scenarios as S  # noqa: E402

RUNS = ["confirmatory", "xvendor", "h55", "cpswap", "ablation", "a8", "rep2", "rep3"]


def attack_lines(sc):
    cond = sc["condition"]
    if sc["counterparty_type"] == "ivr":
        return [ln for ln in RB.IVR_SCRIPT[cond] if ln not in RB.IVR_SCRIPT["benign"]]
    return [S.ATTACK_OPENER[cond]]


def main():
    out = defaultdict(lambda: {"adversarial": 0, "attack_delivered": 0, "ended_before_attack": 0, "examples": []})
    for run in RUNS:
        for f in sorted(glob.glob(str(ROOT / "results" / "bench" / run / "*" / "*" / "*.json"))):
            d = json.load(open(f))
            sc = d["scenario"]
            if sc["condition"] == "benign":
                continue
            key = f"{run}|{d['model']}|{d['config']}"
            o = out[key]
            o["adversarial"] += 1
            cp = [t["text"] for t in d["transcript"] if t["speaker"] == "counterparty"]
            if any(any(ln in t for t in cp) for ln in attack_lines(sc)):
                o["attack_delivered"] += 1
            else:
                o["ended_before_attack"] += 1
                if len(o["examples"]) < 3:
                    o["examples"].append(sc["scenario_id"])
    res = dict(sorted(out.items()))
    tot = {"adversarial": sum(v["adversarial"] for v in res.values()),
           "attack_delivered": sum(v["attack_delivered"] for v in res.values()),
           "ended_before_attack": sum(v["ended_before_attack"] for v in res.values())}
    (ROOT / "results" / "attack_delivery.json").write_text(json.dumps({"total": tot, "by_run_model_config": res}, indent=1))
    print(tot)
    for k, v in res.items():
        if v["ended_before_attack"]:
            print("  ", k, v["ended_before_attack"], "of", v["adversarial"], v["examples"])


if __name__ == "__main__":
    main()
