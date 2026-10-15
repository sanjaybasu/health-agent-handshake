"""Component ablation (amendment A6): each arm adds exactly one handshake component to the privacy-prompt configuration (C1).

  M  mandate in the agent's context only      (agent prompt as C2; counterparty backend as C1; no gate or filter)
  V  counterparty verifier only               (agent prompt as C1, full record, no mandate; backend runs the HAH verifier as C2)
  D  data minimisation only                   (agent sees only allowlisted fields, no mandate; backend as C1; no gate or filter)
  G  operator tool gate and outbound filter   (agent prompt as C1, full record, no mandate; backend as C1; gate and filter as C3)

The registered code (bench/run_bench.py) is imported unchanged; the arm is applied by wrapping agent_system and Backend and
by choosing which configuration run_one sees. Agent adapters for other developers come from bench/run_bench_xvendor.py.
The counterparty simulator is the registered claude-sonnet-5-5. Output: results/bench/<run>/<model>/<arm>/.

Usage:
  python bench/run_bench_ablation.py --run ablation --model claude-haiku-4-5 --n all
"""
import argparse
import concurrent.futures as cf
import random
import threading
import time
from pathlib import Path

import run_bench as RB
_anthropic_call_agent = RB.call_agent
_orig_agent_system = RB.agent_system
_orig_Backend = RB.Backend
import run_bench_xvendor as X  # noqa: E402  (sets RB.call_agent to the cross-vendor dispatcher)
from run_bench import S, atomic_write  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ARMS = {
    "M": {"run_cfg": "C1", "prompt": "C2", "backend": "C1"},
    "V": {"run_cfg": "C1", "prompt": "C1", "backend": "C2"},
    "D": {"run_cfg": "C1", "prompt": "D", "backend": "C1"},
    "G": {"run_cfg": "C3", "prompt": "C1", "backend": "C1"},
}
_tl = threading.local()


def agent_system(config, member, task, counterparty_class):
    p = ARMS[_tl.arm]["prompt"]
    if p == "D":
        # The C3 prompt shows only allowlisted fields; drop its final part, the mandate.
        parts = _orig_agent_system("C3", member, task, counterparty_class).split("\n\n")
        assert parts[-1].startswith("Signed mandate")
        return "\n\n".join(parts[:-1])
    return _orig_agent_system(p, member, task, counterparty_class)


def Backend(config, member, task, task_key, counterparty_class):
    return _orig_Backend(ARMS[_tl.arm]["backend"], member, task, task_key, counterparty_class)


def call_agent(model, system, messages):
    if model.startswith("claude-"):
        return _anthropic_call_agent(model, system, messages)
    return X.call_agent(model, system, messages)


RB.agent_system = agent_system
RB.Backend = Backend
RB.call_agent = call_agent


def run_arm(sc, arm, model, mk):
    _tl.arm = arm
    out = RB.run_one(sc, ARMS[arm]["run_cfg"], model, mk)
    out["config"] = arm
    out["ablation_arm"] = arm
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--n", default="all")
    ap.add_argument("--arms", default="M,V,D,G")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--per-cell", type=int, default=0,
                    help="if > 0, run a stratified subset: this many scenarios per (counterparty type, condition) cell (amendment A6a)")
    a = ap.parse_args()
    import os
    import openai
    if a.model.startswith("gpt-"):
        X._oa = openai.OpenAI(max_retries=6)
    if a.model.startswith("gemini-"):
        from google import genai
        X._gm = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    members = S.make_members()
    mk = {m["record"]["member_key"]: m for m in members}
    grid = S.scenario_grid(members)
    if a.per_cell > 0:
        cells = {}
        for r in grid:
            cells.setdefault((r["counterparty_type"], r["condition"]), []).append(r)
        rng = random.Random(S.SEED)
        grid = [r for k in sorted(cells) for r in rng.sample(sorted(cells[k], key=lambda r: r["scenario_id"]), a.per_cell)]
    elif a.n != "all":
        grid = random.Random(S.SEED).sample(grid, int(a.n))
    jobs = []
    for arm in a.arms.split(","):
        d = ROOT / "results" / "bench" / a.run / a.model / arm
        d.mkdir(parents=True, exist_ok=True)
        for sc in grid:
            p = d / (sc["scenario_id"].replace("|", "__") + ".json")
            if not p.exists():
                jobs.append((sc, arm, p))
    print(f"{len(jobs)} conversations to run ({len(grid)} scenarios x arms {a.arms})", flush=True)

    def work(j):
        sc, arm, p = j
        err = None
        for attempt in range(8):
            try:
                atomic_write(p, run_arm(sc, arm, a.model, mk))
                return None
            except Exception as e:  # one bad conversation must not stop the run
                err = e
                if not X._transient(e):
                    break
                time.sleep(min(30 * (attempt + 1), 180))
        return f"{sc['scenario_id']} {arm}: {type(err).__name__} {str(err)[:300]}"

    done = 0
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for err in ex.map(work, jobs):
            done += 1
            if err:
                print("FAILED", err, flush=True)
            if done % 20 == 0:
                print(f"{done}/{len(jobs)}", flush=True)


if __name__ == "__main__":
    main()
