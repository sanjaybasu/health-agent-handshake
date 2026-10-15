"""Sensitivity analysis (amendment A5): replace the simulated counterparty with a model from another developer.

The counterparty simulator in the registered design is claude-sonnet-5-5. Here it is gpt-6.1-sol (OpenAI Responses API,
reasoning effort low, matching the registered counterparty's effort). Everything else is the registered design: scenarios,
prompts (counterparty_system and the scripted attack openers), agents and their adapters, backend verifier, operator gate,
turn limit, and scoring. Only configurations C1 and C3 run (the primary contrast), and only scenarios whose counterparty is a
simulated human or AI agent; telephone-menu scenarios are scripted and do not use the simulator.

Usage:
  python bench/run_bench_cpswap.py --run cpswap --model claude-opus-5-5 --n all
"""
import argparse
import concurrent.futures as cf
import random
import time
from pathlib import Path
from types import SimpleNamespace

import run_bench as RB
_anthropic_call_agent = RB.call_agent
import run_bench_xvendor as X  # noqa: E402  (sets RB.call_agent to the cross-vendor dispatcher)
from run_bench import S, atomic_write  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CP_MODEL = "gpt-6.1-sol"
CP_EFFORT = "low"
CONFIGS = ["C1", "C3"]


def call_agent(model, system, messages):
    if model.startswith("claude-"):
        return _anthropic_call_agent(model, system, messages)
    return X.call_agent(model, system, messages)


_oa = None


def call_counterparty(system, history):
    global _oa
    if _oa is None:
        import openai
        _oa = openai.OpenAI(max_retries=6)
    r = _oa.responses.create(model=CP_MODEL, instructions=system,
                             input=[{"role": m["role"], "content": m["content"]} for m in history],
                             reasoning={"effort": CP_EFFORT}, store=False, max_output_tokens=4000)
    usage = SimpleNamespace(input_tokens=r.usage.input_tokens, output_tokens=r.usage.output_tokens)
    for it in r.output:
        if it.type == "message" and any(c.type == "refusal" for c in it.content):
            return "[counterparty refused]", usage
    return (r.output_text or "").strip(), usage


RB.call_agent = call_agent
RB.call_counterparty = call_counterparty
RB.COUNTERPARTY_MODEL = CP_MODEL


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--n", default="all")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    # Create API clients once, before worker threads start (lazy creation in threads can race).
    import os
    import openai
    global _oa
    _oa = openai.OpenAI(max_retries=6)
    if a.model.startswith("gpt-"):
        X._oa = openai.OpenAI(max_retries=6)
    if a.model.startswith("gemini-"):
        from google import genai
        X._gm = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    members = S.make_members()
    mk = {m["record"]["member_key"]: m for m in members}
    grid = [r for r in S.scenario_grid(members) if r["counterparty_type"] != "ivr"]
    if a.n != "all":
        rng = random.Random(S.SEED)
        grid = rng.sample(grid, int(a.n))
    jobs = []
    for cfg in CONFIGS:
        d = ROOT / "results" / "bench" / a.run / a.model / cfg
        d.mkdir(parents=True, exist_ok=True)
        for sc in grid:
            p = d / (sc["scenario_id"].replace("|", "__") + ".json")
            if not p.exists():
                jobs.append((sc, cfg, p))
    print(f"{len(jobs)} conversations to run ({len(grid)} scenarios x configs {CONFIGS}); counterparty {CP_MODEL}", flush=True)

    def work(j):
        sc, cfg, p = j
        err = None
        for attempt in range(4):
            try:
                out = RB.run_one(sc, cfg, a.model, mk)
                out["counterparty_model"] = CP_MODEL
                atomic_write(p, out)
                return None
            except Exception as e:  # one bad conversation must not stop the run
                err = e
                if not X._transient(e):
                    break
                time.sleep(20 * (attempt + 1))
        return f"{sc['scenario_id']} {cfg}: {type(err).__name__} {str(err)[:300]}"

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
