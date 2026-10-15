"""Cross-vendor extension of the benchmark (amendment A4): OpenAI and Google agent models.

Reuses bench/run_bench.py unchanged: the scenarios, prompts, counterparty simulator (claude-sonnet-5-5), backend,
operator gate, and conversation loop are the locked ones. Only the agent call is replaced. Each vendor adapter takes
the Anthropic-format message list that run_one builds, converts it to the vendor's format, and returns a response
with the Anthropic shape that run_one reads (content blocks, stop_reason, usage).

Usage:
  python bench/run_bench_xvendor.py --run xvendor --model gpt-6.1-sol --n all
  python bench/run_bench_xvendor.py --run xvendor --model gemini-3.1-pro-preview --n all
"""
import argparse
import concurrent.futures as cf
import json
import os
import random
import time
from pathlib import Path
from types import SimpleNamespace

import run_bench as RB
from run_bench import S, TURN_TOOL, atomic_write

ROOT = Path(__file__).resolve().parents[1]
REASONING_EFFORT = "medium"   # matches output_config effort "medium" for the Claude Opus and Sonnet agents


class Blocks(list):
    """Assistant content blocks in Anthropic shape, carrying the vendor's raw message for the next request."""
    raw = None


def _blocks(raw, text, calls):
    b = Blocks()
    if text:
        b.append(SimpleNamespace(type="text", text=text))
    for cid, name, args in calls:
        b.append(SimpleNamespace(type="tool_use", id=cid, name=name, input=args))
    b.raw = raw
    return b


def _resp(content, stop_reason, n_in, n_out, category=None):
    return SimpleNamespace(content=content, stop_reason=stop_reason,
                           stop_details=SimpleNamespace(category=category) if category else None,
                           usage=SimpleNamespace(input_tokens=n_in, output_tokens=n_out))


# ---------------------------------------------------------------- OpenAI (Responses API, strict function, stateless)

_oa = None


def _openai_call(model, system, messages):
    global _oa
    if _oa is None:
        import openai
        _oa = openai.OpenAI(max_retries=6)
    items = []
    for m in messages:
        c = m["content"]
        if m["role"] == "assistant":
            items.extend(c.raw)   # prior output items, including encrypted reasoning
        elif isinstance(c, str):
            items.append({"role": "user", "content": c})
        else:
            for tr in c:
                items.append({"type": "function_call_output", "call_id": tr["tool_use_id"], "output": tr["content"]})
    tool = {"type": "function", "name": TURN_TOOL["name"], "description": TURN_TOOL["description"],
            "parameters": TURN_TOOL["input_schema"], "strict": True}
    r = _oa.responses.create(model=model, instructions=system, input=items, tools=[tool], tool_choice="auto",
                             parallel_tool_calls=False, reasoning={"effort": REASONING_EFFORT}, store=False,
                             include=["reasoning.encrypted_content"], max_output_tokens=16000)
    n_in, n_out = r.usage.input_tokens, r.usage.output_tokens
    calls, text, refused = [], [], False
    for it in r.output:
        if it.type == "function_call":
            calls.append((it.call_id, it.name, json.loads(it.arguments)))
        elif it.type == "message":
            for c in it.content:
                if c.type == "refusal":
                    refused = True
                elif c.type == "output_text":
                    text.append(c.text)
    if refused and not calls:
        return _resp(Blocks(), "refusal", n_in, n_out, "openai_refusal")
    raw = [it.model_dump(exclude_none=True) for it in r.output]
    return _resp(_blocks(raw, "".join(text).strip(), calls), "tool_use" if calls else "end_turn", n_in, n_out)


# ---------------------------------------------------------------- Google (Gemini, function calling)

_gm = None


def _gemini_call(model, system, messages):
    global _gm
    from google.genai import types
    if _gm is None:
        from google import genai
        _gm = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    contents, names = [], {}
    for m in messages:
        c = m["content"]
        if m["role"] == "assistant":
            contents.append(c.raw)
            for b in c:
                if b.type == "tool_use":
                    names[b.id] = b.name
        elif isinstance(c, str):
            contents.append(types.Content(role="user", parts=[types.Part(text=c)]))
        else:
            contents.append(types.Content(role="user", parts=[
                types.Part.from_function_response(name=names.get(tr["tool_use_id"], "turn"),
                                                  response={"result": tr["content"]}) for tr in c]))
    decl = types.FunctionDeclaration(name=TURN_TOOL["name"], description=TURN_TOOL["description"],
                                     parameters_json_schema=TURN_TOOL["input_schema"])
    cfg = types.GenerateContentConfig(
        system_instruction=system, tools=[types.Tool(function_declarations=[decl])],
        tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="AUTO")),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        thinking_config=types.ThinkingConfig(thinking_level=REASONING_EFFORT), max_output_tokens=16000)
    r = _gm.models.generate_content(model=model, contents=contents, config=cfg)
    um = r.usage_metadata
    n_in = (um.prompt_token_count or 0) if um else 0
    n_out = ((um.candidates_token_count or 0) + (um.thoughts_token_count or 0)) if um else 0
    cand = r.candidates[0] if r.candidates else None
    fr = str(getattr(cand, "finish_reason", "") or "")
    if cand is None or cand.content is None or any(x in fr for x in ("SAFETY", "PROHIBITED", "BLOCKLIST", "SPII")):
        return _resp(Blocks(), "refusal", n_in, n_out, f"gemini_{fr or 'blocked'}")
    calls, text = [], []
    for i, p in enumerate(cand.content.parts or []):
        if p.function_call:
            calls.append((p.function_call.id or f"call_{len(messages)}_{i}", p.function_call.name,
                          dict(p.function_call.args or {})))
        elif p.text and not p.thought:
            text.append(p.text)
    return _resp(_blocks(cand.content, "".join(text).strip(), calls), "tool_use" if calls else "end_turn", n_in, n_out)


def call_agent(model, system, messages):
    if model.startswith(("gpt-", "o")):
        return _openai_call(model, system, messages)
    if model.startswith("gemini-"):
        return _gemini_call(model, system, messages)
    raise SystemExit(f"unsupported model {model}")


RB.call_agent = call_agent   # run_one resolves call_agent from the run_bench module at call time


def _transient(e):
    name = type(e).__name__
    code = getattr(e, "code", None) or getattr(e, "status_code", None)
    return (name in ("APIConnectionError", "APITimeoutError", "InternalServerError", "RateLimitError", "ServerError",
                     "ConnectionError", "ReadTimeout", "RemoteProtocolError")
            or code in (429, 500, 502, 503, 504))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--n", default="48")
    ap.add_argument("--configs", default=",".join(RB.CONFIGS))
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    members = S.make_members()
    mk = {m["record"]["member_key"]: m for m in members}
    grid = S.scenario_grid(members)
    if a.n != "all":   # same stratified sample as run_bench.py
        rng = random.Random(S.SEED)
        cells = {}
        for r in grid:
            cells.setdefault((r["counterparty_type"], r["condition"]), []).append(r)
        n = int(a.n)
        keys = sorted(cells)
        per = max(1, n // len(keys))
        grid = [r for k in keys for r in rng.sample(cells[k], min(per, len(cells[k])))]
        extra = n - len(grid)
        if extra > 0:
            rest = [r for r in S.scenario_grid(members) if r not in grid]
            grid += rng.sample(rest, extra)
    jobs = []
    for cfg in a.configs.split(","):
        d = ROOT / "results" / "bench" / a.run / a.model / cfg
        d.mkdir(parents=True, exist_ok=True)
        for sc in grid:
            p = d / (sc["scenario_id"].replace("|", "__") + ".json")
            if not p.exists():
                jobs.append((sc, cfg, p))
    print(f"{len(jobs)} conversations to run ({len(grid)} scenarios x configs {a.configs})", flush=True)

    def work(j):
        sc, cfg, p = j
        err = None
        for attempt in range(4):
            try:
                atomic_write(p, RB.run_one(sc, cfg, a.model, mk))
                return None
            except Exception as e:  # one bad conversation must not stop the run (as amendment A3)
                err = e
                if not _transient(e):
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
