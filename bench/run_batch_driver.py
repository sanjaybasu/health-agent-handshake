"""Amendment A9: run registered conversations through the Message Batches API.

Each conversation runs in its own thread through the unchanged runner (bench/run_bench.py via run_bench_ablation.py or
run_bench_a8.py). The only change is transport: the runner's Anthropic client is replaced by a proxy whose messages.create()
queues the request and waits. A coordinator collects the pending requests of all conversations into one Message Batches
request per round, waits for it to end, and returns each result to its conversation. Model, parameters, prompts, turn
limits, and scoring are those of the runner. Batch processing costs half the standard price.

Usage:
  python bench/run_batch_driver.py --runner ablation --run ablation --model claude-haiku-4-5 --arms M,V,D,G
  python bench/run_batch_driver.py --runner a8 --run a8 --model claude-haiku-4-5 --arms C4,IFC
"""
import argparse
import importlib
import json
import sys
import threading
import time
from pathlib import Path

import anthropic

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))


class _Pending:
    def __init__(self, params):
        self.params, self.event, self.result, self.error, self.tries = params, threading.Event(), None, None, 0


class Coordinator:
    def __init__(self, real, log, poll=30, idle=20, max_tries=4):
        self.real, self.log, self.poll, self.idle, self.max_tries = real, log, poll, idle, max_tries
        self.lock, self.pending, self.active, self.last = threading.Lock(), [], 0, time.time()
        self.rounds = 0

    def create(self, **params):
        p = _Pending(params)
        with self.lock:
            self.pending.append(p)
            self.last = time.time()
        p.event.wait()
        if p.error:
            raise p.error
        return p.result

    def run(self, done):
        while not done.is_set() or self.pending:
            time.sleep(2)
            with self.lock:
                ready = self.pending and (len(self.pending) >= self.active or time.time() - self.last > self.idle)
                batch = self.pending[:100000] if ready else []
                self.pending = self.pending[len(batch):]
            if batch:
                self._submit(batch)

    def _submit(self, batch):
        self.rounds += 1
        ids = {f"r{self.rounds}-{i}": p for i, p in enumerate(batch)}
        mb = self.real.messages.batches.create(requests=[{"custom_id": k, "params": p.params} for k, p in ids.items()])
        self.log(f"round {self.rounds}: batch {mb.id} with {len(ids)} requests")
        while True:
            time.sleep(self.poll)
            mb = self.real.messages.batches.retrieve(mb.id)
            if mb.processing_status == "ended":
                break
        retry = []
        for r in self.real.messages.batches.results(mb.id):
            p = ids.pop(r.custom_id)
            if r.result.type == "succeeded":
                p.result = r.result.message
                p.event.set()
            else:
                p.tries += 1
                if p.tries < self.max_tries:
                    retry.append(p)
                else:
                    p.error = RuntimeError(f"batch request {r.result.type}: {getattr(r.result, 'error', '')}")
                    p.event.set()
        for p in ids.values():  # missing from results
            retry.append(p)
        c = mb.request_counts
        self.log(f"round {self.rounds}: succeeded {c.succeeded}, errored {c.errored}, expired {c.expired}; retrying {len(retry)}")
        if retry:
            with self.lock:
                self.pending = retry + self.pending


class _Proxy:
    def __init__(self, coord):
        self.messages = self
        self._coord = coord

    def create(self, **params):
        return self._coord.create(**params)


def main():
    threading.stack_size(512 * 1024)
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", choices=["ablation", "a8"], required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--arms", required=True)
    ap.add_argument("--n", default="all")
    a = ap.parse_args()
    mod = importlib.import_module("run_bench_ablation" if a.runner == "ablation" else "run_bench_a8")
    RB = mod.RB
    S = RB.S
    logf = open(ROOT / "results" / f"batch_driver_{a.runner}_{a.model}.log", "a")

    def log(msg):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    coord = Coordinator(anthropic.Anthropic(max_retries=6), log)
    RB.client = _Proxy(coord)  # run_bench resolves `client` at call time
    members = S.make_members()
    mk = {m["record"]["member_key"]: m for m in members}
    grid = S.scenario_grid(members)
    if a.n != "all":
        import random
        grid = random.Random(S.SEED).sample(grid, int(a.n))
    jobs = []
    for arm in a.arms.split(","):
        d = ROOT / "results" / "bench" / a.run / a.model / arm
        d.mkdir(parents=True, exist_ok=True)
        for sc in grid:
            p = d / (sc["scenario_id"].replace("|", "__") + ".json")
            if not p.exists():
                jobs.append((sc, arm, p))
    log(f"{len(jobs)} conversations to run ({len(grid)} scenarios x arms {a.arms})")
    done, failed = threading.Event(), []

    def work(job):
        sc, arm, p = job
        try:
            RB.atomic_write(p, mod.run_arm(sc, arm, a.model, mk))
        except Exception as e:  # one bad conversation must not stop the run; it is rerun on the next invocation
            failed.append(f"{sc['scenario_id']} {arm}: {type(e).__name__} {str(e)[:200]}")
        finally:
            with coord.lock:
                coord.active -= 1

    coord.active = len(jobs)
    ct = threading.Thread(target=coord.run, args=(done,), daemon=True)
    ct.start()
    threads = [threading.Thread(target=work, args=(j,), daemon=True) for j in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    done.set()
    ct.join()
    log(f"finished: {len(jobs) - len(failed)} written, {len(failed)} failed, {coord.rounds} batch rounds")
    for f in failed:
        log("FAILED " + f)


if __name__ == "__main__":
    main()
