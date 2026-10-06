"""Run Tamarin on the main model, the voice model, and the negative-control variants.
Default: version 2 models in formal/v2/ (results/formal_v2.json). With --v1: version 1 (results/formal.json).

Writes results/formal.json: per model, per lemma, status (verified / falsified), proof steps,
plus prover version and wall time. Exits non-zero if any wellformedness check fails.
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal"
VERSION = "v2" if "--v1" not in sys.argv else "v1"
if VERSION == "v2":
    MODELS = ([FORMAL / "v2" / "hah2.spthy", FORMAL / "v2" / "hah2_voice.spthy"] + sorted((FORMAL / "v2" / "variants").glob("*.spthy"))
              + sorted((FORMAL / "v2" / "variants_voice").glob("*.spthy")))
    OUT_NAME = "formal_v2.json"
else:
    MODELS = [FORMAL / "v1" / "hah.spthy", FORMAL / "v1" / "hah_voice.spthy"] + sorted((FORMAL / "v1" / "variants").glob("*.spthy"))
    OUT_NAME = "formal.json"
LEMMA = re.compile(r"^\s+(\S+) \((all-traces|exists-trace)\): (verified|falsified - found trace|analysis incomplete) \((\d+) steps\)")


def run(model: Path) -> dict:
    t0 = time.time()
    p = subprocess.run(["tamarin-prover", "--prove", "--derivcheck-timeout=0", str(model)],
                       capture_output=True, text=True)
    wall = time.time() - t0
    out = p.stdout + p.stderr
    (model.parent / (model.stem + "_proof.txt")).write_text(out)
    summary = out[out.find("summary of summaries"):]
    lemmas = {}
    for line in summary.splitlines():
        m = LEMMA.match(line)
        if m:
            lemmas[m.group(1)] = {"kind": m.group(2), "status": m.group(3).split(" -")[0], "steps": int(m.group(4))}
    return {"model": str(model.relative_to(ROOT)), "wall_seconds": round(wall, 2),
            "wellformedness_ok": "wellformedness check failed" not in summary, "lemmas": lemmas}


def main():
    version = subprocess.run(["tamarin-prover", "--version"], capture_output=True, text=True).stdout.splitlines()
    maude = subprocess.run(["maude", "--version"], capture_output=True, text=True).stdout.strip()
    only = [a.split("=", 1)[1] for a in sys.argv if a.startswith("--only=")]
    prev = {}
    if only and (ROOT / "results" / OUT_NAME).exists():
        prev = {m["model"]: m for m in json.load(open(ROOT / "results" / OUT_NAME))["models"]}
    models = []
    for m in MODELS:
        key = str(m.relative_to(ROOT))
        models.append(run(m) if (not only or any(o in key for o in only) or key not in prev) else prev[key])
    res = {"tamarin_version": next((v for v in version if "tamarin-prover" in v), "").strip(),
           "maude_version": maude, "models": models}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / OUT_NAME).write_text(json.dumps(res, indent=2))
    for m in res["models"]:
        print(m["model"], "wellformed" if m["wellformedness_ok"] else "WELLFORMEDNESS FAILED", m["wall_seconds"], "s")
        for k, v in m["lemmas"].items():
            print(f"   {k:48s} {v['status']:10s} {v['steps']}")
    if not all(m["wellformedness_ok"] for m in res["models"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
