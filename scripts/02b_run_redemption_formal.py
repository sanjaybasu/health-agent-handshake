"""Run Tamarin on the permission-carrying (redemption) model and its negative controls.
Writes results/formal_redeem.json in the same format as 02_run_formal_verification.py."""
import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("f02", ROOT / "scripts" / "02_run_formal_verification.py")
f02 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f02)

MODELS = [ROOT / "formal" / "v2" / "hah2_redeem.spthy"] + sorted((ROOT / "formal" / "v2" / "variants_redeem").glob("*.spthy"))


def main():
    version = subprocess.run(["tamarin-prover", "--version"], capture_output=True, text=True).stdout.splitlines()
    maude = subprocess.run(["maude", "--version"], capture_output=True, text=True).stdout.strip()
    res = {"tamarin_version": next((v for v in version if "tamarin-prover" in v), "").strip(),
           "maude_version": maude, "models": [f02.run(m) for m in MODELS]}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "formal_redeem.json").write_text(json.dumps(res, indent=2))
    for m in res["models"]:
        print(m["model"], "wellformed" if m["wellformedness_ok"] else "WELLFORMEDNESS FAILED", m["wall_seconds"], "s")
        for k, v in m["lemmas"].items():
            print(f"   {k:48s} {v['status']:10s} {v['steps']}")


if __name__ == "__main__":
    main()
