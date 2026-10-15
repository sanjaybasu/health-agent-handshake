"""Regression test: non-finite timestamps (reported in co-author review, 2026-10-15). A request signed with ts = NaN passed
the freshness check in hah2.py because abs(now - nan) > skew is False. Writes results/nan_regression.json."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("conf", ROOT / "scripts" / "01b_protocol_conformance_v2.py")
C = importlib.util.module_from_spec(spec)
sys.argv = [sys.argv[0]]
spec.loader.exec_module(C)
H = C.H

out = {}
for label, bad in (("nan", float("nan")), ("inf", float("inf")), ("string", "now")):
    w = C.world("L4_full_hah")
    real = H.time.time
    H.time.time = lambda bad=bad: bad   # the agent signs the request with a non-finite or non-numeric timestamp
    try:
        try:
            r, _ = C.req(w, "refill_request", ["name", "dob", "medication_list"], {"drug": "metformin 500 mg"})
        except Exception as e:
            out[label] = {"accepted": False, "reason": f"request construction refused: {type(e).__name__}"}
            continue
    finally:
        H.time.time = real
    ok, why, _ = w["cp"].verify(r)
    out[label] = {"accepted": bool(ok), "reason": why}
w = C.world("L4_full_hah")
ok, why, _ = C.legit_t2(w)
out["control_valid_request"] = {"accepted": bool(ok), "reason": why}
(ROOT / "results" / "nan_regression.json").write_text(json.dumps(out, indent=1))
print(json.dumps(out, indent=1))
assert out["control_valid_request"]["accepted"] and not any(v["accepted"] for k, v in out.items() if k != "control_valid_request")
