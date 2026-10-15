"""Run the amendment-A6 component ablation on Modal (same pattern as modal_xvendor.py).

Each model runs in its own container. Conversations are written to a Modal Volume and committed every 60 s;
bench/run_bench_xvendor.py skips conversations already on disk, so a restarted container resumes where it stopped.

  modal run --detach scripts/modal_xvendor.py                 # start (or resume) both models
  modal volume get agent-handshake-ablation cpswap results/bench/   # copy results back
"""
import subprocess
import threading
import time

import modal

ROOT = "/root/ah"
vol = modal.Volume.from_name("agent-handshake-ablation", create_if_missing=True)
image = (modal.Image.debian_slim(python_version="3.12")
         .pip_install("anthropic==1.11.0", "openai==3.24.0", "google-genai==2.28.0", "cryptography", "numpy")
         .add_local_dir("bench", f"{ROOT}/bench", ignore=["__pycache__"])
         .add_local_dir("handshake", f"{ROOT}/handshake", ignore=["__pycache__"]))
app = modal.App("agent-handshake-ablation", image=image)


@app.function(volumes={f"{ROOT}/results/bench": vol}, secrets=[modal.Secret.from_name("agent-handshake-xvendor-keys")],
              timeout=86400, retries=modal.Retries(max_retries=3, initial_delay=30.0))
def run(model: str, workers: int = 8, extra: list = None):
    stop = threading.Event()

    def committer():
        while not stop.wait(60):
            vol.commit()

    threading.Thread(target=committer, daemon=True).start()
    try:
        subprocess.run(["python", "bench/run_bench_ablation.py", "--run", "ablation", "--model", model, "--n", "all",
                        "--workers", str(workers)] + (extra or []), cwd=ROOT, check=True)
    finally:
        stop.set()
        vol.commit()
    return model


@app.local_entrypoint()
def main():
    calls = [run.spawn(*args) for args in (("claude-opus-5-5", 5), ("claude-sonnet-5-5", 5), ("claude-haiku-4-5", 3, ["--per-cell", "22"]), ("gpt-6.1-sol", 8), ("gemini-3.1-pro-preview", 10))]
    for c in calls:
        print("finished", c.get())
