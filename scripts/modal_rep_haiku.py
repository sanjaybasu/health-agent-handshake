"""Amendment A7 repeated runs on Modal: C1 and C3 on the registered stratified sample of 198 scenarios, runs rep2 and rep3."""
import subprocess
import threading

import modal

ROOT = "/root/ah"
vol = modal.Volume.from_name("agent-handshake-rep", create_if_missing=True)
image = (modal.Image.debian_slim(python_version="3.12")
         .pip_install("anthropic==1.11.0", "openai==3.24.0", "google-genai==2.28.0", "cryptography", "numpy")
         .add_local_dir("bench", f"{ROOT}/bench", ignore=["__pycache__"])
         .add_local_dir("handshake", f"{ROOT}/handshake", ignore=["__pycache__"]))
app = modal.App("agent-handshake-rep", image=image)


@app.function(volumes={f"{ROOT}/results/bench": vol}, secrets=[modal.Secret.from_name("agent-handshake-xvendor-keys")],
              timeout=86400, retries=modal.Retries(max_retries=3, initial_delay=30.0))
def run(model: str, rep: str, workers: int):
    stop = threading.Event()

    def committer():
        while not stop.wait(60):
            vol.commit()

    threading.Thread(target=committer, daemon=True).start()
    script = "bench/run_bench.py" if model.startswith("claude-") else "bench/run_bench_xvendor.py"
    try:
        subprocess.run(["python", script, "--run", rep, "--model", model, "--n", "198", "--configs", "C1,C3",
                        "--workers", str(workers)], cwd=ROOT, check=False)
    finally:
        stop.set()
        vol.commit()
    return model, rep


@app.local_entrypoint()
def main():
    plan = [("claude-haiku-4-5", "rep2", 3), ("claude-haiku-4-5", "rep3", 1)]
    for c in [run.spawn(*p) for p in plan]:
        print("finished", c.get())
