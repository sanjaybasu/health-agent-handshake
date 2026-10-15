"""Amendment A8 on Modal: C4 and IFC arms for five agents, and claude-haiku-5-5 C0-C3."""
import subprocess
import threading

import modal

ROOT = "/root/ah"
vol = modal.Volume.from_name("agent-handshake-a8", create_if_missing=True)
image = (modal.Image.debian_slim(python_version="3.12")
         .pip_install("anthropic==1.11.0", "openai==3.24.0", "google-genai==2.28.0", "cryptography", "numpy")
         .add_local_dir("bench", f"{ROOT}/bench", ignore=["__pycache__"])
         .add_local_dir("handshake", f"{ROOT}/handshake", ignore=["__pycache__"]))
app = modal.App("agent-handshake-a8", image=image)


@app.function(volumes={f"{ROOT}/results/bench": vol}, secrets=[modal.Secret.from_name("agent-handshake-xvendor-keys")],
              timeout=86400, retries=modal.Retries(max_retries=3, initial_delay=30.0))
def run(cmd: list):
    stop = threading.Event()

    def committer():
        while not stop.wait(60):
            vol.commit()

    threading.Thread(target=committer, daemon=True).start()
    try:
        subprocess.run(["python"] + cmd, cwd=ROOT, check=False)
    finally:
        stop.set()
        vol.commit()
    return " ".join(cmd)


@app.local_entrypoint()
def main():
    plan = [["bench/run_bench_a8.py", "--run", "a8", "--model", "claude-opus-5-5", "--workers", "5"],
            ["bench/run_bench_a8.py", "--run", "a8", "--model", "claude-sonnet-5-5", "--workers", "5"],
            ["bench/run_bench_a8.py", "--run", "a8", "--model", "claude-haiku-4-5", "--per-cell", "22", "--workers", "3"],
            ["bench/run_bench_a8.py", "--run", "a8", "--model", "gpt-6.1-sol", "--workers", "8"],
            ["bench/run_bench_a8.py", "--run", "a8", "--model", "gemini-3.1-pro-preview", "--workers", "10"],
            ["bench/run_bench.py", "--run", "h55", "--model", "claude-haiku-5-5", "--n", "all", "--workers", "4"]]
    for c in [run.spawn(p) for p in plan]:
        print("finished", c.get())
