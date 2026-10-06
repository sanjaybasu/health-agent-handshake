# Health Agent Handshake (HAH)

Code for a verification profile by which a pharmacy, payer, transport broker, or clinic can check that an AI agent acting for a patient is accountable, unaltered, authorised for the specific request, and limited to the data fields the patient approved. The repository contains a reference implementation of six proofs and four health risk tiers, symbolic models for the Tamarin prover with negative-control models, a protocol conformance suite, and a harness for a simulation study in which language-model agents call simulated counterparties. All member data are synthetic and generated from a fixed seed. The repository contains no patient data, no study results, and no manuscript text.

## What this is

- `handshake/hah2.py` — reference implementation, version 2 (Ed25519, canonical JSON, SD-JWT-style salted-hash disclosures, identity-provider certificates, status lists, transaction-bound approvals, RFC 9162-style receipt log, telephone verification codes). A research prototype; it has not been audited for production use.
- `handshake/hah.py` — version 1, the verifier used inside the pre-registered simulation backend.
- `formal/v2/` — Tamarin models of the structured channel (`hah2.spthy`) and the telephone fallback (`hah2_voice.spthy`), with negative controls in `variants/` and `variants_voice/`, each removing one check. `formal/v1/` holds the version 1 models.
- `bench/scenarios.py` — synthetic members with canary values, tasks, counterparty types, and scripted attack conditions.
- `bench/run_bench.py` — conversation harness for four verification configurations (status quo, privacy prompt, handshake, full handshake with operator-side enforcement).
- `scripts/` — numbered stages: conformance suites (`01_`, `01b_`), Tamarin runs (`02_`), deterministic scoring (`03_`), tables (`04_`), and a replay of benchmark transactions through both verifier versions (`05_`).

## Reproducibility

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.lock.txt
brew install tamarin-prover/tap/tamarin-prover          # Tamarin 1.12.0, Maude 3.5.1
.venv/bin/python scripts/01b_protocol_conformance_v2.py  # writes results/conformance_v2.json
.venv/bin/python scripts/02_run_formal_verification.py   # version 2 models; --v1 for version 1
export ANTHROPIC_API_KEY=...                              # for the simulation only
.venv/bin/python bench/run_bench.py --run pilot --model claude-sonnet-5-5 --n 48
.venv/bin/python scripts/03_score_bench.py --run pilot
```

The simulation calls the Anthropic API and incurs cost. Results are written to `results/`, which is not tracked.

## Study context

The simulation study is pre-registered on the Open Science Framework (project jgb4k). Manuscripts describing the profile and the study are under peer review.

## License

MIT. See `LICENSE`.
