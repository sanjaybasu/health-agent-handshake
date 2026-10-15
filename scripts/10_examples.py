"""Illustrative excerpts for the npj article (Table 4) and Supplementary Note 5, quoted verbatim from conversation files.

Each example names a conversation file and the agent turn to quote; the preceding counterparty turn is quoted with it. Quotes are
trimmed only at word boundaries, with an ellipsis. All members and conversations are synthetic.
Writes results/tables/table_examples.md and results/tables/note_examples.md.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "tables"
OUT.mkdir(parents=True, exist_ok=True)
EX = [
    ("Pretext for identity data", "Privacy prompt; Claude Opus 5.5", "confirmatory/claude-opus-5-5/C1/M01__refill_request__ai_agent__A1_pretext_extra_phi.json",
     "address", "Mandate in context; data minimisation", "text"),
    ("Impersonated health plan", "Privacy prompt; Claude Haiku 4.5", "confirmatory/claude-haiku-4-5/C1/M12__appointment_booking__ai_agent__A4_impersonate_plan.json",
     "diagnoses", "Data minimisation", "text"),
    ("Probe for a protected condition", "Status quo; Gemini 3.1 Pro", "xvendor/gemini-3.1-pro-preview/C0/M06__pa_status_inquiry__ai_agent__A6_protected_probe.json",
     "protected_attribute", "Privacy prompt; data minimisation", "text"),
    ("Prompt injection that triggers an action", "Status quo; Claude Haiku 4.5", "confirmatory/claude-haiku-4-5/C0/M12__refill_request__ai_agent__A2_prompt_injection_action.json",
     "@action", "Tool gate; verifier", "text"),
    ("Over-sharing that the verifier rejects", "Verifier only; Gemini 3.1 Pro", "ablation/gemini-3.1-pro-preview/V/M07__pa_status_inquiry__human__A1_pretext_extra_phi.json",
     "address", "Verifier rejected the transaction, not the spoken words", "text"),
    ("Outbound filter at work", "Gate and filter only; Gemini 3.1 Pro", "ablation/gemini-3.1-pro-preview/G/M02__pa_status_inquiry__ivr__A1_pretext_extra_phi.json",
     "@filtered", "Outbound filter (agent's words before and after)", "raw_text"),
    ("Agent declines with the mandate", "Mandate in context only; Claude Opus 5.5", "ablation/claude-opus-5-5/M/M11__appointment_booking__ai_agent__A1_pretext_extra_phi.json",
     "@mandate", "Mandate in context", "text"),
    ("Telephone number passes the filter", "Gate and filter only; Claude Opus 5.5", "ablation/claude-opus-5-5/G/M03__pharmacy_change__ai_agent__A1_pretext_extra_phi.json",
     "phone", "Not caught: the filter does not redact telephone numbers", "text"),
]


def trim(s, n):
    s = " ".join(s.split())
    if len(s) <= n:
        return s
    cut = s[:n].rsplit(" ", 1)[0]
    return cut.rstrip(",;:") + " …"


def pick(d, key):
    tr = d["transcript"]
    allowed = set(d["allowed_fields"])
    for i, t in enumerate(tr):
        if t["speaker"] != "agent":
            continue
        if key == "@action" and t.get("action") not in (None, "none", d["task_action"]):
            return i
        if key == "@filtered" and t.get("raw_text") != t["text"]:
            return i
        if key == "@mandate" and "mandate" in t["text"].lower():
            return i
        if not key.startswith("@") and key in (set(t["disclosed_fields"]) - allowed):
            return i
    raise SystemExit(f"no turn for {key}")


def main():
    rows = ["| Problem | Configuration and agent | Counterparty said | Agent said | Component that addresses it |", "|---|---|---|---|---|"]
    note = []
    for title, cfg, rel, key, comp, field in EX[:7]:
        d = json.load(open(ROOT / "results" / "bench" / rel))
        i = pick(d, key)
        cp = d["transcript"][i - 1]["text"] if i > 0 else ""
        ag = d["transcript"][i]
        said = trim(ag["raw_text"], 160) + " → heard as: " + trim(ag["text"], 160) if field == "raw_text" else trim(ag["text"], 240)
        if key == "@action":
            said += f" [submitted: {ag['action'].replace('_', ' ')}]"
        rows.append(f"| {title} | {cfg} | {trim(cp, 170)} | {said} | {comp} |")
    for title, cfg, rel, key, comp, field in EX:
        d = json.load(open(ROOT / "results" / "bench" / rel))
        i = pick(d, key)
        note.append(f"*{title}* ({cfg}; scenario {d['scenario']['scenario_id'].replace('|', ', ')}).\n")
        for t in d["transcript"][max(0, i - 2): i + 1]:
            who = "Counterparty" if t["speaker"] == "counterparty" else "Agent"
            txt = t["text"]
            if t["speaker"] == "agent" and t.get("raw_text") and t["raw_text"] != t["text"]:
                txt = f"{t['raw_text']} [before the filter; the counterparty heard: {t['text']}]"
            if t["speaker"] == "agent" and t.get("action") not in (None, "none"):
                txt += f" [transaction submitted: {t['action'].replace('_', ' ')} with fields {', '.join(t.get('action_fields', []))}]"
            note.append(f"> {who}: {' '.join(txt.split())}\n>")
        if d["rejected"]:
            note.append(f"> [Counterparty system: rejected, {str(d['rejected'][0][1]).replace('P3_', 'H3: ').replace('_', ' ')}]\n>")
        note.append(f"\nComponent: {comp}.\n")
    (OUT / "table_examples.md").write_text("\n".join(rows) + "\n")
    (OUT / "note_examples.md").write_text("\n".join(note) + "\n")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
