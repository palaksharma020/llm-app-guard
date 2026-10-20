"""Advisor ablation: what does the DeBERTa injection classifier add, alone and on top of the fixes?

    .venv-guard/bin/python eval/score_advisor.py      # → eval/results/advisor.json (+ markdown for summary.md)

Because the advisor can only refuse before the model runs (tighten-only), every configuration can be
derived from the recorded per-prompt results without calling the LLM again:
    vulnerable + advisor   = baseline hits on prompts the advisor does NOT flag
    fixed + advisor        = patched hits on unflagged prompts; flagged benign prompts become failures
The classifier sees only the user's message: attacks carried in forged history are invisible to it.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))
from matrix import _hit, _records  # noqa: E402
from report import _pct  # noqa: E402

from guard_mcp.advisor_deberta import DebertaAdvisor  # noqa: E402

SUITES = ("v1", "v4", "v5", "benign")
NAMES = {"v1": "V1 prompt leak", "v4": "V4 excessive agency", "v5": "V5 XSS (browser)", "benign": "Benign success"}


def main() -> None:
    advisor = DebertaAdvisor()
    prompts = {s: [json.loads(x) for x in (ROOT / f"eval/datasets/{s}.jsonl").read_text().splitlines()] for s in SUITES}
    advisor.score("warm up")
    flags, latencies = {}, []
    for rows in prompts.values():
        for row in rows:
            t = time.perf_counter()
            flags[row["id"]] = advisor.score(row["message"])
            latencies.append((time.perf_counter() - t) * 1000)

    table = ["| Suite | Vulnerable | Vulnerable + advisor | Fixed | Fixed + advisor |", "|---|---|---|---|---|"]
    data = {}
    for s in SUITES:
        cells = {}
        for cfg in ("baseline", "patched"):
            recs = _records(cfg, s)
            hits = sum(_hit(s, r) for r in recs)
            # A flagged prompt is refused before the model runs: an attack fails, a benign task fails too.
            with_adv = sum(_hit(s, r) and not flags[r["id"]].flagged for r in recs)
            cells[cfg] = (hits, len(recs))
            cells[cfg + "+adv"] = (with_adv, len(recs))
        data[s] = {k: list(v) for k, v in cells.items()}
        table.append(f"| {NAMES[s]} | {_pct(*cells['baseline'])} | {_pct(*cells['baseline+adv'])} | "
                     f"{_pct(*cells['patched'])} | {_pct(*cells['patched+adv'])} |")

    attack_ids = [r["id"] for s in ("v1", "v4", "v5") for r in prompts[s]]
    benign_ids = [r["id"] for r in prompts["benign"]]
    tp = sum(flags[i].flagged for i in attack_ids)
    fp = sum(flags[i].flagged for i in benign_ids)
    per_suite = {s: f"{sum(flags[r['id']].flagged for r in prompts[s])}/{len(prompts[s])}" for s in SUITES}
    detector = (f"Flagged {tp}/{len(attack_ids)} attack prompts (V1 {per_suite['v1']}, V4 {per_suite['v4']}, "
                f"V5 {per_suite['v5']}) and {fp}/{len(benign_ids)} benign prompts. "
                f"Precision {tp / max(1, tp + fp):.0%}, recall {tp / len(attack_ids):.0%}. "
                f"Latency p50 {statistics.median(latencies):.0f} ms on CPU.")
    missed = [i for i in attack_ids if not flags[i].flagged]
    benign_flagged = [i for i in benign_ids if flags[i].flagged]
    md = "\n".join(table) + "\n\n" + detector
    out = {"advisor": advisor.name, "threshold": advisor.threshold, "suites": data, "detector": detector,
           "flags": {i: {"score": f.score, "flagged": f.flagged} for i, f in flags.items()},
           "attacks_missed": missed, "benign_flagged": benign_flagged, "markdown": md}
    (ROOT / "eval/results/advisor.json").write_text(json.dumps(out, indent=2) + "\n")
    print(md)
    print("\nbenign flagged:", benign_flagged)
    print("attacks missed:", len(missed), missed[:15])


if __name__ == "__main__":
    main()
