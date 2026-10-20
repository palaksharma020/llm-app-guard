"""Assemble every measurement into eval/results/summary.md (the numbers the README and case study quote).

    python eval/report.py

Inputs: eval/results/{baseline,patched}.json (breakit summarize), raw exemplar runs, guard_latency.json,
and optional advisor.json / crossmodel.json when those experiments have run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from breakit.stats import wilson  # noqa: E402

RES = ROOT / "eval" / "results"
NAMES = {"v1": "V1 prompt leak (LLM07)", "v4": "V4 excessive agency (LLM06)",
         "v5": "V5 XSS, browser-executed (LLM05)", "benign": "Benign task success"}
EXEMPLAR = {"v1": "v1-12", "v4": "v4-14", "v5": "v5-21"}
# Where each exemplar was verified against the fixed app (phase configs keep verification separate)
EXEMPLAR_AFTER = {"v1": "patched", "v4": "phase3", "v5": "phase4"}


def _load(name: str) -> dict | None:
    p = RES / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def _pct(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} = **{k / n:.0%}** ({lo:.0%}–{hi:.0%})" if n else "–"


def _exemplar(config: str, suite: str) -> tuple[int, int]:
    raw = RES / "raw" / config
    path = raw / f"{suite}.jsonl"
    if not path.exists():
        return 0, 0
    executed = {}
    render = raw / "v5_render.jsonl"
    if suite == "v5" and render.exists():
        executed = {(r["id"], r["trial"], r["ts"]): r["executed"] for r in map(json.loads, render.read_text().splitlines())}
    k = n = 0
    for r in map(json.loads, path.read_text().splitlines()):
        if r["id"] != EXEMPLAR[suite] or not r.get("exemplar_run"):
            continue
        n += 1
        k += executed.get((r["id"], r["trial"], r["ts"]), r["detector"]["success"]) if suite == "v5" else r["detector"]["success"]
    return k, n


def main() -> None:
    base, patched = _load("baseline"), _load("patched")
    lines = ["# Results", "",
             "Model: `llama3.1:8b-instruct-q3_K_M` (Ollama, default sampling). Rates are successes/trials with Wilson 95% CI.",
             "Attack rows: lower is better. Benign row: higher is better.", ""]

    lines += ["## Full suites (N=3 per prompt)", "",
              "| Suite | Prompts | Vulnerable app | Fixed app |", "|---|---|---|---|"]
    for s in ("v1", "v4", "v5", "benign"):
        b = (base or {}).get("suites", {}).get(s)
        p = (patched or {}).get("suites", {}).get(s)
        cell = lambda v: _pct(v["successes"], v["trials"]) if v else "–"  # noqa: E731
        lines.append(f"| {NAMES[s]} | {(b or p or {}).get('prompts', '–')} | {cell(b)} | {cell(p)} |")

    lines += ["", "## Exemplar attacks (N=10, the ones in the report and screenshots)", "",
              "| Vulnerability | Exemplar | Vulnerable app | Fixed app |", "|---|---|---|---|"]
    for s in ("v1", "v4", "v5"):
        lines.append(f"| {NAMES[s]} | `{EXEMPLAR[s]}` | {_pct(*_exemplar('baseline', s))} | "
                     f"{_pct(*_exemplar(EXEMPLAR_AFTER[s], s))} |")

    lat = _load("guard_latency")
    if lat:
        lines += ["", f"## Guard latency ({lat['replies']} real model replies × {lat['repeat']})", "",
                  "| Guard | p50 | p95 |", "|---|---|---|"]
        lines += [f"| {r['guard']} | {r['p50_us']} µs | {r['p95_us']} µs |" for r in lat["rows"]]
        lines.append(f"\nAll guards: ~{lat['total_p50_us'] / 1000:.2f} ms per reply (p50), against 10–60 s of model time.")

    adv = _load("advisor")
    if adv:
        lines += ["", "## Advisor ablation (deberta prompt-injection classifier, tighten-only)", "", adv["markdown"]]
    xm = _load("crossmodel")
    if xm:
        lines += ["", "## Cross-model check (same attacks, different model)", "", xm["markdown"]]

    (RES / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
