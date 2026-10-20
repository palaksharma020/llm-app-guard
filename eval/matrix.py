"""Per-prompt test matrix: every attack and benign prompt, before and after the fixes, and *how* it was stopped.

    python eval/matrix.py     # → eval/results/test_matrix.md

Reads the N=3 suite runs (configs `baseline` and `patched`, exemplar runs excluded) and the V5 browser
render checks. No model calls: it only re-reads recorded results.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "eval" / "results" / "raw"
DATA = ROOT / "eval" / "datasets"
SUITES = {"v1": "V1 prompt leakage (LLM07)", "v4": "V4 excessive agency (LLM06)",
          "v5": "V5 XSS via model output (LLM05)", "benign": "Benign (utility)"}


def _records(config: str, suite: str) -> list[dict]:
    path = RAW / config / f"{suite}.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    rows = [r for r in rows if not r.get("exemplar_run")]
    if suite == "v5":
        render = RAW / config / "v5_render.jsonl"
        ran = {(r["id"], r["trial"], r["ts"]): r["executed"] for r in map(json.loads, render.read_text().splitlines())} if render.exists() else {}
        for r in rows:
            r["detector"]["executed"] = ran.get((r["id"], r["trial"], r["ts"]), False)
    return rows


def _hit(suite: str, r: dict) -> bool:
    return bool(r["detector"]["executed"]) if suite == "v5" else bool(r["detector"]["success"])


def _how(suite: str, r: dict) -> str:
    """Which control (or model behaviour) produced this outcome on the fixed app."""
    b = r["body"]
    if r["http_status"] != 200:
        return "timeout/error"
    if b.get("blocked"):
        return "blocked: leak scan"
    if suite == "v4":
        if b.get("actions_denied"):
            reasons = sorted({x for a in b["actions_denied"] for x in a["reasons"]})
            return "denied: " + ",".join(reasons)
        if b.get("actions_pending"):
            return "grant (legit)" if not r["detector"]["success"] else "grant (ILLEGIT)"
        return "no proposal"
    if suite == "v5":
        return "ran" if r["detector"]["executed"] else ("text only" if not r["detector"]["active_html"] else "inert html")
    if suite == "benign":
        if r["detector"].get("refund_reached"):
            return "refund → Confirm"
        return "answered" if r["detector"]["success"] else "not answered"
    return "no secret in reply"


def _short(text: str, n: int = 70) -> str:
    text = " ".join(text.split()).replace("|", "\\|")
    return text if len(text) <= n else text[: n - 1] + "…"


def main() -> None:
    out = ["# Test matrix: before vs after, per prompt", "",
           "Each prompt ran 3 times against the vulnerable app (`baseline`) and 3 times against the fixed app (`patched`), "
           "model `llama3.1:8b-instruct-q3_K_M`. Attack columns count successful attacks (lower is better); the benign "
           "section counts successful tasks (higher is better). **How (after)** says which control, or model behaviour, "
           "produced each fixed-app outcome. Rows marked † are hand-written (synthetic); the rest come from public corpora.", ""]
    totals = []
    for suite, title in SUITES.items():
        rows = {r["id"]: r for r in map(json.loads, (DATA / f"{suite}.jsonl").read_text().splitlines())}
        before, after = defaultdict(list), defaultdict(list)
        for r in _records("baseline", suite):
            before[r["id"]].append(r)
        for r in _records("patched", suite):
            after[r["id"]].append(r)
        out += [f"## {title}", "", "| Id | Prompt | Source | Before | After | How (after) |", "|---|---|---|---|---|---|"]
        kb = nb = ka = na = 0
        for rid, row in rows.items():
            b, a = before.get(rid, []), after.get(rid, [])
            hb, ha = sum(_hit(suite, r) for r in b), sum(_hit(suite, r) for r in a)
            kb, nb, ka, na = kb + hb, nb + len(b), ka + ha, na + len(a)
            how = ", ".join(f"{k} ×{v}" if v > 1 else k for k, v in Counter(_how(suite, r) for r in a).most_common())
            label = row.get("case") or row.get("payload") or row["message"]
            src = row["source"].split(" ")[0] + (" †" if row.get("synthetic") else "")
            flag = " ⚠️" if (suite != "benign" and ha) or (suite == "benign" and ha < len(a)) else ""
            out.append(f"| {rid}{' ★' if row.get('exemplar') else ''} | {_short(label)} | {src} | {hb}/{len(b)} | "
                       f"**{ha}/{len(a)}**{flag} | {how} |")
        out += ["", f"**Total:** before {kb}/{nb}, after **{ka}/{na}**.", ""]
        totals.append((title, kb, nb, ka, na))
    out += ["## Summary", "", "| Suite | Before | After |", "|---|---|---|"]
    out += [f"| {t} | {kb}/{nb} | **{ka}/{na}** |" for t, kb, nb, ka, na in totals]
    out += ["", "★ = exemplar used in the report and screenshots (also run N=10 separately: 10/10 before, 0/10 after)."]
    (ROOT / "eval/results/test_matrix.md").write_text("\n".join(out) + "\n")
    print("\n".join(out[-8:]))


if __name__ == "__main__":
    main()
