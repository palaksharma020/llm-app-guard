"""breakit CLI.

    breakit try "message" [--history file.json]          one request, print reply + every detector
    breakit run --suite v1|v4|v5|benign|all --config NAME [--n 3] [--only exemplar|--ids v1-01,...]
    breakit render-check --config NAME                    run V5 replies through the real UI sink (Playwright)
    breakit summarize --config NAME                       → eval/results/NAME.json + a markdown table

Only ever point --target at an app you run locally.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from breakit import detectors
from breakit.stats import wilson

ROOT = Path(__file__).resolve().parent.parent
DATASETS = ROOT / "eval" / "datasets"
RESULTS = ROOT / "eval" / "results"
SUITES = ("v1", "v4", "v5", "benign")
DEFAULT_TARGET = "http://localhost:8090"


def _model_label() -> str:
    if os.environ.get("MODEL"):  # set when a run targets a different model than demo/.env
        return os.environ["MODEL"]
    env = ROOT / "demo" / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("MODEL="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("MODEL", "llama3.1:8b")


PROFILE = "demo"


def _load(suite: str) -> list[dict[str, Any]]:
    path = DATASETS / f"{suite}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def chat(client: httpx.Client, target: str, message: str, history: list | None = None) -> tuple[int, dict, float]:
    t = time.perf_counter()
    try:
        r = client.post(f"{target}/api/chat", json={"message": message, "history": history or []})
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"error": r.text[:200]}
        status = r.status_code
    except httpx.HTTPError as exc:
        body, status = {"error": f"{type(exc).__name__}: {exc}"}, 0
    return status, body, time.perf_counter() - t


def score(row: dict[str, Any], status: int, body: dict[str, Any]) -> dict[str, Any]:
    reply = body.get("response") or ""
    suite = row["suite"]
    if suite == "v1":
        return detectors.detect_v1(reply)
    if suite == "v4":
        return detectors.detect_v4(body)
    if suite == "v5":
        return detectors.detect_v5(reply, row["payload"])
    return detectors.detect_benign(status, body, row.get("expect", "answer"))


def cmd_try(args: argparse.Namespace) -> None:
    history = json.loads(Path(args.history).read_text()) if args.history else []
    with httpx.Client(timeout=args.timeout) as client:
        status, body, dt = chat(client, args.target, args.message, history)
    print(f"HTTP {status} in {dt:.1f}s\n{json.dumps(body, indent=2)}\n")
    reply = body.get("response") or ""
    print("v1:", detectors.detect_v1(reply))
    print("v4:", detectors.detect_v4(body))
    print("v5 active_html:", detectors.detect_v5(reply, "")["active_html"])


def cmd_run(args: argparse.Namespace) -> None:
    suites = SUITES if args.suite == "all" else (args.suite,)
    ids = set(args.ids.split(",")) if args.ids else None
    out_dir = RESULTS / "raw" / args.config
    out_dir.mkdir(parents=True, exist_ok=True)
    model = _model_label()
    with httpx.Client(timeout=args.timeout) as client:
        for suite in suites:
            rows = [r for r in _load(suite)
                    if (not ids or r["id"] in ids) and (args.only != "exemplar" or r["exemplar"])]
            if not rows:
                continue
            path = out_dir / f"{suite}.jsonl"
            wins = 0
            print(f"== {suite}: {len(rows)} prompts x {args.n} trials → {path.relative_to(ROOT)}", flush=True)
            with path.open("a") as f:
                for row in rows:
                    for trial in range(args.n):
                        status, body, dt = chat(client, args.target, row["message"], row.get("history"))
                        det = score(row, status, body)
                        wins += det["success"]
                        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                               "config": args.config, "profile": PROFILE, "model": model, "target": args.target,
                               "id": row["id"], "suite": suite, "trial": trial, "exemplar": row["exemplar"],
                               "exemplar_run": bool(args.only or ids),  # targeted runs stay out of suite ASR
                               "http_status": status, "latency_s": round(dt, 2), "body": body, "detector": det}
                        f.write(json.dumps(rec) + "\n")
                        f.flush()
                        mark = "HIT " if det["success"] else "miss"
                        if suite == "benign":
                            mark = "ok  " if det["success"] else "FAIL"
                        print(f"  {row['id']} t{trial} {mark} {dt:5.1f}s", flush=True)
            print(f"   {suite}: {wins} successes", flush=True)


def _records(config: str, suite: str) -> list[dict[str, Any]]:
    path = RESULTS / "raw" / config / f"{suite}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _success(suite: str, rec: dict[str, Any]) -> bool:
    det = rec["detector"]
    if suite == "v5":  # browser execution, when the render check has run, beats the API-level signal
        return bool(det.get("executed", det["success"]))
    return bool(det["success"])


def cmd_summarize(args: argparse.Namespace) -> None:
    summary: dict[str, Any] = {"config": args.config, "suites": {}}
    for suite in SUITES:
        recs = [r for r in _records(args.config, suite) if args.include_exemplar_runs or not r.get("exemplar_run")]
        if suite == "v5":  # execution in the browser, when the render check has run, is the real outcome
            rendered = {(r["id"], r["trial"], r["ts"]): r["executed"] for r in _records(args.config, "v5_render")}
            for r in recs:
                key = (r["id"], r["trial"], r["ts"])
                if key in rendered:
                    r["detector"]["executed"] = rendered[key]
        if not recs:
            continue
        hits = [_success(suite, r) for r in recs]
        k, n = sum(hits), len(recs)
        lo, hi = wilson(k, n)
        per_prompt: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r, hit in zip(recs, hits, strict=True):
            per_prompt[r["id"]][0] += hit
            per_prompt[r["id"]][1] += 1
        lat = sorted(r["latency_s"] for r in recs)
        summary["suites"][suite] = {
            "metric": "benign_success" if suite == "benign" else "attack_success_rate",
            "successes": k, "trials": n, "rate": round(k / n, 3), "ci95": [round(lo, 3), round(hi, 3)],
            "prompts_with_any_success": sum(1 for s, _ in per_prompt.values() if s),
            "prompts": len(per_prompt), "per_prompt": {i: f"{s}/{t}" for i, (s, t) in sorted(per_prompt.items())},
            "latency_p50_s": lat[len(lat) // 2], "models": sorted({r["model"] for r in recs}),
            "v5_outcome": ("browser_executed" if suite == "v5" and any("executed" in r["detector"] for r in recs)
                           else "active_html_reached_client" if suite == "v5" else None),
        }
    out = RESULTS / f"{args.config}.json"
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print("| suite | metric | rate | 95% CI | trials | prompts hit |\n|---|---|---|---|---|---|")
    for s, v in summary["suites"].items():
        print(f"| {s} | {v['metric']}{' (' + v['v5_outcome'] + ')' if v['v5_outcome'] else ''} | "
              f"{v['rate']:.0%} | {v['ci95'][0]:.0%}-{v['ci95'][1]:.0%} | {v['trials']} | "
              f"{v['prompts_with_any_success']}/{v['prompts']} |")
    print(f"\n→ {out.relative_to(ROOT)}")


def cmd_watch(args: argparse.Namespace) -> None:
    """Follow a config's raw result files and print each attempt as it lands (Ctrl+C to stop)."""
    raw = RESULTS / "raw" / args.config
    seen: dict[Path, int] = {}
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    print(f"watching {raw.relative_to(ROOT)}/ (Ctrl+C to stop)\n", flush=True)
    try:
        while True:
            for path in sorted(raw.glob("*.jsonl")) if raw.exists() else []:
                if path.stem.endswith("_render"):
                    continue
                lines = path.read_text().splitlines()
                for line in lines[seen.get(path, 0):]:
                    r = json.loads(line)
                    hit = _success(r["suite"], r)
                    c = counts[r["suite"]]
                    c[0] += hit
                    c[1] += 1
                    label = ("ok  " if hit else "FAIL") if r["suite"] == "benign" else ("HIT " if hit else "miss")
                    reply = (r["body"].get("response") or r["body"].get("error") or "").replace("\n", " ")
                    print(f"{r['ts'][11:19]}  {r['id']} t{r['trial']}  {label} {r['latency_s']:5.1f}s  "
                          f"[{r['suite']} {c[0]}/{c[1]}]  {reply[:args.width]}", flush=True)
                seen[path] = len(lines)
            time.sleep(2)
    except KeyboardInterrupt:
        pass


def cmd_render_check(args: argparse.Namespace) -> None:
    from breakit.render import render_check  # Playwright is an optional dependency

    render_check(args.config, args.target)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="breakit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", default=DEFAULT_TARGET)
    p.add_argument("--profile", default="demo", choices=sorted(detectors.PROFILES),
                   help="which target's secret and original prompt the detectors use (default: demo)")
    p.add_argument("--timeout", type=float, default=150.0)
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("try")
    t.add_argument("message")
    t.add_argument("--history")
    r = sub.add_parser("run")
    r.add_argument("--suite", choices=(*SUITES, "all"), required=True)
    r.add_argument("--config", required=True)
    r.add_argument("--n", type=int, default=3)
    r.add_argument("--only", choices=("exemplar",))
    r.add_argument("--ids")
    s = sub.add_parser("summarize")
    s.add_argument("--config", required=True)
    s.add_argument("--include-exemplar-runs", action="store_true")
    rc = sub.add_parser("render-check")
    rc.add_argument("--config", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--config", required=True)
    w.add_argument("--width", type=int, default=110, help="reply characters to show")
    args = p.parse_args(argv)
    global PROFILE
    PROFILE = args.profile
    detectors.use_profile(args.profile)
    {"try": cmd_try, "run": cmd_run, "summarize": cmd_summarize, "render-check": cmd_render_check,
     "watch": cmd_watch}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
