"""Latency of each deterministic guard, measured on real model replies recorded by breakit.

    python eval/bench_guards.py [config]     # default config: demo-off → eval/results/guard_latency.json

The guards run on every reply, so their cost is per request. Compare with the model's own latency
(seconds) to see what the security layer adds.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))

import shop as policy  # noqa: E402  (the demo shop's own policy: same validators as the app)
from agentic_core import (  # noqa: E402
    GrantIssuer,
    ProtectedValue,
    authorize,
    make_canary,
    parse_action_proposals,
    sanitize_llm_text,
    scan_for_leaks,
    strip_action_commands,
)

REPEAT = 20


def replies(config: str) -> list[str]:
    out = []
    for path in sorted((ROOT / "eval/results/raw" / config).glob("*.jsonl")):
        if path.stem.endswith("_render"):
            continue
        for line in path.read_text().splitlines():
            text = json.loads(line)["body"].get("response")
            if text:
                out.append(text)
    return out


def bench(name: str, fn, inputs: list[str]) -> dict:
    samples = []
    for _ in range(REPEAT):
        for text in inputs:
            t = time.perf_counter_ns()
            fn(text)
            samples.append((time.perf_counter_ns() - t) / 1000)  # µs
    samples.sort()
    return {"guard": name, "calls": len(samples), "p50_us": round(statistics.median(samples), 1),
            "p95_us": round(samples[int(len(samples) * 0.95)], 1), "max_us": round(samples[-1], 1)}


def main() -> None:
    inputs = replies(sys.argv[1] if len(sys.argv) > 1 else "demo-off")
    if not inputs:
        raise SystemExit("no recorded replies: run breakit against the target first")
    prompt = "x " * 400 + make_canary()
    protected = [ProtectedValue("promo_code", "TRAILHEAD25")]
    alice = policy.principal_for("alice@example.com")
    issuer = GrantIssuer(b"k" * 32)

    def actions(text: str) -> None:
        for p in parse_action_proposals(text):
            if authorize(p, alice, policy.POLICY).decision.value == "NEEDS_CONFIRMATION":
                issuer.issue(alice, p)

    rows = [
        bench("V1 scan_for_leaks", lambda t: scan_for_leaks(t, protected=protected, canaries=[make_canary()],
                                                            reference_prompt=prompt), inputs),
        bench("V4 parse + authorize (+ grant)", actions, inputs),
        bench("V5 strip + sanitize_llm_text", lambda t: sanitize_llm_text(strip_action_commands(t)), inputs),
    ]
    total_p50 = sum(r["p50_us"] for r in rows)
    out = {"replies": len(inputs), "repeat": REPEAT, "rows": rows, "total_p50_us": round(total_p50, 1)}
    (ROOT / "eval/results/guard_latency.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"{len(inputs)} real replies × {REPEAT}\n\n| guard | p50 | p95 | max |\n|---|---|---|---|")
    for r in rows:
        print(f"| {r['guard']} | {r['p50_us']} µs | {r['p95_us']} µs | {r['max_us']} µs |")
    print(f"\nAll guards, p50 sum: {total_p50:.0f} µs per reply")


if __name__ == "__main__":
    main()
