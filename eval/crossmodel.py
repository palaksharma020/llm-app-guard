"""Cross-model check: do the fixes hold when the model behind the app changes? (SecureBot case study)

The fixes were designed not to depend on model behaviour (secret not in the prompt, code authorizes
actions, text rendering). This measures it: the same three exemplars against the vulnerable and the
fixed app, on llama3.1:8b (q3) and on a different model (llama3.2:3b).

    # runs: breakit --profile securebot ... --config xm-vuln-3b / xm-fixed-3b (see docs/case-study.md); then
    python eval/crossmodel.py     # → eval/results/crossmodel.json (+ markdown for summary.md)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
from report import EXEMPLAR_AFTER, NAMES, _exemplar, _pct  # noqa: E402

RUNS = {  # model → (vulnerable config, {suite: fixed config})
    "llama3.1:8b-instruct-q3_K_M": ("baseline", EXEMPLAR_AFTER),
    "llama3.2:3b": ("xm-vuln-3b", {s: "xm-fixed-3b" for s in ("v1", "v4", "v5")}),
}


def main() -> None:
    rows = ["| Vulnerability | Model | Vulnerable app | Fixed app |", "|---|---|---|---|"]
    data = []
    for suite in ("v1", "v4", "v5"):
        for model, (vuln_cfg, fixed_cfgs) in RUNS.items():
            before, after = _exemplar(vuln_cfg, suite), _exemplar(fixed_cfgs[suite], suite)
            data.append({"suite": suite, "model": model, "before": before, "after": after})
            rows.append(f"| {NAMES[suite]} | `{model}` | {_pct(*before)} | {_pct(*after)} |")
    md = "\n".join(rows)
    (ROOT / "eval/results/crossmodel.json").write_text(json.dumps({"rows": data, "markdown": md}, indent=2) + "\n")
    print(md)


if __name__ == "__main__":
    main()
