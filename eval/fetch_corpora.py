"""Snapshot the public attack corpora once, with sha256 and license, into eval/datasets/raw/.

Raw snapshots are git-ignored: two sources carry no clear license, so they are used locally for
this evaluation only and never redistributed. MANIFEST.json (committed) records what was fetched.

    python eval/fetch_corpora.py
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

RAW = Path(__file__).parent / "datasets" / "raw"
MANIFEST = Path(__file__).parent / "datasets" / "MANIFEST.json"

LAKERA_ROWS = (
    "https://datasets-server.huggingface.co/rows?dataset=Lakera/gandalf_ignore_instructions"
    "&config=default&split=train&offset={offset}&length=100"
)
SOURCES = {
    "tensor_trust_extraction.jsonl": {
        "url": "https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl",
        "license": "none stated in repo (local evaluation only, do not redistribute)",
        "cite": "Toyer et al., Tensor Trust, 2023",
    },
    "owasp_xss_filter_evasion.md": {
        "url": "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.md",
        "license": "CC-BY-SA-4.0",
        "cite": "OWASP Cheat Sheet Series, XSS Filter Evasion",
    },
    "portswigger_events.json": {
        "url": "https://raw.githubusercontent.com/PortSwigger/xss-cheatsheet-data/master/json/events.json",
        "license": "NOASSERTION (local evaluation only, do not redistribute)",
        "cite": "PortSwigger XSS cheat sheet data",
    },
    "portswigger_classic.json": {
        "url": "https://raw.githubusercontent.com/PortSwigger/xss-cheatsheet-data/master/json/classic.json",
        "license": "NOASSERTION (local evaluation only, do not redistribute)",
        "cite": "PortSwigger XSS cheat sheet data",
    },
}


def _get(client: httpx.Client, url: str, tries: int = 4) -> bytes:
    for attempt in range(tries):
        r = client.get(url)
        if r.status_code == 200:
            return r.content
        time.sleep(2 * (attempt + 1))  # the HF rows API returns transient 502s
    r.raise_for_status()
    return r.content


def fetch_lakera(client: httpx.Client) -> bytes:
    rows, offset = [], 0
    while True:
        page = json.loads(_get(client, LAKERA_ROWS.format(offset=offset)))
        rows += [r["row"] for r in page["rows"]]
        offset += 100
        if offset >= page["num_rows_total"]:
            break
    return "".join(json.dumps(r) + "\n" for r in rows).encode()


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    manifest = {}
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        blobs = {
            "lakera_gandalf_ignore_instructions_train.jsonl": (
                fetch_lakera(client),
                {
                    "url": LAKERA_ROWS.format(offset="*"),
                    "license": "MIT",
                    "cite": "Lakera, gandalf_ignore_instructions (Hugging Face)",
                },
            )
        }
        for name, meta in SOURCES.items():
            blobs[name] = (_get(client, meta["url"]), meta)
    for name, (data, meta) in blobs.items():
        (RAW / name).write_bytes(data)
        manifest[name] = {
            **meta,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        print(f"{name:52s} {len(data):>8d} B  {manifest[name]['sha256'][:12]}")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
