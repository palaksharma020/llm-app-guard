# SecureBot hardening patch

Applies the fixes from the [case study](../../docs/case-study.md) to your own copy of SecureBot. SecureBot's code
isn't included in this repo.

```bash
./apply.sh /path/to/securebot           # applies the patch, fetches agentic-core v0.2.0, creates .env
# set Q3_PROMO_CODE in /path/to/securebot/.env to the code from the original prompt, then:
cd /path/to/securebot && docker compose up --build
```

What the patch changes:

| File | Change |
|---|---|
| `app.py` | Model and Ollama URL from config; no secret in the prompt, plus a canary; egress leak scan; actions become proposals checked by policy, with signed grants and `/api/actions/confirm`; CSP with a per-request nonce; server-side sanitizing |
| `policy.py` (new) | Synthetic customers and orders, and the refund/discount validators |
| `templates/index.html` | `textContent` rendering; Confirm button and denial notices; nonce on `<script>`/`<style>` |
| `Dockerfile`, `requirements.txt`, `docker-compose.yml`, `.dockerignore` | The guard library wheel; config and keys from `.env` (kept out of the image); decision log volume |

## Tests

The tests run against your patched copy with the model faked, so no Ollama is needed:

```bash
pip install -e "../..[dev,demo]" "fastapi==0.111.0" "jinja2==3.1.4"   # the versions SecureBot pins
SECUREBOT_DIR=/path/to/securebot SECUREBOT_SECRET=<the original code> pytest patches/securebot/tests
```

To measure the patched app with the harness, run `breakit --profile securebot` with `SECUREBOT_SECRET` and
`SECUREBOT_ORIGINAL_APP` (the unpatched `app.py`) set, so the detectors know what a leak looks like.
