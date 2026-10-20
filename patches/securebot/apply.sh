#!/usr/bin/env bash
# Apply the hardening patch to your own copy of SecureBot and fetch the guard library it needs.
#   ./apply.sh /path/to/securebot
set -euo pipefail
SB="${1:?usage: ./apply.sh /path/to/securebot}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$SB"
test -f app.py && test -f templates/index.html || { echo "not a SecureBot folder: $SB" >&2; exit 1; }
# Inside a git repo, git apply resolves paths from the repo root, so tell it where this folder is.
PREFIX="$(git rev-parse --show-prefix 2>/dev/null || true)"
git apply -p2 ${PREFIX:+--directory="$PREFIX"} --check "$HERE/securebot-hardening.patch"
git apply -p2 ${PREFIX:+--directory="$PREFIX"} "$HERE/securebot-hardening.patch"
grep -q "scan_for_leaks" app.py || { echo "patch did not apply to $SB" >&2; exit 1; }
mkdir -p vendor
python3 -m pip wheel --quiet --no-deps -w vendor "agentic-core @ git+https://github.com/palaksharma020/agentic-core@v0.2.0"
[ -f .env ] || { cp "$HERE/.env.example" .env; echo "GRANT_HMAC_KEY=$(openssl rand -hex 32)" >> .env; }
echo "Patched. Set Q3_PROMO_CODE in $SB/.env, then: docker compose up --build"
