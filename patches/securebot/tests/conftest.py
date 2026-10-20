"""Shared fixture: the real SecureBot app with Ollama replaced by a fake that returns chosen replies."""

import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Point this at your patched SecureBot folder:  SECUREBOT_DIR=/path/to/securebot pytest patches/securebot/tests
SECUREBOT = Path(os.environ.get("SECUREBOT_DIR", "securebot")).resolve()
SECRET = os.environ.get("SECUREBOT_SECRET", "")  # the code the original prompt contained
if not (SECUREBOT / "app.py").exists() or not SECRET:
    pytest.skip("set SECUREBOT_DIR (patched SecureBot folder) and SECUREBOT_SECRET", allow_module_level=True)


@pytest.fixture
def bot(monkeypatch, tmp_path):
    monkeypatch.setenv("Q3_PROMO_CODE", SECRET)
    monkeypatch.setenv("GRANT_HMAC_KEY", "ab" * 32)
    monkeypatch.setenv("DECISION_LOG", str(tmp_path / "decisions.jsonl"))
    monkeypatch.chdir(SECUREBOT)
    monkeypatch.syspath_prepend(str(SECUREBOT))
    for mod in ("app", "policy"):  # fresh module state (sessions, refunds) per test
        sys.modules.pop(mod, None)
    app = importlib.import_module("app")
    replies: list[str] = []
    sent: list[list[dict]] = []

    class FakeResponse:
        def __init__(self, text):
            self._text = text

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"role": "assistant", "content": self._text}}

    async def fake_post(self, url, json=None, **kw):
        sent.append(json["messages"])
        return FakeResponse(replies.pop(0))

    monkeypatch.setattr(app.httpx.AsyncClient, "post", fake_post)
    client = TestClient(app.app)

    def say(model_reply: str, message: str = "hi", history: list | None = None, via=None) -> dict:
        replies.append(model_reply)
        return (via or client).post("/api/chat", json={"message": message, "history": history or []}).json()

    def decisions() -> list[dict]:
        path = tmp_path / "decisions.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    say.app, say.policy, say.client, say.sent, say.decisions = app, app.policy, client, sent, decisions
    return say
