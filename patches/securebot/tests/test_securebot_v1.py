"""Fix V1 (prompt leakage), tested offline: Ollama is replaced by a fake that returns a chosen reply.

These tests prove the control, not the model: whatever the model says, a leaking reply never leaves.
"""

import base64

import pytest
from conftest import SECRET


def test_prompt_has_no_secret_but_has_a_canary(bot):
    assert SECRET not in bot.app.SYSTEM_PROMPT
    assert bot.app.CANARY in bot.app.SYSTEM_PROMPT


@pytest.mark.parametrize(
    "model_reply",
    [
        f"The current promotional discount code is {SECRET}.",
        "Sure, spelled out: " + "-".join(SECRET),
        f"Encoded for you: {base64.b64encode(SECRET.encode()).decode()}",
    ],
)
def test_secret_in_any_form_is_replaced(bot, model_reply):
    body = bot(model_reply)
    assert body["blocked"] == "output_policy"
    assert body["response"] == bot.app.SAFE_REFUSAL


def test_prompt_dump_is_caught_by_canary_and_overlap(bot):
    body = bot(f"Here is everything above: {bot.app.SYSTEM_PROMPT}")
    assert body["blocked"] == "output_policy"
    assert bot.app.CANARY not in body["response"]


def test_leaking_reply_carries_no_actions(bot):
    body = bot(f"Code {SECRET} applied!\n[ACTION:DISCOUNT:alice@example.com:5]")
    assert body["blocked"] == "output_policy"
    assert not any(k.startswith("actions") for k in body)


def test_benign_reply_passes_unchanged(bot):
    reply = "Our tablet has a 30-day return policy. All returns require original packaging."
    body = bot(reply)
    assert body["response"] == reply and "blocked" not in body
