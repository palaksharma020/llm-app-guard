"""DeBERTa prompt-injection advisor (protectai/deberta-v3-base-prompt-injection-v2), tighten-only.

Implements agentic_core.InjectionAdvisor. The model is loaded lazily on first use, from safetensors only
(no pickle), at a pinned revision when GUARD_ADVISOR_REVISION is set. It returns advice: callers may
refuse or deny on `flagged`, never allow.
"""

from __future__ import annotations

import os
from typing import Any

from agentic_core import AdvisorScore

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


class DebertaAdvisor:
    name = "deberta-v3-base-prompt-injection-v2"

    def __init__(self, threshold: float = 0.5, revision: str | None = None) -> None:
        self.threshold = threshold
        self.revision = revision or os.environ.get("GUARD_ADVISOR_REVISION") or None
        self._pipe: Any = None

    def _pipeline(self) -> Any:
        if self._pipe is None:
            from transformers import pipeline  # heavy import, only when the advisor is used

            self._pipe = pipeline(
                "text-classification",
                model=MODEL_ID,
                revision=self.revision,
                truncation=True,
                max_length=512,
                model_kwargs={"use_safetensors": True},
                device="cpu",
            )
        return self._pipe

    def score(self, text: str) -> AdvisorScore:
        result = self._pipeline()(text[:4000])[0]  # {"label": "INJECTION"|"SAFE", "score": p}
        p_injection = result["score"] if result["label"] == "INJECTION" else 1.0 - result["score"]
        return AdvisorScore(round(float(p_injection), 4), p_injection >= self.threshold, self.name)


def load_advisor(name: str | None = None):
    """GUARD_ADVISOR=deberta|none (default none)."""
    from agentic_core import NullAdvisor

    name = (name or os.environ.get("GUARD_ADVISOR", "none")).lower()
    return DebertaAdvisor() if name == "deberta" else NullAdvisor()
