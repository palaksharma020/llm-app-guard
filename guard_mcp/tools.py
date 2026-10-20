"""The five guard operations as plain functions. The MCP server and the CLI are thin wrappers.

Callers are application code (the policy enforcement point), not the model: `principal` must come from
the caller's authenticated session. Exposing these tools to an LLM would let it claim any identity.
"""

from __future__ import annotations

import html
import importlib.util
import os
import secrets
import sys
from functools import cache
from pathlib import Path
from typing import Any

from agentic_core import (
    ActionProposal,
    AuthzDecision,
    GrantIssuer,
    InjectionAdvisor,
    NullAdvisor,
    ProtectedValue,
    authorize,
    sanitize_llm_text,
    scan_for_leaks,
)

ROOT = Path(__file__).resolve().parent.parent
POLICY_MODULES = {"larkspur-demo": ROOT / "demo" / "shop.py"}  # policy id → module with POLICY and principal_for


@cache
def _policy_module(policy_id: str) -> Any:
    path = POLICY_MODULES.get(policy_id)
    if path is None:
        raise ValueError(f"unknown policy {policy_id!r}; known: {sorted(POLICY_MODULES)}")
    spec = importlib.util.spec_from_file_location(f"policy_{policy_id.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[spec.name] = module  # type: ignore[union-attr]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _issuer() -> GrantIssuer:
    key = os.environ.get("GUARD_GRANT_KEY", "")
    return GrantIssuer(bytes.fromhex(key) if len(key) >= 64 else secrets.token_bytes(32), ttl_seconds=300)


class Guard:
    def __init__(self, advisor: InjectionAdvisor | None = None) -> None:
        self.advisor = advisor or NullAdvisor()
        self.grants = _issuer()

    def check_leakage(self, text: str, protected: list[dict[str, str]] | None = None,
                      canaries: list[str] | None = None, reference_prompt: str | None = None) -> dict:
        """Scan a model reply for a canary, protected values in disguise, or a verbatim prompt dump."""
        result = scan_for_leaks(
            text,
            protected=[ProtectedValue(p["name"], p["value"]) for p in protected or []],
            canaries=canaries or [],
            reference_prompt=reference_prompt,
        )
        return {"leaked": result.leaked, "prompt_overlap": result.prompt_overlap,
                "findings": [{"rule": f.rule, "name": f.name, "form": f.form} for f in result.findings]}

    def sanitize_output(self, text: str, mode: str = "strip_html") -> dict:
        """Make model output safe to show: strip markup/links/URLs, or HTML-escape everything."""
        if mode not in {"strip_html", "escape"}:
            raise ValueError("mode must be 'strip_html' or 'escape'")
        out = sanitize_llm_text(text) if mode == "strip_html" else html.escape(text)
        return {"text": out, "changed": out != text}

    def authorize_action(self, action: str, params: list[str], principal: str,
                         policy: str = "larkspur-demo", advisor_flagged: bool = False) -> dict:
        """Decide on a model-proposed action for an authenticated principal; allowed → signed grant."""
        module = _policy_module(policy)
        who = module.principal_for(principal)
        proposal = ActionProposal(action.upper(), tuple(params))
        result = authorize(proposal, who, module.POLICY, advisor_flagged=advisor_flagged)
        out: dict[str, Any] = {"decision": result.decision.value, "reasons": list(result.reasons)}
        if result.decision is AuthzDecision.NEEDS_CONFIRMATION:
            grant = self.grants.issue(who, proposal)
            out["grant"] = {"token": grant.token, "grant_id": grant.grant_id, "expires_at": int(grant.expires_at)}
        return out

    def redeem_grant(self, token: str, principal: str, policy: str = "larkspur-demo") -> dict:
        """Verify and burn a grant (single use), then re-authorize: the only path to execution."""
        module = _policy_module(policy)
        who = module.principal_for(principal)
        check = self.grants.redeem(token, who)
        if not check.valid:
            return {"valid": False, "reason": check.reason}
        recheck = authorize(check.proposal, who, module.POLICY)  # state may have changed
        if recheck.decision is AuthzDecision.DENY:
            return {"valid": False, "reason": ",".join(recheck.reasons)}
        return {"valid": True, "reason": "ok", "action": check.proposal.action,
                "params": list(check.proposal.params), "grant_id": check.grant_id}

    def score_injection(self, text: str) -> dict:
        """Advisory prompt-injection score for untrusted text. Tighten-only: never use it to allow."""
        s = self.advisor.score(text)
        return {"score": s.score, "flagged": s.flagged, "advisor": s.advisor,
                "threshold": getattr(self.advisor, "threshold", None)}
