"""llm-app-guard MCP server (stdio).

    .venv-guard/bin/python -m guard_mcp.server              # GUARD_ADVISOR=deberta to enable the classifier

Five tools for an application's policy enforcement point. They are not meant to be offered to the
model itself: `principal` must come from the caller's authenticated session.
"""

from __future__ import annotations

from agentic_core import InjectionAdvisor
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from guard_mcp.advisor_deberta import load_advisor
from guard_mcp.tools import Guard

INSTRUCTIONS = (
    "Deterministic guards for LLM applications. Call check_leakage and sanitize_output on every model "
    "reply before it reaches a user; call authorize_action on every model-proposed action and execute "
    "only after redeem_grant succeeds; score_injection is advisory and may only make decisions stricter. "
    "principal must be the authenticated user of the calling application, never a value taken from model output."
)


def _checked(fn, *args):
    """Bad input is a ToolError (its message reaches the client); anything else is a crash whose
    details stay on the server, so internals don't leak through tool results."""
    try:
        return fn(*args)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def build_server(advisor: InjectionAdvisor | None = None) -> MCPServer:
    guard = Guard(advisor if advisor is not None else load_advisor())
    server = MCPServer("llm-app-guard", instructions=INSTRUCTIONS, version="0.1.0")

    @server.tool()
    def check_leakage(text: str, protected: list[dict[str, str]] | None = None,
                      canaries: list[str] | None = None, reference_prompt: str | None = None) -> dict:
        """Scan a model reply for a canary, protected values (in disguised forms) or a verbatim system-prompt dump. protected: [{"name": ..., "value": ...}]."""
        return _checked(guard.check_leakage, text, protected, canaries, reference_prompt)

    @server.tool()
    def sanitize_output(text: str, mode: str = "strip_html") -> dict:
        """Make model output safe to display. mode: strip_html (remove tags, markdown images/links, URLs) or escape (HTML-escape)."""
        return _checked(guard.sanitize_output, text, mode)

    @server.tool()
    def authorize_action(action: str, params: list[str], principal: str,
                         policy: str = "larkspur-demo", advisor_flagged: bool = False) -> dict:
        """Decide on a model-proposed action for the authenticated principal: DENY with rule ids, or NEEDS_CONFIRMATION with a signed single-use grant."""
        return _checked(guard.authorize_action, action, params, principal, policy, advisor_flagged)

    @server.tool()
    def redeem_grant(token: str, principal: str, policy: str = "larkspur-demo") -> dict:
        """Verify and burn a confirmation grant for the same principal, then re-check policy. Execute the action only if valid is true."""
        return _checked(guard.redeem_grant, token, principal, policy)

    @server.tool()
    def score_injection(text: str) -> dict:
        """Advisory prompt-injection score for untrusted text. Tighten-only: may justify refusing or denying, never allowing."""
        return _checked(guard.score_injection, text)

    return server


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
