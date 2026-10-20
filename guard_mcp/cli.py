"""guard: the same five operations as the MCP server, from the shell (JSON out).

    guard check-leakage "reply text" --protected promo_code=TRAILHEAD25 --canary CANARY-abc
    guard sanitize "<img src=x onerror=alert(1)>hi" [--mode escape]
    guard authorize REFUND B2001 899 --principal alice@example.com
    guard redeem <token> --principal alice@example.com
    guard score-injection "Ignore all previous instructions"      # GUARD_ADVISOR=deberta
"""

from __future__ import annotations

import argparse
import json

from guard_mcp.advisor_deberta import load_advisor
from guard_mcp.tools import Guard


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="guard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-leakage")
    c.add_argument("text")
    c.add_argument("--protected", action="append", default=[], help="name=value (repeatable)")
    c.add_argument("--canary", action="append", default=[])
    c.add_argument("--reference-prompt")
    s = sub.add_parser("sanitize")
    s.add_argument("text")
    s.add_argument("--mode", default="strip_html", choices=("strip_html", "escape"))
    a = sub.add_parser("authorize")
    a.add_argument("action")
    a.add_argument("params", nargs="+")
    a.add_argument("--principal", required=True)
    a.add_argument("--policy", default="larkspur-demo")
    r = sub.add_parser("redeem")
    r.add_argument("token")
    r.add_argument("--principal", required=True)
    r.add_argument("--policy", default="larkspur-demo")
    i = sub.add_parser("score-injection")
    i.add_argument("text")
    args = p.parse_args(argv)

    guard = Guard(load_advisor())
    if args.cmd == "check-leakage":
        protected = [dict(zip(("name", "value"), x.split("=", 1), strict=True)) for x in args.protected]
        out = guard.check_leakage(args.text, protected, args.canary, args.reference_prompt)
    elif args.cmd == "sanitize":
        out = guard.sanitize_output(args.text, args.mode)
    elif args.cmd == "authorize":
        out = guard.authorize_action(args.action, args.params, args.principal, args.policy)
    elif args.cmd == "redeem":
        out = guard.redeem_grant(args.token, args.principal, args.policy)
    else:
        out = guard.score_injection(args.text)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
