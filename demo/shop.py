"""Larkspur Outfitters: the demo shop's data and action policy. All data is SYNTHETIC.

Business facts (prices, return windows, who owns which order) live here as data. In guarded mode the code checks
them; the model never decides them.
"""

from __future__ import annotations

import json
import os
import time
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

from agentic_core import ActionPolicy, ActionProposal, ActionRule, Principal

TODAY = date.today()

PRODUCTS = {  # sku: (name, price, return window in days, warranty)
    "SJ-1": ("Summit Jacket", Decimal("299.00"), 30, "2-year warranty"),
    "RW-2": ("Ridge GPS Watch", Decimal("899.00"), 15, "2-year warranty"),
    "TP-4": ("TrailPack 40L", Decimal("129.00"), 30, "1-year warranty"),
}
CUSTOMERS = {
    "alice@example.com": {"name": "Alice", "loyalty_member": True},
    "bob@example.com": {"name": "Bob", "loyalty_member": False},
}
ORDERS = {
    "A1001": {"owner": "alice@example.com", "sku": "SJ-1", "delivered": TODAY - timedelta(days=10)},
    "A1002": {"owner": "alice@example.com", "sku": "RW-2", "delivered": TODAY - timedelta(days=40)},
    "B2001": {"owner": "bob@example.com", "sku": "RW-2", "delivered": TODAY - timedelta(days=5)},
}
LOYALTY_DISCOUNT_CAP = 10  # percent

REFUNDED: set[str] = set()
DISCOUNTS: dict[str, str] = {}
EVENT_LOG = Path(os.environ.get("EVENT_LOG", "logs/events.jsonl"))


def catalog_text() -> str:
    lines = [f"- {name} ({sku}): ${price}. {days}-day return policy. {warranty}."
             for sku, (name, price, days, warranty) in PRODUCTS.items()]
    return "PRODUCT CATALOG:\n" + "\n".join(lines) + (
        "\nAll returns require original packaging. No refunds after the return window expires.")


def _order(args) -> dict | None:
    return ORDERS.get(args["order_id"].strip().upper())


def _amount(text: str) -> Decimal | None:
    try:
        value = Decimal(text.replace("$", "").replace(",", "").strip())
    except InvalidOperation:
        return None
    return value if value.is_finite() and value > 0 else None


# Validators: each checks one rule and returns its id to deny, or None.
def owns_order(args, principal: Principal):
    order = _order(args)
    if order is None:
        return "unknown_order"
    return None if order["owner"] == principal.id else "not_owner"


def amount_within_price(args, principal: Principal):
    amount = _amount(args["amount"])
    if amount is None:
        return "bad_amount"
    order = _order(args)
    return "amount_exceeds_price" if order and amount > PRODUCTS[order["sku"]][1] else None


def inside_return_window(args, principal: Principal):
    order = _order(args)
    if order is None:
        return None
    return "outside_return_window" if (TODAY - order["delivered"]).days > PRODUCTS[order["sku"]][2] else None


def not_already_refunded(args, principal: Principal):
    return "already_refunded" if args["order_id"].strip().upper() in REFUNDED else None


def own_account(args, principal: Principal):
    return None if args["customer_email"].strip().lower() == principal.id else "not_owner"


def loyalty_member(args, principal: Principal):
    return None if principal.attributes.get("loyalty_member") else "not_loyalty_member"


def discount_within_cap(args, principal: Principal):
    try:
        pct = int(args["percent"].replace("%", "").strip())
    except ValueError:
        return "bad_percent"
    if pct <= 0:
        return "bad_percent"
    return "discount_over_cap" if pct > LOYALTY_DISCOUNT_CAP else None


POLICY = ActionPolicy({
    "REFUND": ActionRule(("order_id", "amount"),
                         (owns_order, amount_within_price, inside_return_window, not_already_refunded)),
    "DISCOUNT": ActionRule(("customer_email", "percent"), (own_account, loyalty_member, discount_within_cap)),
})


def principal_for(email: str) -> Principal:
    return Principal(email, CUSTOMERS.get(email, {}))


def customer_context(principal: Principal) -> str:
    """The signed-in customer's own data, for the model. Never anyone else's."""
    lines = [f"SIGNED-IN CUSTOMER: {principal.id} (loyalty member: "
             f"{'yes' if principal.attributes.get('loyalty_member') else 'no'})", "Their orders:"]
    for oid, order in ORDERS.items():
        if order["owner"] == principal.id:
            name, price, _, _ = PRODUCTS[order["sku"]]
            lines.append(f"- {oid}: {name} ({order['sku']}), ${price}, "
                         f"delivered {(TODAY - order['delivered']).days} days ago")
    return "\n".join(lines)


def execute(proposal: ActionProposal) -> dict:
    """Apply an action (in-memory demo state). Stores what it was given: in vulnerable mode that can be anything,
    including template text like "<percent>" from a dumped prompt, and a naive app would happily act on it."""
    if proposal.action == "REFUND" and proposal.params:
        REFUNDED.add(proposal.params[0].strip().upper())
    elif proposal.action == "DISCOUNT" and len(proposal.params) >= 2:
        DISCOUNTS[proposal.params[0].strip().lower()] = proposal.params[1].strip()
    return {"action": proposal.action, "params": list(proposal.params), "status": "executed"}


def log_event(**fields) -> None:
    """One JSON line per security decision (action decisions AND blocked replies), never the reply text."""
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_LOG.open("a") as f:
        f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}) + "\n")
