"""A deterministic stand-in for an LLM.

Real models are non-deterministic, which makes security regression tests flaky.
ScriptedLLM reproduces the one behavior these tests depend on: it follows
instructions that appear anywhere in its context window, including retrieved
documents. That is how real models fail under indirect prompt injection.

To test a real model, implement `complete()` with the same signature.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# An instruction to call a tool, wherever it appears in the context.
_CALL = re.compile(r"CALL\s+(\w+)\((\{.*?\})\)")
_SEARCH = re.compile(r"search invoices for (.+)$", re.IGNORECASE)
_REFUND = re.compile(r"refund (INV-\d{4}) (\d+(?:\.\d+)?)", re.IGNORECASE)
_INVOICE = re.compile(r"\b(INV-\d{4})\b")


@dataclass
class Completion:
    text: str
    tool_calls: list[dict] = field(default_factory=list)


class ScriptedLLM:
    def complete(self, system: str, user: str, context: list[str]) -> Completion:
        calls: list[dict] = []

        # Obeys tool-call instructions from the user AND from retrieved text.
        for chunk in [user, *context]:
            for name, raw_args in _CALL.findall(chunk):
                calls.append({"name": name, "args": json.loads(raw_args)})

        if m := _SEARCH.search(user):
            calls.append({"name": "search_invoices", "args": {"query": m.group(1).strip()}})
        elif m := _REFUND.search(user):
            calls.append(
                {"name": "issue_refund", "args": {"invoice_id": m.group(1), "amount": float(m.group(2))}}
            )
        elif m := _INVOICE.search(user):
            calls.append({"name": "get_invoice", "args": {"invoice_id": m.group(1)}})

        if context:
            text = "Relevant documents:\n" + "\n".join(f"- {c}" for c in context)
        else:
            text = "No relevant documents found."
        return Completion(text=text, tool_calls=calls)
