"""Intentionally vulnerable billing-support agent. Never deploy this code.

Each flaw is tagged VULN-0x here and explained in FINDINGS.md.
"""

from __future__ import annotations

import re
import sqlite3

from lab.auth import AuthContext
from lab.llm import ScriptedLLM

# VULN-01: this prompt is the only thing standing between the model and the tools.
SYSTEM_PROMPT = (
    "You are a billing support assistant. Only discuss the current tenant's data "
    "and never issue refunds unless a billing admin asks."
)


MIN_SCORE = 2  # shared words needed before a document counts as relevant


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_-]+", text.lower()))


def retrieve(docs: list[dict], question: str, ctx: AuthContext, k: int = 3) -> list[dict]:
    # VULN-02: ranks every document in the store. ctx.tenant is never used, so
    # one tenant's confidential documents reach another tenant's context.
    q = _tokens(question)
    scored = [(len(q & _tokens(d["text"])), d) for d in docs]
    return [d for score, d in sorted(scored, key=lambda s: -s[0]) if score >= MIN_SCORE][:k]


# --- Tools the model can call -------------------------------------------------


def get_invoice(db: sqlite3.Connection, args: dict, ctx: AuthContext):
    # Parameterized, so not SQL injection. But no tenant filter: see VULN-01.
    return db.execute(
        "SELECT id, customer, amount, status FROM invoices WHERE id = ?", (args["invoice_id"],)
    ).fetchone()


def search_invoices(db: sqlite3.Connection, args: dict, ctx: AuthContext):
    query = args["query"]
    # VULN-03: the model's tool argument is formatted straight into SQL.
    sql = (
        "SELECT id, customer, amount, status FROM invoices "
        f"WHERE tenant = '{ctx.tenant}' AND customer LIKE '%{query}%'"
    )
    return db.execute(sql).fetchall()


def issue_refund(db: sqlite3.Connection, args: dict, ctx: AuthContext):
    db.execute(
        "INSERT INTO refunds VALUES (?, ?, ?)", (args["invoice_id"], args["amount"], ctx.user_id)
    )
    db.commit()
    return "refund issued"


TOOLS = {"get_invoice": get_invoice, "search_invoices": search_invoices, "issue_refund": issue_refund}


class Agent:
    def __init__(self, db: sqlite3.Connection, docs: list[dict], llm: ScriptedLLM | None = None):
        self.db = db
        self.docs = docs
        self.llm = llm or ScriptedLLM()

    def ask(self, question: str, ctx: AuthContext) -> dict:
        context = [d["text"] for d in retrieve(self.docs, question, ctx)]
        completion = self.llm.complete(SYSTEM_PROMPT, question, context)
        results = []
        for call in completion.tool_calls:
            # VULN-01: every tool call the model emits runs with the caller's
            # session and no authorization check, including calls planted in
            # retrieved documents.
            results.append((call["name"], TOOLS[call["name"]](self.db, call["args"], ctx)))
        return {"answer": completion.text, "tool_results": results}
