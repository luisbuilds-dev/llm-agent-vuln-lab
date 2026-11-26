# llm-agent-vuln-lab

A small, runnable lab for security issues in LLM agents and RAG systems.

It contains an **intentionally vulnerable** billing-support agent, the **fixed** version, **exploit tests** that prove each flaw, **validation tests** that prove each fix without breaking features, and a **Semgrep evaluation** of what static analysis catches and what it misses.

> ⚠️ `lab/vulnerable/` is vulnerable on purpose. Do not reuse it. All data is fake.

## The scenario

Two companies, Acme and Globex, share one support assistant. For each question the agent:

1. retrieves documents (knowledge base articles and customer tickets),
2. sends them to the model with the question,
3. runs the tool calls the model returns: `get_invoice`, `search_invoices`, `issue_refund`.

A customer hides an instruction inside a support ticket. When an Acme support agent asks for a summary of the ticket, the vulnerable assistant refunds $9,800 on a Globex invoice.

## Findings

| ID | Issue | OWASP LLM 2025 | CWE | Semgrep |
|---|---|---|---|---|
| VULN-01 | Model-chosen tool calls run with no authorization (indirect prompt injection → refund on another tenant's invoice) | LLM01, LLM06 | 862 | ✅ heuristic |
| VULN-02 | Retrieval ignores the tenant → confidential document leaks | LLM02, LLM08 | 200 | ❌ missed |
| VULN-03 | Model output formatted into SQL | LLM05 | 89 | ✅ taint |

Every finding has its source → sink path, root cause, fix and tests in **[FINDINGS.md](FINDINGS.md)**, along with the non-findings: things that look suspicious but are not vulnerabilities.

## Run it

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -v
```

The 18 tests run offline in a few seconds. `tests/test_sast.py` is skipped if Semgrep is not installed.

```
tests/test_vulnerable.py   4 exploit tests     pass while the flaw exists
tests/test_fixed.py       12 validation tests  exploits blocked, features intact
tests/test_sast.py         2 SAST tests        what Semgrep finds, and that the fix is clean
```

## Why a scripted model?

Security regression tests have to be deterministic, and real models are not. `lab/llm.py` contains `ScriptedLLM`, which reproduces the one behavior that matters here: **it follows instructions found anywhere in its context, including retrieved documents**, the way real models do under indirect prompt injection.

That is also the point of the fixes. None of them tries to make the model behave. The fixed agent assumes the model is compromised and enforces authorization in code: allowlisted tools, session-based tenant and role checks, limits, and human confirmation before any side effect.

To test a real model, implement `complete(system, user, context)` with the same interface and pass it to `Agent(..., llm=...)`.

## Layout

```
lab/
  auth.py              AuthContext: who is asking (from the session, never from the model)
  data.py              fake tenants, invoices, documents and the poisoned ticket
  llm.py               ScriptedLLM, a deterministic injectable model
  vulnerable/agent.py  VULN-01..03
  fixed/agent.py       FIX-01..03
semgrep/llm-agent.yml  custom taint and authorization rules
tests/                 exploit, validation and SAST tests
FINDINGS.md            full write-up
```

## License

MIT. Author: Luis Cabrera ([@luisbuilds-dev](https://github.com/luisbuilds-dev)).
