"""Measures what static analysis catches in this lab, and what it misses.

Expected result (documented in FINDINGS.md):
- VULN-01 (tool calls without authorization): caught by a heuristic rule.
- VULN-02 (retrieval ignores the tenant): NOT caught. It is a missing filter,
  a business-logic flaw with no dangerous sink to match.
- VULN-03 (model output into SQL): caught by a taint rule.
- Fixed code: no findings.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SEMGREP = shutil.which("semgrep")

pytestmark = pytest.mark.skipif(SEMGREP is None, reason="semgrep is not installed")


def scan(target: str) -> list[str]:
    proc = subprocess.run(
        [SEMGREP, "scan", "--config", "semgrep/", "--json", "--metrics=off", "--quiet", target],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(proc.stdout)["results"]
    return sorted(r["check_id"].rsplit(".", 1)[-1] for r in results)


def test_semgrep_on_vulnerable_agent():
    assert scan("lab/vulnerable") == ["llm-tool-arg-to-sql", "tool-call-without-authorize"]


def test_semgrep_on_fixed_agent_is_clean():
    assert scan("lab/fixed") == []
