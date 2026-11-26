"""Who is asking. The agent receives this from the authenticated session, never from the model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuthContext:
    user_id: str
    tenant: str
    roles: frozenset[str] = field(default_factory=frozenset)
