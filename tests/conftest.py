import pytest

from lab.auth import AuthContext
from lab.data import make_db

ACME_SUPPORT = AuthContext(user_id="ana", tenant="acme", roles=frozenset({"support"}))
ACME_ADMIN = AuthContext(user_id="bo", tenant="acme", roles=frozenset({"billing_admin"}))


@pytest.fixture
def db():
    conn = make_db()
    yield conn
    conn.close()


def refunds(db):
    return db.execute("SELECT invoice_id, amount, requested_by FROM refunds").fetchall()
