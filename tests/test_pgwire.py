import unittest
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal

from polarys.db import pgwire
from polarys.db.pgwire import _convert_placeholders, parse_dsn

from backends import PG_DSN


class PlaceholderTests(unittest.TestCase):
    def test_conversion(self):
        self.assertEqual(_convert_placeholders("a = %s AND b = %s"), "a = $1 AND b = $2")
        self.assertEqual(_convert_placeholders("LIKE '10%%' OR x = %s"), "LIKE '10%' OR x = $1")

    def test_dsn(self):
        p = parse_dsn("postgresql://u:p%40ss@db.example.com:6543/ledger?sslmode=require")
        self.assertEqual((p["host"], p["port"], p["user"], p["password"], p["dbname"], p["sslmode"]),
                         ("db.example.com", 6543, "u", "p@ss", "ledger", "require"))
        self.assertEqual(parse_dsn("postgresql://u@/db?host=/run/postgresql")["sslmode"], "disable")


@unittest.skipUnless(PG_DSN, "POLARYS_TEST_PG_DSN not set")
class LiveTests(unittest.TestCase):
    def setUp(self):
        self.c = pgwire.connect(PG_DSN)

    def tearDown(self):
        self.c.close()

    def test_types_roundtrip(self):
        now = datetime(2026, 9, 27, 4, 0, 0, 123456, tzinfo=timezone.utc)
        u = uuid.uuid4()
        row = self.c.execute(
            "SELECT %s::bigint, %s::bytea, %s::timestamptz, %s::jsonb, %s::uuid, %s::bool, %s::text, %s::numeric, %s::date, %s::float8, NULL",
            (2**62, b"\x00\xffabc", now, {"a": [1, "é"]}, u, False, "it's ☃", Decimal("1.50"), date(2026, 1, 2), 0.25),
        ).fetchall()[0]
        self.assertEqual(row, (2**62, b"\x00\xffabc", now, {"a": [1, "é"]}, u, False, "it's ☃", Decimal("1.50"), date(2026, 1, 2), 0.25, None))

    def test_transactions_and_errors(self):
        self.c.execute("CREATE TEMP TABLE t (x int PRIMARY KEY)")
        self.c.execute("INSERT INTO t VALUES (%s)", (1,))
        self.c.commit()
        with self.assertRaises(pgwire.Error) as cm:
            self.c.execute("INSERT INTO t VALUES (%s)", (1,))
        self.assertEqual(cm.exception.sqlstate, "23505")
        self.c.rollback()
        cur = self.c.execute("UPDATE t SET x = x + 1")
        self.assertEqual(cur.rowcount, 1)
        self.c.rollback()
        self.assertEqual(self.c.execute("SELECT x FROM t").fetchall(), [(1,)])

    def test_password_auth_scram(self):
        self.c.autocommit = True
        self.c.execute("DROP ROLE IF EXISTS polarys_scram_test")
        self.c.execute("SET password_encryption = 'scram-sha-256'")
        self.c.execute("CREATE ROLE polarys_scram_test LOGIN PASSWORD 's3cret pw'")
        try:
            port = parse_dsn(PG_DSN)["port"]
            tcp = f"postgresql://polarys_scram_test:s3cret%20pw@127.0.0.1:{port}/postgres"
            try:
                c2 = pgwire.connect(tcp)
            except (ConnectionRefusedError, OSError):
                self.skipTest("server does not listen on 127.0.0.1")
            self.assertEqual(c2.execute("SELECT current_user").fetchall(), [("polarys_scram_test",)])
            c2.close()
            with self.assertRaises(pgwire.Error) as cm:
                pgwire.connect(tcp.replace("s3cret%20pw", "wrong"))
            self.assertEqual(cm.exception.sqlstate, "28P01")
        finally:
            self.c.execute("DROP ROLE IF EXISTS polarys_scram_test")


if __name__ == "__main__":
    unittest.main()
