"""A minimal, synchronous PostgreSQL wire-protocol (v3) client.

Production deployments should install ``psycopg`` (``pip install polarys[postgres]``);
it is used automatically when importable.  This module exists so POLARYS can
talk to PostgreSQL with no compiled dependencies, and so the ledger SQL is
tested against a real server where psycopg is unavailable.

Supported: TCP and Unix sockets, TLS (``sslmode=require``), trust / cleartext /
MD5 / SCRAM-SHA-256 authentication, the extended query protocol with text
parameters, and conversion of common result types to the same Python types
psycopg 3 returns (int, bool, bytes, Decimal, float, datetime, date, UUID,
parsed JSON, str).  Not supported: COPY, LISTEN/NOTIFY, binary formats,
arrays, cancellation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import uuid
from datetime import date, datetime
from decimal import Decimal
from urllib.parse import parse_qs, unquote, urlparse


class Error(Exception):
    """Server-reported error; ``fields`` holds the ErrorResponse fields (``C`` = SQLSTATE)."""

    def __init__(self, fields: dict[str, str]):
        self.fields = fields
        self.sqlstate = fields.get("C")
        super().__init__(f"{fields.get('S', 'ERROR')}: {fields.get('M', 'unknown error')} (SQLSTATE {self.sqlstate})")


class InterfaceError(Exception):
    pass


def parse_dsn(dsn: str) -> dict:
    """``postgresql://user:pass@host:port/db?sslmode=require&host=/run/postgresql``."""
    u = urlparse(dsn)
    if u.scheme not in ("postgres", "postgresql"):
        raise InterfaceError("DSN must start with postgresql://")
    q = {k: v[-1] for k, v in parse_qs(u.query).items()}
    host = q.get("host") or (unquote(u.hostname) if u.hostname else "/var/run/postgresql")
    return {
        "host": host,
        "port": u.port or int(q.get("port", 5432)),
        "user": unquote(u.username or q.get("user", "postgres")),
        "password": unquote(u.password) if u.password else q.get("password"),
        "dbname": (u.path or "/").lstrip("/") or q.get("dbname", "postgres"),
        "sslmode": q.get("sslmode", "prefer" if not host.startswith("/") else "disable"),
        "application_name": q.get("application_name", "polarys"),
    }


def _convert_placeholders(sql: str) -> str:
    """``%s`` -> ``$1, $2, ...`` and ``%%`` -> ``%``, exactly as psycopg treats them (quotes are not special)."""
    out, n, i = [], 0, 0
    while i < len(sql):
        c = sql[i]
        if c == "%" and i + 1 < len(sql) and sql[i + 1] in "s%":
            if sql[i + 1] == "s":
                n += 1
                out.append(f"${n}")
            else:
                out.append("%")
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _encode_param(v) -> bytes | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return b"true" if v else b"false"
    if isinstance(v, (bytes, bytearray, memoryview)):
        return b"\\x" + bytes(v).hex().encode()
    if isinstance(v, datetime):
        if v.tzinfo is None:
            raise InterfaceError("naive datetimes are not accepted")
        return v.isoformat().encode()
    if isinstance(v, (date, uuid.UUID, Decimal, int, float)):
        return str(v).encode()
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":")).encode()
    if isinstance(v, str):
        return v.encode()
    raise InterfaceError(f"cannot send parameters of type {type(v).__name__}")


def _decode(oid: int, raw: bytes | None):
    if raw is None:
        return None
    s = raw.decode()
    if oid in (20, 21, 23, 26):
        return int(s)
    if oid == 16:
        return s == "t"
    if oid == 17:
        return bytes.fromhex(s[2:]) if s.startswith("\\x") else raw
    if oid == 1700:
        return Decimal(s)
    if oid in (700, 701):
        return float(s)
    if oid in (1114, 1184):
        return datetime.fromisoformat(s)
    if oid == 1082:
        return date.fromisoformat(s)
    if oid == 2950:
        return uuid.UUID(s)
    if oid in (114, 3802):
        return json.loads(s)
    return s


class Cursor:
    def __init__(self, rows, description, rowcount):
        self._rows = rows
        self.description = description
        self.rowcount = rowcount

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class Connection:
    """One server connection. Starts transactions implicitly, like psycopg's default."""

    def __init__(self, dsn: str, connect_timeout: float = 10.0):
        p = parse_dsn(dsn)
        self._params = p
        if p["host"].startswith("/"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout)
            sock.connect(os.path.join(p["host"], f".s.PGSQL.{p['port']}"))
        else:
            sock = socket.create_connection((p["host"], p["port"]), timeout=connect_timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if p["sslmode"] in ("prefer", "require", "verify-ca", "verify-full"):
                sock.sendall(struct.pack("!ii", 8, 80877103))
                if sock.recv(1) == b"S":
                    ctx = ssl.create_default_context()
                    if p["sslmode"] in ("prefer", "require"):
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    elif p["sslmode"] == "verify-ca":
                        ctx.check_hostname = False
                    sock = ctx.wrap_socket(sock, server_hostname=p["host"])
                elif p["sslmode"] != "prefer":
                    raise InterfaceError("server does not support TLS")
        sock.settimeout(None)
        self._sock = sock
        self._buf = b""
        self.closed = False
        self.status = b"I"
        self.autocommit = False
        self._startup()

    # -- framing ------------------------------------------------------------------

    def _send(self, typ: bytes, body: bytes = b"") -> None:
        self._sock.sendall(typ + struct.pack("!i", len(body) + 4) + body)

    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(65536, n - len(self._buf)))
            if not chunk:
                self.closed = True
                raise InterfaceError("server closed the connection")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _recv(self) -> tuple[bytes, bytes]:
        head = self._read_exact(5)
        typ, ln = head[:1], struct.unpack("!i", head[1:])[0]
        return typ, self._read_exact(ln - 4)

    @staticmethod
    def _fields(body: bytes) -> dict[str, str]:
        out = {}
        for part in body.split(b"\x00"):
            if part:
                out[chr(part[0])] = part[1:].decode("utf-8", "replace")
        return out

    # -- startup and authentication -----------------------------------------------

    def _startup(self) -> None:
        p = self._params
        kv = {"user": p["user"], "database": p["dbname"], "application_name": p["application_name"],
              "client_encoding": "UTF8", "TimeZone": "UTC", "DateStyle": "ISO"}
        body = struct.pack("!i", 196608) + b"".join(k.encode() + b"\x00" + v.encode() + b"\x00" for k, v in kv.items()) + b"\x00"
        self._sock.sendall(struct.pack("!i", len(body) + 4) + body)
        scram = None
        while True:
            typ, body = self._recv()
            if typ == b"R":
                code = struct.unpack("!i", body[:4])[0]
                if code == 0:
                    continue
                pw = p["password"]
                if code in (3, 5, 10) and pw is None:
                    raise InterfaceError("server requires a password")
                if code == 3:
                    self._send(b"p", pw.encode() + b"\x00")
                elif code == 5:
                    inner = hashlib.md5(pw.encode() + p["user"].encode()).hexdigest()
                    outer = hashlib.md5(inner.encode() + body[4:8]).hexdigest()
                    self._send(b"p", b"md5" + outer.encode() + b"\x00")
                elif code == 10:
                    if b"SCRAM-SHA-256" not in body[4:].split(b"\x00"):
                        raise InterfaceError("server offers no supported SASL mechanism")
                    scram = _Scram(pw)
                    first = scram.client_first()
                    self._send(b"p", b"SCRAM-SHA-256\x00" + struct.pack("!i", len(first)) + first)
                elif code == 11:
                    self._send(b"p", scram.client_final(body[4:]))
                elif code == 12:
                    scram.verify_server(body[4:])
                else:
                    raise InterfaceError(f"unsupported authentication method {code}")
            elif typ == b"E":
                raise Error(self._fields(body))
            elif typ == b"Z":
                self.status = body[:1]
                return
            # ParameterStatus (S), BackendKeyData (K), NoticeResponse (N) are ignored

    # -- queries ------------------------------------------------------------------

    def execute(self, sql: str, params: tuple | list = ()) -> Cursor:
        if self.closed:
            raise InterfaceError("connection is closed")
        if not self.autocommit and self.status == b"I":
            self._simple("BEGIN")
        enc = [_encode_param(v) for v in params]
        bind = b"\x00\x00" + struct.pack("!hh", 0, len(enc))
        for e in enc:
            bind += struct.pack("!i", -1) if e is None else struct.pack("!i", len(e)) + e
        bind += struct.pack("!h", 0)
        q = _convert_placeholders(sql).encode()
        msgs = [
            (b"P", b"\x00" + q + b"\x00" + struct.pack("!h", 0)),
            (b"B", bind),
            (b"D", b"P\x00"),
            (b"E", b"\x00" + struct.pack("!i", 0)),
            (b"S", b""),
        ]
        self._sock.sendall(b"".join(t + struct.pack("!i", len(b) + 4) + b for t, b in msgs))
        rows, desc, oids, rowcount, error = [], None, [], -1, None
        while True:
            typ, body = self._recv()
            if typ == b"T":
                n = struct.unpack("!h", body[:2])[0]
                off, desc, oids = 2, [], []
                for _ in range(n):
                    end = body.index(b"\x00", off)
                    name = body[off:end].decode()
                    off = end + 1
                    _tbl, _col, oid, _sz, _mod, _fmt = struct.unpack("!ihihih", body[off : off + 18])
                    off += 18
                    desc.append((name, oid))
                    oids.append(oid)
            elif typ == b"D":
                n = struct.unpack("!h", body[:2])[0]
                off, row = 2, []
                for i in range(n):
                    ln = struct.unpack("!i", body[off : off + 4])[0]
                    off += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(_decode(oids[i], body[off : off + ln]))
                        off += ln
                rows.append(tuple(row))
            elif typ == b"C":
                tag = body.rstrip(b"\x00").split()
                if tag and tag[-1].isdigit():
                    rowcount = int(tag[-1])
            elif typ == b"E":
                error = Error(self._fields(body))
            elif typ == b"Z":
                self.status = body[:1]
                break
        if error:
            raise error
        return Cursor(rows, desc, rowcount)

    def _simple(self, sql: str) -> None:
        self._send(b"Q", sql.encode() + b"\x00")
        error = None
        while True:
            typ, body = self._recv()
            if typ == b"E":
                error = Error(self._fields(body))
            elif typ == b"Z":
                self.status = body[:1]
                break
        if error:
            raise error

    def commit(self) -> None:
        if self.status != b"I":
            self._simple("COMMIT")

    def rollback(self) -> None:
        if self.status != b"I":
            self._simple("ROLLBACK")

    def close(self) -> None:
        if not self.closed:
            try:
                self._send(b"X")
            except OSError:
                pass
            self._sock.close()
            self.closed = True


def connect(dsn: str, **kw) -> Connection:
    return Connection(dsn, **kw)


class _Scram:
    """RFC 5802 / RFC 7677 SCRAM-SHA-256 without channel binding."""

    def __init__(self, password: str):
        self.password = password.encode()
        self.nonce = base64.b64encode(os.urandom(18)).decode()
        self.first_bare = f"n=,r={self.nonce}"

    def client_first(self) -> bytes:
        return ("n,," + self.first_bare).encode()

    def client_final(self, server_first: bytes) -> bytes:
        attrs = dict(kv.split("=", 1) for kv in server_first.decode().split(","))
        if not attrs["r"].startswith(self.nonce):
            raise InterfaceError("SCRAM server nonce does not extend the client nonce")
        salted = hashlib.pbkdf2_hmac("sha256", self.password, base64.b64decode(attrs["s"]), int(attrs["i"]))
        client_key = hmac.new(salted, b"Client Key", "sha256").digest()
        stored_key = hashlib.sha256(client_key).digest()
        without_proof = f"c=biws,r={attrs['r']}"
        auth_msg = f"{self.first_bare},{server_first.decode()},{without_proof}".encode()
        sig = hmac.new(stored_key, auth_msg, "sha256").digest()
        proof = bytes(a ^ b for a, b in zip(client_key, sig))
        server_key = hmac.new(salted, b"Server Key", "sha256").digest()
        self.expected_server_sig = hmac.new(server_key, auth_msg, "sha256").digest()
        return f"{without_proof},p={base64.b64encode(proof).decode()}".encode()

    def verify_server(self, server_final: bytes) -> None:
        attrs = dict(kv.split("=", 1) for kv in server_final.decode().split(","))
        if not hmac.compare_digest(base64.b64decode(attrs.get("v", "")), self.expected_server_sig):
            raise InterfaceError("SCRAM server signature is invalid")
