"""POLARYS REST API (Starlette + pydantic).

Authentication: ``Authorization: Bearer plk_<key_id>.<secret>``.  Each API key
belongs to exactly one submitter identity (a user's UPN or a device's FQDN),
which becomes the ``submitter`` of every record sent with it.

Endpoints
---------
POST /v1/records                    submit one record              201 (200 on idempotent replay)
POST /v1/records:batch              submit up to 1,000 records     200, per-item results
GET  /v1/records/{id}               status of a record
GET  /v1/records/{id}/receipt       receipt: 202 until the block is anchored, then 200
GET  /v1/blocks/latest              chain head                     auditor role
GET  /v1/blocks/{id}                block header and token         auditor role
GET  /.well-known/log-keys.json     public keys                    no authentication
GET  /healthz, /readyz
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import __version__
from .config import Settings
from .ingest import IngestError, Ingestor, RecordReader, Submission, request_hash
from .jcs import canonicalize
from .keys import KeyProvider
from .ledger import ApiClient, Ledger
from .manifest import Document
from .records import IdentityError, Submitter
from .store import ObjectStore
from .store.spool import SpoolingStore
from .util import b64e, rfc3339, utcnow

TOKEN_PREFIX = "plk_"
ELEVATED_ATTRIBUTES = {"permanent", "exposure_record"}  # attributes that lengthen retention


# --------------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------------


def new_api_key() -> tuple[str, str, bytes]:
    """(key_id, token to hand to the client once, secret hash to store)."""
    key_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    return key_id, f"{TOKEN_PREFIX}{key_id}.{secret}", hashlib.sha256(secret.encode()).digest()


def parse_token(token: str) -> tuple[str, str] | None:
    if not token.startswith(TOKEN_PREFIX) or "." not in token:
        return None
    key_id, _, secret = token[len(TOKEN_PREFIX) :].partition(".")
    if len(key_id) != 16 or not secret:
        return None
    return key_id, secret


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------


class DocumentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    content_type: str = Field("application/octet-stream", max_length=200)
    data_base64: str

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if "/" in v or "\\" in v or v in (".", ".."):
            raise ValueError("document name must be a plain file name")
        return v


class RecordIn(BaseModel):
    """Exactly one of ``data`` (any JSON value), ``text``, ``payload_base64`` or ``documents``."""

    model_config = ConfigDict(extra="forbid")
    record_class: str | None = Field(None, max_length=64)
    source_type: Literal["api", "windows_event"] = "api"
    data: Any = None
    text: str | None = None
    payload_base64: str | None = None
    content_type: str | None = Field(None, max_length=200)
    documents: list[DocumentIn] | None = Field(None, min_length=1, max_length=100)
    title: str | None = Field(None, max_length=500)
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=32)
    client_origin: dict[str, str] | None = Field(None, max_length=16)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def _one_payload(self):
        given = ["data"] if "data" in self.model_fields_set else []  # data may legitimately be JSON null
        given += [k for k in ("text", "payload_base64", "documents") if getattr(self, k) is not None]
        if len(given) != 1:
            raise ValueError("send exactly one of: data, text, payload_base64, documents")
        return self


class BatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    records: list[dict] = Field(min_length=1)


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------


@dataclass
class Services:
    settings: Settings
    ledger: Ledger
    store: ObjectStore
    provider: KeyProvider
    ingestor: Ingestor
    reader: RecordReader


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None, headers: dict | None = None):
        self.status, self.code, self.message, self.details, self.headers = status, code, message, details, headers or {}


def _error(status: int, code: str, message: str, details: Any = None, headers: dict | None = None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status, headers=headers)


def _pydantic_details(e: ValidationError) -> list[dict]:
    return [{"loc": ".".join(str(x) for x in err["loc"]), "msg": err["msg"]} for err in e.errors(include_url=False, include_input=False)]


class _ClientCache:
    def __init__(self, ledger: Ledger, ttl: float):
        self.ledger, self.ttl = ledger, ttl
        self._c: dict[str, tuple[float, ApiClient | None]] = {}
        self._lock = threading.Lock()

    def get(self, key_id: str) -> ApiClient | None:
        now = time.monotonic()
        with self._lock:
            hit = self._c.get(key_id)
            if hit and hit[0] > now:
                return hit[1]
        client = self.ledger.get_client(key_id)
        with self._lock:
            self._c[key_id] = (now + self.ttl, client)
        return client


def create_app(svc: Services) -> Starlette:
    s = svc.settings
    clients = _ClientCache(svc.ledger, s.client_cache_seconds)
    proxies = [ipaddress.ip_network(c, strict=False) for c in s.trusted_proxies]

    # -- helpers ------------------------------------------------------------------

    def client_ip(request: Request) -> str | None:
        host = request.client.host if request.client else None
        try:
            if host and any(ipaddress.ip_address(host) in n for n in proxies):
                fwd = request.headers.get("x-forwarded-for")
                if fwd:
                    return fwd.split(",")[0].strip()
        except ValueError:
            pass
        return host

    async def authenticate(request: Request) -> ApiClient:
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        parsed = parse_token(token.strip()) if scheme.lower() == "bearer" else None
        if not parsed:
            raise ApiError(401, "unauthenticated", "send Authorization: Bearer plk_<key id>.<secret>", headers={"WWW-Authenticate": "Bearer"})
        key_id, secret = parsed
        client = await run_in_threadpool(clients.get, key_id)
        if client is None or not client.active or not hmac.compare_digest(client.secret_hash, hashlib.sha256(secret.encode()).digest()):
            raise ApiError(401, "unauthenticated", "invalid or revoked API key", headers={"WWW-Authenticate": "Bearer"})
        return client

    async def read_json(request: Request, limit: int):
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ApiError(413, "request_too_large", f"request body exceeds {limit} bytes")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise ApiError(413, "request_too_large", f"request body exceeds {limit} bytes")
            chunks.append(chunk)
        try:
            return json.loads(b"".join(chunks))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "invalid_json", "request body is not valid JSON") from None

    def to_submission(item: dict, client: ApiClient, request: Request, idem_override: str | None) -> Submission:
        try:
            r = RecordIn.model_validate(item)
        except ValidationError as e:
            raise ApiError(422, "invalid_record", "record failed validation", _pydantic_details(e)) from None
        if r.source_type not in client.allowed_sources:
            raise ApiError(403, "source_not_allowed", f"this API key may not submit source_type {r.source_type}")
        if client.allowed_classes is not None and r.source_type == "api" and r.record_class not in client.allowed_classes:
            raise ApiError(403, "class_not_allowed", f"this API key may not submit record class {r.record_class}")
        if ELEVATED_ATTRIBUTES & set(r.attributes) and "records_manager" not in client.roles:
            raise ApiError(403, "attribute_not_allowed", "attributes that extend retention need the records_manager role")
        documents = None
        try:
            if r.documents is not None:
                documents = [Document(d.name, d.content_type, base64.b64decode(d.data_base64, validate=True)) for d in r.documents]
                payload, ctype = None, "application/octet-stream"
            elif "data" in r.model_fields_set:
                payload, ctype = canonicalize(r.data), r.content_type or "application/json"
            elif r.text is not None:
                payload, ctype = r.text.encode("utf-8"), r.content_type or "text/plain; charset=utf-8"
            else:
                payload, ctype = base64.b64decode(r.payload_base64, validate=True), r.content_type or "application/octet-stream"
        except (binascii.Error, ValueError) as e:
            raise ApiError(422, "invalid_record", f"invalid base64 or JSON value: {e}") from None
        try:
            submitter = Submitter(client.submitter_type, client.submitter_id, "api-key", client.display_name)
        except IdentityError as e:
            raise ApiError(500, "bad_client_identity", str(e)) from None
        origin = {"api_key_id": client.key_id}
        ip = client_ip(request)
        if ip:
            origin["ip"] = ip
        ua = request.headers.get("user-agent")
        if ua:
            origin["user_agent"] = ua[:200]
        if r.client_origin:
            origin["client"] = r.client_origin
        return Submission(
            source_type=r.source_type,
            submitter=submitter,
            content_type=ctype,
            payload=payload,
            documents=documents,
            title=r.title,
            record_class=r.record_class,
            attributes=dict(r.attributes),
            origin=origin,
            api_key_id=client.key_id,
            idempotency_key=idem_override or r.idempotency_key,
            request_hash=request_hash(item),
        )

    def can_read(client: ApiClient, row: dict) -> bool:
        if "auditor" in client.roles:
            return True
        return row["submitter_type"] == client.submitter_type and row["submitter_id"] == client.submitter_id

    # -- handlers ----------------------------------------------------------------------

    async def post_record(request: Request) -> Response:
        client = await authenticate(request)
        limit = min(s.max_request_bytes, s.max_submission_bytes * 4 // 3 + 65536)
        item = await read_json(request, limit)
        if not isinstance(item, dict):
            raise ApiError(422, "invalid_record", "body must be a JSON object")
        idem = request.headers.get("idempotency-key")
        if idem is not None and not 0 < len(idem) <= 200:
            raise ApiError(422, "invalid_idempotency_key", "Idempotency-Key must be 1 to 200 characters")
        sub = to_submission(item, client, request, idem)
        out = await run_in_threadpool(svc.ingestor.submit_one, sub)
        if out.error:
            raise ApiError(out.error.status, out.error.code, out.error.message)
        headers = {"Location": f"/v1/records/{out.ack['record_id']}"}
        if out.replayed:
            headers["Idempotent-Replayed"] = "true"
        return JSONResponse(out.ack, status_code=200 if out.replayed else 201, headers=headers)

    async def post_batch(request: Request) -> Response:
        client = await authenticate(request)
        body = await read_json(request, s.max_request_bytes)
        try:
            batch = BatchIn.model_validate(body)
        except ValidationError as e:
            raise ApiError(422, "invalid_batch", "batch failed validation", _pydantic_details(e)) from None
        if len(batch.records) > s.max_batch:
            raise ApiError(413, "batch_too_large", f"at most {s.max_batch} records per batch")
        results: list[dict | None] = [None] * len(batch.records)
        subs, idx = [], []
        for i, item in enumerate(batch.records):
            try:
                subs.append(to_submission(item, client, request, None))
                idx.append(i)
            except ApiError as e:
                results[i] = {"index": i, "status": e.status, "error": {"code": e.code, "message": e.message, **({"details": e.details} if e.details else {})}}
        outs = await run_in_threadpool(svc.ingestor.submit, subs) if subs else []
        for i, out in zip(idx, outs):
            if out.ok:
                results[i] = {"index": i, "status": 200 if out.replayed else 201, "ack": out.ack}
            else:
                results[i] = {"index": i, "status": out.error.status, "error": out.error.to_dict()}
        accepted = sum(1 for r in results if r["status"] in (200, 201))
        return JSONResponse({"accepted": accepted, "rejected": len(results) - accepted, "results": results})

    async def get_record(request: Request) -> Response:
        client = await authenticate(request)
        row = await run_in_threadpool(svc.ledger.get_record, request.path_params["record_id"])
        if row is None or not can_read(client, row):
            raise ApiError(404, "not_found", "no such record")
        body = Ingestor.ack_from_row(row)
        body["block_id"] = row["block_id"]
        body["leaf_index"] = row["leaf_index"]
        body["object_state"] = row["object_state"]
        return JSONResponse(body)

    async def get_receipt(request: Request) -> Response:
        client = await authenticate(request)
        rid = request.path_params["record_id"]
        row = await run_in_threadpool(svc.ledger.get_record, rid)
        if row is None or not can_read(client, row):
            raise ApiError(404, "not_found", "no such record")
        if row["source_type"] not in ("api", "upload"):
            raise ApiError(404, "no_receipt", f"records from {row['source_type']} sources do not get receipts")
        receipt = await run_in_threadpool(svc.ledger.get_receipt, rid)
        if receipt is not None:
            return JSONResponse(receipt)
        return JSONResponse(
            {"record_id": rid, "status": row["status"], "expected_seal_after": Ingestor.ack_from_row(row)["expected_seal_after"]},
            status_code=202,
            headers={"Retry-After": "60"},
        )

    def block_body(b: dict) -> dict:
        return {
            "block_id": b["block_id"],
            "state": b["state"],
            "block_hash": b["block_hash"].hex(),
            "header": b["header"],
            "timestamp": {"tsa": b["tsa_name"], "gen_time": rfc3339(b["gen_time"]) if b["gen_time"] else None,
                          "token": b64e(b["token"]) if b["token"] else None},
        }

    async def get_block(request: Request) -> Response:
        client = await authenticate(request)
        if "auditor" not in client.roles:
            raise ApiError(403, "forbidden", "the auditor role is required")
        ref = request.path_params["block_ref"]
        if ref == "latest":
            b = await run_in_threadpool(svc.ledger.latest_block)
        elif ref.isdigit():
            b = await run_in_threadpool(svc.ledger.get_block, int(ref))
        else:
            b = None
        if b is None:
            raise ApiError(404, "not_found", "no such block")
        return JSONResponse(block_body(b))

    async def well_known_keys(request: Request) -> Response:
        return JSONResponse(svc.provider.keyring().to_document(), headers={"Cache-Control": "public, max-age=300"})

    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__})

    async def readyz(request: Request) -> Response:
        def check():
            out = {"database": "ok", "store": svc.store.name}
            svc.ledger.count_records()
            if isinstance(svc.store, SpoolingStore):
                out["spool_pending"] = len(svc.store.pending())
            return out

        try:
            return JSONResponse({"status": "ready", **await run_in_threadpool(check)})
        except Exception as e:
            return JSONResponse({"status": "unavailable", "error": f"{type(e).__name__}: {e}"}, status_code=503)

    def wrap(handler):
        async def endpoint(request: Request) -> Response:
            try:
                return await handler(request)
            except ApiError as e:
                return _error(e.status, e.code, e.message, e.details, e.headers)
            except IngestError as e:
                return _error(e.status, e.code, e.message)

        return endpoint

    routes = [
        Route("/v1/records", wrap(post_record), methods=["POST"]),
        Route("/v1/records:batch", wrap(post_batch), methods=["POST"]),
        Route("/v1/records/{record_id}", wrap(get_record), methods=["GET"]),
        Route("/v1/records/{record_id}/receipt", wrap(get_receipt), methods=["GET"]),
        Route("/v1/blocks/{block_ref}", wrap(get_block), methods=["GET"]),
        Route("/.well-known/log-keys.json", well_known_keys, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]
    app = Starlette(routes=routes)
    app.state.services = svc
    return app


def build_services(settings: Settings) -> Services:
    """Open the configured ledger, store and keystore (the schema must already exist)."""
    from .db import Database
    from .keys import LocalKeyProvider
    from .store import open_store

    db = Database.open(settings.database_url, settings.db_pool_size)
    ledger = Ledger(db)
    ledger.ensure_open_interval(utcnow())
    store = open_store(settings)
    provider = LocalKeyProvider(settings.keystore_dir, settings.passphrase())
    ingestor = Ingestor(
        ledger, store, provider,
        max_record_bytes=settings.max_record_bytes,
        max_submission_bytes=settings.max_submission_bytes,
        tx_batch=settings.tx_batch,
    )
    return Services(settings, ledger, store, provider, ingestor, RecordReader(ledger, store, provider))


def app_from_env() -> Starlette:
    """ASGI factory for ``uvicorn --factory polarys.api:app_from_env``."""
    return create_app(build_services(Settings()))
