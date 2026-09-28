# POLARYS

**P**ermanent **O**bservability and **L**ogging **A**rchive for **R**ecords and **Y**ielding **S**ystems.

| Phase | Status | Contents |
| --- | --- | --- |
| 1 | done | Core cryptography and formats, `logverify` offline verifier |
| 2 | done | REST API, ingest pipeline, PostgreSQL ledger, local and S3 object stores, `polarys` admin CLI |
| 3 | next | 5-minute sealer service, RFC 3161 anchoring, receipt delivery (webhook and polling) |
| 4 | | Syslog listener, upload page, Windows agent |
| 5 | | OpenSearch indexing and search, roles, retention jobs, re-timestamping, Docker Compose |

## Quick start (development: SQLite ledger, local object store)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                      # add [postgres] for psycopg in production

export POLARYS_KEY_PASSPHRASE='choose a long passphrase'
polarys keys init                     # record key, block key, KEK in ./keystore
polarys init-db                       # ./polarys-ledger.db, first open interval
polarys client add --user controller@contoso.com --name "Controller" --role records_manager
polarys serve                         # http://127.0.0.1:8080
```

```bash
TOKEN=plk_…   # printed once by `client add`
curl -s -X POST http://127.0.0.1:8080/v1/records \
  -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: INV-10442" \
  -d '{"record_class":"sales_invoices","data":{"invoice":"INV-10442","amount":"1250.00"}}'
```

## Production configuration

All settings are environment variables prefixed `POLARYS_` (or a `.env` file).

| Setting | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///polarys-ledger.db` | `postgresql://user:pass@host:5432/polarys?sslmode=require` in production |
| `DB_POOL_SIZE` | 8 | connections per API process |
| `KEYSTORE_DIR` | `keystore` | from `polarys keys init` |
| `KEY_PASSPHRASE` / `KEY_PASSPHRASE_FILE` | none | one is required |
| `STORE` | `local` | `local` or `s3` |
| `LOCAL_STORE_DIR` | `objects` | local store root |
| `SPOOL_DIR` | `spool` | objects are spooled here when the store is unreachable; empty to disable |
| `S3_BUCKET`, `S3_REGION` | none, `us-east-1` | bucket must have Object Lock enabled |
| `S3_ENDPOINT_URL` | none (AWS) | e.g. `http://minio:9000` for MinIO; uses path-style addressing |
| `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_SESSION_TOKEN` | `AWS_*` env vars | static or STS credentials |
| `S3_PREFIX` | empty | key prefix inside the bucket |
| `S3_OBJECT_LOCK` | true | send retention / legal-hold headers |
| `MAX_RECORD_BYTES` | 1 MiB | one log record payload |
| `MAX_SUBMISSION_BYTES` | 50 MiB | all documents of one business submission |
| `MAX_REQUEST_BYTES` | 64 MiB | request body |
| `MAX_BATCH` / `TX_BATCH` | 1000 / 500 | records per batch request / per database transaction |
| `TRUSTED_PROXIES` | none | JSON list of CIDRs whose `X-Forwarded-For` is trusted |
| `CLIENT_CACHE_SECONDS` | 30 | API-key cache; a revoked key stops working within this time |

Run several API processes against one PostgreSQL ledger (`polarys serve --workers 4`, or several containers).
SQLite mode is single-process.

## REST API

Authentication: `Authorization: Bearer plk_<key id>.<secret>`. Each key belongs to one submitter identity,
a user UPN or a device FQDN, which is written into every record it submits. Keys may be limited to record
classes (`--class`) and source types (`--source windows_event` for Windows agents).

| Method | Path | Result |
| --- | --- | --- |
| POST | `/v1/records` | 201 acknowledgement; 200 on an idempotent replay; 409 if the `Idempotency-Key` was used for a different body |
| POST | `/v1/records:batch` | 200 with a result per record (up to 1,000); invalid records do not block the rest |
| GET | `/v1/records/{id}` | status (`committed`, `sealed`, `anchored`, `receipted`), block and leaf index |
| GET | `/v1/records/{id}/receipt` | 202 with `Retry-After` until the record's block is anchored, then 200 with the receipt |
| GET | `/v1/blocks/latest`, `/v1/blocks/{id}` | block header, hash and timestamp token (auditor role) |
| GET | `/.well-known/log-keys.json` | public keys for verification (no authentication) |
| GET | `/healthz`, `/readyz` | liveness; readiness including database and spool status |

A record body carries exactly one of:

| Field | Stored as |
| --- | --- |
| `data` | any JSON value, stored as canonical JSON (`application/json`) |
| `text` | UTF-8 text |
| `payload_base64` | raw bytes, with optional `content_type` |
| `documents` | 1 to 100 files `{name, content_type, data_base64}`: one record whose payload is a signed manifest; each file is encrypted and stored separately |

plus `record_class` (required except for Windows events), optional `title`, `attributes` (for example
`severity`, `security`), `client_origin` and, in batches, a per-record `idempotency_key`.
`attributes.permanent` and `attributes.exposure_record` lengthen retention and need the `records_manager` role.

The acknowledgement contains `record_id`, `leaf_hash`, `signature`, `signing_key_id`, `record_class`,
`retention_rule`, `retain_until`, `interval_id` and `expected_seal_after`, and, for document submissions, the
`manifest`. Errors are `{"error": {"code", "message", "details"?}}`.

## Guarantees

* **An acknowledgement means the record is durable.** It is sent only after the encrypted objects are written
  (or fsynced to the spool) and the ledger row has committed.
* **Every record lands in exactly one interval, and a closed interval never changes.** Ingest transactions
  share-lock the open interval; the sealer's close waits for them and opens the next interval atomically. This
  replaces the 2-second grace period in the original design and is tested with concurrent writers on PostgreSQL.
* **The object store never sees plaintext.** Records are AES-256-GCM encrypted with a data key per interval and
  record class, and each ciphertext is bound to its record id, leaf hash and (for documents) position.
* **Objects are written once.** Local files are created with hard links and made read-only; S3 writes use
  `If-None-Match: *` and Object Lock: COMPLIANCE retention to `retain_until`, or a legal hold for event-based and
  indefinite retention until the triggering event sets a date (Phase 5).
* **Object store outages do not stop ingest.** Transient failures spool objects locally; `polarys spool drain`
  uploads them and marks the records `stored`. Authentication and configuration errors are not spooled, so they
  surface immediately.

## Tests

```bash
cd tests && python -m unittest                  # SQLite and pure-unit tests
POLARYS_TEST_PG_DSN='postgresql://postgres@/postgres?host=/run/postgresql' python -m unittest   # adds PostgreSQL
```

114 tests. With PostgreSQL enabled, every ledger, ingest and API test runs on both SQLite and PostgreSQL 16.
They include the RFC 6962, RFC 8785 and AWS Signature V4 reference vectors; RFC 3161 interop with OpenSSL in both
directions; tamper tests; and concurrent ingest while intervals are closed. They also cover store outage
and drain, rolled-back data keys, idempotency, permissions, and API ingest through to a sealed block and
a receipt verified with `verify_receipt`.

### Load test

`tools/loadtest.py` against one `polarys serve` process on a 2-CPU container, PostgreSQL 16 and the local store:

| Load | Records | Errors | p50 | p99 |
| --- | --- | --- | --- | --- |
| 50 records/s, single-record requests (the spec's peak) | 1,000 | 0 | 6.5 ms | 11.4 ms |
| 150 records/s, single-record requests | 2,250 | 0 | 4.8 ms | 12.4 ms |
| batches of 500 | 5,000 | 0 | 962 ms per batch | 521 records/s sustained |

S3 adds one network round trip per object; expect p99 to be dominated by the S3 PUT latency.

## Offline verification (Phase 1)

```bash
logverify demo demo && cd demo
logverify chain store --keys log-keys.json --tsa-ca dev-tsa-root.pem
logverify receipt store/receipts/<id>.json --keys log-keys.json --tsa-ca dev-tsa-root.pem --document documents/…
logverify tsa-check                       # live request to each of the five public TSAs
```

`logverify receipt` checks the record signature, leaf hash, Merkle inclusion, block hash and sealer signature,
the RFC 3161 token, the receipt signature and, for document submissions, each file against the manifest.

## Implementation notes

* **Starlette instead of FastAPI.** FastAPI could not be installed in the build environment; the API uses
  Starlette and pydantic, which FastAPI is built on. There is no auto-generated OpenAPI page yet.
* **PostgreSQL driver.** psycopg 3 is used when installed (`pip install -e .[postgres]`, recommended). Otherwise
  the built-in `polarys.db.pgwire` client is used; it supports TLS and SCRAM-SHA-256 and is what the test suite
  ran against, because psycopg could not be installed here. Force one with `?driver=psycopg` or `?driver=pgwire`.
* **S3 without boto3.** `polarys.store.s3` signs requests itself (Signature V4, checked against AWS's published
  examples). Instance-profile and SSO credentials are not supported yet; use static keys or STS environment
  variables. It has been tested against a simulated S3 service, not yet against AWS or MinIO.
* **All business record classes accept API submissions.** Phase 1 limited legal, tax, insurance and similar
  classes to web uploads; per-key `--class` limits now control who may submit what.
* Block hash covers the sealer signature; receipts are signed with the block key; device identities must be FQDNs.

See `FORMATS.md` for byte-level formats.
