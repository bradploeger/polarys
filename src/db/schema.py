"""Ledger schema, version 1, for PostgreSQL and SQLite.

The ledger is the source of truth for which records exist, which interval and
block each belongs to, and where its encrypted object lives.  It never holds
record plaintext; the object store holds only ciphertext.
"""

SCHEMA_VERSION = 1

POSTGRES = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);

CREATE TABLE IF NOT EXISTS intervals (
    interval_id text PRIMARY KEY,
    opened_at   timestamptz NOT NULL,
    state       text NOT NULL CHECK (state IN ('open', 'sealing', 'sealed', 'empty')),
    closed_at   timestamptz,
    block_id    bigint
);
CREATE UNIQUE INDEX IF NOT EXISTS intervals_one_open ON intervals (state) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS data_keys (
    interval_id  text NOT NULL REFERENCES intervals (interval_id),
    record_class text NOT NULL,
    dek_id       text NOT NULL UNIQUE,
    kek_id       text NOT NULL,
    wrapped      bytea NOT NULL,
    created_at   timestamptz NOT NULL,
    destroyed_at timestamptz,
    PRIMARY KEY (interval_id, record_class)
);

CREATE TABLE IF NOT EXISTS api_clients (
    key_id          text PRIMARY KEY,
    secret_hash     bytea NOT NULL,
    submitter_type  text NOT NULL CHECK (submitter_type IN ('device', 'user')),
    submitter_id    text NOT NULL,
    display_name    text,
    auth_method     text NOT NULL,
    allowed_sources jsonb NOT NULL,
    allowed_classes jsonb,
    roles           jsonb NOT NULL,
    webhook_url     text,
    active          boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL,
    revoked_at      timestamptz
);

CREATE TABLE IF NOT EXISTS records (
    ingest_seq      bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    record_id       uuid PRIMARY KEY,
    interval_id     text NOT NULL REFERENCES intervals (interval_id),
    received_at     timestamptz NOT NULL,
    source_type     text NOT NULL,
    submitter_type  text NOT NULL,
    submitter_id    text NOT NULL,
    record_class    text NOT NULL,
    retention_rule  text NOT NULL,
    retain_until    timestamptz,
    legal_hold      boolean NOT NULL DEFAULT false,
    content_type    text NOT NULL,
    payload_sha256  text NOT NULL,
    payload_size    bigint NOT NULL,
    document_count  integer NOT NULL DEFAULT 0,
    signing_key_id  text NOT NULL,
    signature       bytea NOT NULL,
    leaf_hash       bytea NOT NULL UNIQUE,
    object_key      text NOT NULL,
    object_state    text NOT NULL CHECK (object_state IN ('stored', 'spooled')),
    api_key_id      text,
    idempotency_key text,
    request_hash    text,
    status          text NOT NULL DEFAULT 'committed'
                    CHECK (status IN ('committed', 'sealed', 'anchored', 'receipted')),
    block_id        bigint,
    leaf_index      bigint,
    UNIQUE (api_key_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS records_interval ON records (interval_id, ingest_seq);
CREATE INDEX IF NOT EXISTS records_submitter ON records (submitter_id, received_at);
CREATE INDEX IF NOT EXISTS records_spooled ON records (object_state) WHERE object_state = 'spooled';
CREATE INDEX IF NOT EXISTS records_retention ON records (retain_until) WHERE retain_until IS NOT NULL;

CREATE TABLE IF NOT EXISTS blocks (
    block_id    bigint PRIMARY KEY,
    block_uuid  uuid NOT NULL UNIQUE,
    interval_id text NOT NULL REFERENCES intervals (interval_id),
    created_at  timestamptz NOT NULL,
    header      jsonb NOT NULL,
    block_hash  bytea NOT NULL UNIQUE,
    entry_count integer NOT NULL,
    token       bytea,
    tsa_name    text,
    gen_time    timestamptz,
    state       text NOT NULL CHECK (state IN ('sealed', 'anchored'))
);

CREATE TABLE IF NOT EXISTS receipts (
    record_id         uuid PRIMARY KEY REFERENCES records (record_id),
    block_id          bigint NOT NULL REFERENCES blocks (block_id),
    receipt           jsonb NOT NULL,
    created_at        timestamptz NOT NULL,
    delivered_at      timestamptz,
    delivery_attempts integer NOT NULL DEFAULT 0,
    last_error        text
);

CREATE TABLE IF NOT EXISTS index_queue (
    ingest_seq  bigint PRIMARY KEY,
    record_id   uuid NOT NULL,
    enqueued_at timestamptz NOT NULL
);
"""

SQLITE = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intervals (
    interval_id TEXT PRIMARY KEY,
    opened_at   TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('open', 'sealing', 'sealed', 'empty')),
    closed_at   TEXT,
    block_id    INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS intervals_one_open ON intervals (state) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS data_keys (
    interval_id  TEXT NOT NULL REFERENCES intervals (interval_id),
    record_class TEXT NOT NULL,
    dek_id       TEXT NOT NULL UNIQUE,
    kek_id       TEXT NOT NULL,
    wrapped      BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    destroyed_at TEXT,
    PRIMARY KEY (interval_id, record_class)
);

CREATE TABLE IF NOT EXISTS api_clients (
    key_id          TEXT PRIMARY KEY,
    secret_hash     BLOB NOT NULL,
    submitter_type  TEXT NOT NULL CHECK (submitter_type IN ('device', 'user')),
    submitter_id    TEXT NOT NULL,
    display_name    TEXT,
    auth_method     TEXT NOT NULL,
    allowed_sources TEXT NOT NULL,
    allowed_classes TEXT,
    roles           TEXT NOT NULL,
    webhook_url     TEXT,
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS records (
    ingest_seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id       TEXT NOT NULL UNIQUE,
    interval_id     TEXT NOT NULL REFERENCES intervals (interval_id),
    received_at     TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    submitter_type  TEXT NOT NULL,
    submitter_id    TEXT NOT NULL,
    record_class    TEXT NOT NULL,
    retention_rule  TEXT NOT NULL,
    retain_until    TEXT,
    legal_hold      INTEGER NOT NULL DEFAULT 0,
    content_type    TEXT NOT NULL,
    payload_sha256  TEXT NOT NULL,
    payload_size    INTEGER NOT NULL,
    document_count  INTEGER NOT NULL DEFAULT 0,
    signing_key_id  TEXT NOT NULL,
    signature       BLOB NOT NULL,
    leaf_hash       BLOB NOT NULL UNIQUE,
    object_key      TEXT NOT NULL,
    object_state    TEXT NOT NULL CHECK (object_state IN ('stored', 'spooled')),
    api_key_id      TEXT,
    idempotency_key TEXT,
    request_hash    TEXT,
    status          TEXT NOT NULL DEFAULT 'committed'
                    CHECK (status IN ('committed', 'sealed', 'anchored', 'receipted')),
    block_id        INTEGER,
    leaf_index      INTEGER,
    UNIQUE (api_key_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS records_interval ON records (interval_id, ingest_seq);
CREATE INDEX IF NOT EXISTS records_submitter ON records (submitter_id, received_at);

CREATE TABLE IF NOT EXISTS blocks (
    block_id    INTEGER PRIMARY KEY,
    block_uuid  TEXT NOT NULL UNIQUE,
    interval_id TEXT NOT NULL REFERENCES intervals (interval_id),
    created_at  TEXT NOT NULL,
    header      TEXT NOT NULL,
    block_hash  BLOB NOT NULL UNIQUE,
    entry_count INTEGER NOT NULL,
    token       BLOB,
    tsa_name    TEXT,
    gen_time    TEXT,
    state       TEXT NOT NULL CHECK (state IN ('sealed', 'anchored'))
);

CREATE TABLE IF NOT EXISTS receipts (
    record_id         TEXT PRIMARY KEY REFERENCES records (record_id),
    block_id          INTEGER NOT NULL REFERENCES blocks (block_id),
    receipt           TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    delivered_at      TEXT,
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT
);

CREATE TABLE IF NOT EXISTS index_queue (
    ingest_seq  INTEGER PRIMARY KEY,
    record_id   TEXT NOT NULL,
    enqueued_at TEXT NOT NULL
);
"""
