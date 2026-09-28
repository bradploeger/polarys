# POLARYS formats (version 1)

Conventions: hashes are lowercase hex; signatures, keys, tokens and payloads are standard padded base64; times
are UTC RFC 3339 with microseconds (`2026-09-26T19:40:00.000000Z`); JSON that is signed or hashed is
canonicalized with RFC 8785 (JCS). `||` is byte concatenation.

## Keys

| Key | Algorithm | Identifier |
| --- | --- | --- |
| record | Ed25519 | `ed25519:` + hex(SHA-256(raw public key)[0:16]) |
| block (also signs receipts) | Ed25519 | same form |
| KEK | AES-256, RFC 3394 key wrap | `kek:` + 16 random bytes hex |
| DEK | AES-256-GCM | `<interval_id>/<record_class>`, e.g. `20260926T1935Z/payroll` |

Public keys are published as `log-keys.json`:

```json
{"version": 1, "keys": [{"key_id": "ed25519:…", "alg": "Ed25519", "use": "record|block",
  "public_key": "<base64 raw 32 bytes>", "status": "active|retired", "created": "…"}]}
```

## Record envelope

```json
{
  "version": 1,
  "record_id": "<UUIDv7>",
  "received_at": "<RFC 3339>",
  "source_type": "syslog | windows_event | upload | api | audit | retention_event",
  "submitter": {"type": "device|user", "id": "<FQDN or UPN, lower case>", "auth_method": "…", "display_name": "…"},
  "origin": {"…": "source IP, host, agent id, file name, line number"},
  "record_class": "<class id>",
  "retention_rule": "P90D | P7Y | event:<name>+P<n>Y | indefinite",
  "retain_until": "<RFC 3339> | null",
  "content_type": "text/syslog | application/json | application/vnd.polarys.manifest+json | …",
  "payload_sha256": "<hex>",
  "payload": "<base64>",
  "attributes": {"severity": 5, "security": true},
  "signing_key_id": "ed25519:…"
}
```

```
canonical = JCS(envelope)                     (includes signing_key_id)
signature = Ed25519-sign(record key, canonical)
leaf_hash = SHA-256(0x00 || canonical || signature)
```

Signed record: `{"envelope": …, "signature": "<base64>", "key_id": "<same as signing_key_id>"}`.

## Business-document manifest (payload when `content_type` is `application/vnd.polarys.manifest+json`)

```json
{"version": 1, "title": "…", "category": "<record class>", "document_count": 3,
 "documents": [{"index": 0, "name": "…", "content_type": "…", "size": 1234, "sha256": "<hex>"}],
 "submission_sha256": "SHA-256(raw sha256 of document 0 || document 1 || …)"}
```

## Stored record object (`records/<yyyy>/<mm>/<dd>/<interval_id>/<record_id>.bin`)

```json
{"v": 1, "alg": "A256GCM", "dek_id": "<interval_id>/<class>", "nonce": "<base64 12 bytes>",
 "ciphertext": "<base64>", "record_id": "…", "leaf_hash": "<hex>", "block_id": 7}
```

Plaintext is `JCS(signed record)`. Additional authenticated data is `UTF-8(record_id) || leaf_hash (32 bytes)`.
Wrapped DEKs live at `keys/dek/<interval_id>/<class>.json` as `{"dek_id", "kek_id", "wrapped"}`.

## Merkle tree

RFC 6962: `leaf = SHA-256(0x00 || data)`, `node = SHA-256(0x01 || left || right)`, split at the largest power of
two below n. Inclusion proofs are `{"leaf_index", "tree_size", "audit_path": [hex, …]}` (bottom-up) and are
verified with the RFC 9162 section 2.1.3.2 algorithm; `tree_size` must also equal the block's `entry_count`.

`trees/<block_id>.bin`: `"PLMT" 0x01 || uint64 big-endian leaf count || every level's hashes, leaves first`.

## Block header (`blocks/<block_id>.json`)

```json
{
  "version": 1,
  "block_id": 0,
  "block_uuid": "<UUIDv7>",
  "created_at": "<RFC 3339>",
  "interval": {"start": "…", "end": "…"},
  "prev_block_hash": "<hex; 64 zeros for genesis>",
  "prev_timestamp_token": "<base64 DER token of block N-1; null for genesis>",
  "merkle_root": "<hex>",
  "entry_count": 15000,
  "submitters": [{"type": "device|user", "id": "…", "display_name": "…", "record_count": 12, "first_seq": 0, "last_seq": 40}],
  "hash_alg": "sha256",
  "signing_key_id": "ed25519:…",
  "sealer_signature": "<base64>"
}
```

```
sealer_signature = Ed25519-sign(block key, JCS(header without sealer_signature))
block_hash       = SHA-256(JCS(header))     (with sealer_signature)
```

`tokens/<block_id>.tsr` holds the DER RFC 3161 token (CMS ContentInfo) whose SHA-256 message imprint is
`block_hash`.

Chain rules: block ids are consecutive from 0; `prev_block_hash` is the previous block's hash;
`prev_timestamp_token` is the previous block's token byte for byte; each token's genTime is later than the
previous one and within 5 minutes of `created_at`; intervals do not overlap; `entry_count` equals the sum of
`submitters[].record_count` and the stored tree's leaf count.

## Receipt (`receipts/<record_id>.json`, upload and API submitters only)

```json
{
  "version": 1,
  "issued_at": "…",
  "record_id": "…",
  "signed_record": {"envelope": {}, "signature": "…", "key_id": "…"},
  "leaf_hash": "<hex>",
  "inclusion_proof": {"leaf_index": 3, "tree_size": 15000, "audit_path": ["…"]},
  "block_header": {},
  "block_hash": "<hex>",
  "timestamp": {"tsa": "Sectigo", "token": "<base64 DER>"},
  "server_keys": [{"key_id": "…", "alg": "Ed25519", "use": "record"}, {"use": "block"}],
  "receipt_key_id": "ed25519:…",
  "receipt_signature": "<base64 Ed25519 over JCS(receipt without receipt_signature)>"
}
```

## RFC 3161 usage

Requests: version 1, SHA-256 imprint of `block_hash`, random 63-bit nonce, `certReq = true`, no policy.
Accepted tokens: CMS SignedData over TSTInfo; RSA PKCS#1 v1.5, RSA-PSS, ECDSA or Ed25519 signatures; ESS
signing-certificate v1 or v2 attribute; signer certificate with the timeStamping EKU, valid at genTime.
Trust-root chain building checks signatures, `basicConstraints` and validity at genTime; revocation is not
checked in v1.
