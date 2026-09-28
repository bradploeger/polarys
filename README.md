# POLARYS — Phase 1 core library

**P**ermanent **O**bservability and **L**ogging **A**rchive for **R**ecords and **Y**ielding **S**ystems.

Phase 1 is the cryptographic core that every later component (ingest API, syslog listener, sealer, receipt
service) is built on, plus `logverify`, the offline verifier that auditors and submitters use to check
evidence without trusting the operator.

## What is in this phase

| Module | Purpose |
| --- | --- |
| `jcs` | RFC 8785 JSON canonicalization (the bytes that are signed and hashed) |
| `keys` | `KeyProvider` interface; local provider with Ed25519 record and block keys and an AES-256 KEK; public key ring |
| `cipher` | AES-256-GCM record encryption with one data key per 5-minute interval and record class |
| `records` | Record envelope, submitter identity (device FQDN or user UPN), signing, leaf hashes |
| `classes` | The 16 initial record classes and their retention rules |
| `manifest` | Multi-document business submissions (one submission = one record) |
| `merkle` | RFC 6962 Merkle tree, inclusion proofs, compact range |
| `blocks` | Block headers, sealer signatures, block hashes, chain verification |
| `tsa` | RFC 3161 requests, responses and token verification; client that tries Sectigo, DigiCert, Apple, Microsoft ACS, FreeTSA in order |
| `receipts` | Submitter receipts and their verification |
| `sealing` | Seal an interval into a timestamped block; write the object-store layout to a directory |
| `devtsa` | Local RFC 3161 TSA for tests and demos only |
| `cli` | `logverify` |

Dependencies: `cryptography`, `httpx`, `click`. ASN.1 for RFC 3161 is handled by the small built-in DER codec,
so there is no dependency on an ASN.1 library.

## Install and test

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
cd tests && python -m unittest -v        # 54 tests; OpenSSL interop tests run when `openssl` is on PATH
```

## Try it

```bash
logverify demo demo                       # 3 sealed blocks, 2 receipts, dev TSA
cd demo
logverify chain store --keys log-keys.json --tsa-ca dev-tsa-root.pem
logverify receipt store/receipts/<id>.json --keys log-keys.json --tsa-ca dev-tsa-root.pem \
    --document documents/form-1120-2025.pdf --document documents/schedule-l.pdf --document documents/signature-page.pdf
logverify tsa-check                       # live test request to each of the five public TSAs
```

`logverify receipt` walks the proof step by step:

1. record signature (Ed25519, record key)
2. leaf hash recomputed from the signed record
3. Merkle inclusion proof leads to the block's `merkle_root`, and `tree_size` equals `entry_count`
4. block hash recomputed and sealer signature verified (block key)
5. RFC 3161 token covers the block hash; with `--tsa-ca`, the TSA certificate chains to that root
6. receipt signature
7. for business submissions, the manifest is consistent and each `--document` matches a listed hash

Without `--keys`, the server keys embedded in the receipt are used and a warning says so. Without `--tsa-ca`, the
TSA signature is checked but not its chain to a trusted root. For production verification, pass both.

## What has been verified

* Merkle roots and proofs match the Certificate Transparency RFC 6962 test vectors and a reference recursive
  implementation for every tree size from 1 to 69, plus 127, 128, 129 and 1,000.
* Canonical JSON matches the RFC 8785 examples.
* Tokens from the development TSA pass `openssl ts -verify`, and tokens issued by OpenSSL's own TSA pass
  `verify_token`, so the RFC 3161 code interoperates with an independent implementation in both directions.
* Tamper tests: altered envelopes, header fields, leaves, proofs, tokens, swapped or deleted blocks, a block
  re-signed with an attacker's key, and a block rewritten with the operator's own key all fail verification.

**Not yet verified here:** tokens from the five public TSAs. This build environment's network policy blocks
them (HTTP 403 for all five). Run `logverify tsa-check` on a machine with internet access to confirm; the client
accepts any RFC 3161 compliant token, and the verifier supports RSA (PKCS#1 v1.5 and PSS), ECDSA and Ed25519 TSA
signatures with ESS signing-certificate v1 or v2.

## Design decisions made during implementation

* **Block hash covers the sealer signature.** `block_hash = SHA-256(JCS(header))` where the header includes
  `sealer_signature` and `signing_key_id`. The TSA token therefore also fixes which key sealed the block.
* **Receipts are signed with the block key.** The receipt signature only makes the bundle tamper-evident; the
  evidence is the proof chain.
* **Event-based retention** (employee separation, policy expiry, and so on) is signed as a `retention_rule` with
  `retain_until = null`; the trigger event and lock-date update arrive in Phase 5.
* **Stored record objects carry `record_id`, `leaf_hash` and `block_id` in the clear.** These are already public
  in proofs, and the AES-GCM additional data binds the ciphertext to them.
* **Device identity rejects bare IP addresses.** A device must present an FQDN whose top-level label contains a letter.

## Next phases

Phase 2 adds the REST API, the ingest pipeline, the PostgreSQL ledger and the local and S3 stores, built on
`records`, `cipher` and `sealing.DirectoryStore`'s layout. Phase 3 turns `sealing.seal` into the 5-minute sealer
service with the Postgres advisory-lock leader election and webhook and polling receipt delivery.

See `FORMATS.md` for byte-level formats.
