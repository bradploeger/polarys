"""POLARYS core library (Phase 1).

Formats and cryptography shared by the ingest service, the sealer and the
offline ``logverify`` tool:

* ``jcs``       RFC 8785 JSON canonicalization
* ``keys``      KeyProvider interface, local Ed25519 + AES-256 KEK provider, public key ring
* ``cipher``    AES-256-GCM record encryption with per-interval, per-class data keys
* ``records``   record envelope, submitter identity (FQDN / UPN), signing, leaf hashes
* ``classes``   the 16 record classes and retention rules
* ``manifest``  multi-document business submissions (one submission = one record)
* ``merkle``    RFC 6962 Merkle trees, inclusion proofs, compact range
* ``blocks``    block headers, hashing, sealing signatures, chain verification
* ``tsa``       RFC 3161 request / response / token verification, ordered TSA client
* ``receipts``  submitter receipts and their verification
"""

__version__ = "0.3.0"
