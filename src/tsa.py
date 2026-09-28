"""RFC 3161 time-stamping: requests, responses, token verification and the TSA client.

The sealer asks public TSAs to timestamp each block hash.  TSAs are tried in
the configured order (default: Sectigo, DigiCert, Apple, Microsoft ACS,
FreeTSA); any RFC 3161 compliant token is accepted and the TSA that issued it
is recorded.

Token verification checks, in order:

1. the token is CMS SignedData wrapping a TSTInfo
2. the message imprint equals the expected digest (and the nonce, if given)
3. the signed attributes' messageDigest matches the TSTInfo bytes
4. the ESS signing-certificate attribute (v1 or v2) matches the signer certificate
5. the CMS signature verifies with the signer certificate
6. the signer certificate carries the timeStamping extended key usage and was valid at genTime
7. optionally, the signer certificate chains to one of the supplied trust roots,
   each certificate valid at genTime (no revocation checking in v1)
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import der
from .der import CONTEXT, DERError

# --------------------------------------------------------------------------
# Object identifiers
# --------------------------------------------------------------------------

OID_SHA1 = "1.3.14.3.2.26"
OID_SHA224 = "2.16.840.1.101.3.4.2.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ATTR_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"

OID_RSA = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_ED25519 = "1.3.101.112"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"

_HASHES = {
    OID_SHA1: hashes.SHA1,
    OID_SHA224: hashes.SHA224,
    OID_SHA256: hashes.SHA256,
    OID_SHA384: hashes.SHA384,
    OID_SHA512: hashes.SHA512,
}
_RSA_SIG = {
    "1.2.840.113549.1.1.5": OID_SHA1,
    "1.2.840.113549.1.1.14": OID_SHA224,
    "1.2.840.113549.1.1.11": OID_SHA256,
    "1.2.840.113549.1.1.12": OID_SHA384,
    "1.2.840.113549.1.1.13": OID_SHA512,
}
_ECDSA_SIG = {
    "1.2.840.10045.4.1": OID_SHA1,
    "1.2.840.10045.4.3.1": OID_SHA224,
    "1.2.840.10045.4.3.2": OID_SHA256,
    "1.2.840.10045.4.3.3": OID_SHA384,
    "1.2.840.10045.4.3.4": OID_SHA512,
}

PKI_STATUS = {0: "granted", 1: "grantedWithMods", 2: "rejection", 3: "waiting", 4: "revocationWarning", 5: "revocationNotification"}
FAIL_INFO = {0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable", 15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure"}


class TimestampError(Exception):
    pass


def _hash(oid: str, data: bytes) -> bytes:
    try:
        h = hashes.Hash(_HASHES[oid]())
    except KeyError:
        raise TimestampError(f"unsupported digest algorithm {oid}") from None
    h.update(data)
    return h.finalize()


# --------------------------------------------------------------------------
# Requests and responses
# --------------------------------------------------------------------------


def build_request(digest: bytes, nonce: int | None = None, cert_req: bool = True, policy: str | None = None) -> bytes:
    """DER TimeStampReq for a SHA-256 digest."""
    if len(digest) != 32:
        raise ValueError("digest must be a 32-byte SHA-256 value")
    parts = [der.integer(1), der.seq(der.algorithm_identifier(OID_SHA256), der.octet_string(digest))]
    if policy:
        parts.append(der.oid(policy))
    if nonce is not None:
        parts.append(der.integer(nonce))
    if cert_req:
        parts.append(der.boolean(True))
    return der.seq(*parts)


def new_nonce() -> int:
    return int.from_bytes(os.urandom(8), "big") >> 1  # positive 63-bit


@dataclass
class ParsedRequest:
    hash_oid: str
    digest: bytes
    nonce: int | None
    cert_req: bool
    imprint_raw: bytes


def parse_request(data: bytes) -> ParsedRequest:
    root = der.parse(data).expect(der.SEQUENCE)
    kids = root.children
    if kids[0].integer() != 1:
        raise TimestampError("unsupported TimeStampReq version")
    imprint = kids[1]
    hash_oid = imprint.children[0].children[0].oid()
    digest = imprint.children[1].octets()
    nonce, cert_req = None, False
    for k in kids[2:]:
        if k.is_(der.INTEGER):
            nonce = k.integer()
        elif k.is_(der.BOOLEAN):
            cert_req = k.boolean()
    return ParsedRequest(hash_oid, digest, nonce, cert_req, imprint.raw)


def parse_response(data: bytes) -> bytes:
    """Return the DER timestamp token from a TimeStampResp, or raise with the TSA's reason."""
    try:
        root = der.parse(data).expect(der.SEQUENCE)
        status_info = root.children[0].expect(der.SEQUENCE).children
        status = status_info[0].integer()
    except (DERError, IndexError) as e:
        raise TimestampError(f"malformed TimeStampResp: {e}") from None
    if status not in (0, 1):
        text = []
        fail = []
        for n in status_info[1:]:
            if n.is_(der.SEQUENCE):
                text += [c.content.decode("utf-8", "replace") for c in n.children]
            elif n.is_(der.BIT_STRING):
                bits = n.content[1:]
                fail += [name for bit, name in FAIL_INFO.items() if bit // 8 < len(bits) and bits[bit // 8] & (0x80 >> bit % 8)]
        detail = "; ".join(text + fail)
        raise TimestampError(f"TSA refused the request: {PKI_STATUS.get(status, status)}" + (f" ({detail})" if detail else ""))
    if len(root.children) < 2:
        raise TimestampError("TSA granted the request but returned no token")
    return root.children[1].raw


# --------------------------------------------------------------------------
# Token verification
# --------------------------------------------------------------------------


@dataclass
class TimestampInfo:
    gen_time: datetime
    serial_number: int
    policy: str
    hash_algorithm: str
    hashed_message: bytes
    nonce: int | None
    accuracy_seconds: float | None
    signer: x509.Certificate
    certificates: list[x509.Certificate]
    chain: list[x509.Certificate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def tsa_name(self) -> str:
        return self.signer.subject.rfc4514_string()

    @property
    def chain_verified(self) -> bool:
        return bool(self.chain)

    def summary(self) -> dict:
        return {
            "gen_time": self.gen_time.isoformat().replace("+00:00", "Z"),
            "serial_number": hex(self.serial_number),
            "policy": self.policy,
            "tsa": self.tsa_name,
            "hash_algorithm": self.hash_algorithm,
            "hashed_message": self.hashed_message.hex(),
            "accuracy_seconds": self.accuracy_seconds,
            "chain_verified": self.chain_verified,
            "warnings": self.warnings,
        }


def _parse_tstinfo(data: bytes) -> dict:
    kids = der.parse(data).expect(der.SEQUENCE).children
    if kids[0].integer() != 1:
        raise TimestampError("unsupported TSTInfo version")
    imprint = kids[2].children
    out = {
        "policy": kids[1].oid(),
        "hash_oid": imprint[0].children[0].oid(),
        "hashed_message": imprint[1].octets(),
        "serial": kids[3].integer(),
        "gen_time": kids[4].generalized_time(),
        "nonce": None,
        "accuracy": None,
    }
    for k in kids[5:]:
        if k.is_(der.SEQUENCE):  # Accuracy
            acc = 0.0
            for a in k.children:
                if a.is_(der.INTEGER):
                    acc += a.integer()
                elif a.cls == CONTEXT and a.tag == 0:
                    acc += int.from_bytes(a.content, "big") / 1e3
                elif a.cls == CONTEXT and a.tag == 1:
                    acc += int.from_bytes(a.content, "big") / 1e6
            out["accuracy"] = acc
        elif k.is_(der.INTEGER):
            out["nonce"] = k.integer()
    return out


def _signer_cert(sid: der.Node, certs: list[tuple[bytes, x509.Certificate]]) -> tuple[bytes, x509.Certificate]:
    if sid.is_(der.SEQUENCE):  # IssuerAndSerialNumber
        issuer_raw = sid.children[0].raw
        serial = sid.children[1].integer()
        for raw, c in certs:
            if c.serial_number == serial and c.issuer.public_bytes() == issuer_raw:
                return raw, c
    elif sid.cls == CONTEXT and sid.tag == 0:  # SubjectKeyIdentifier
        for raw, c in certs:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid.content:
                return raw, c
    raise TimestampError("signer certificate is not included in the token (request certReq=true)")


def _verify_signature(cert: x509.Certificate, sig_alg: der.Node, digest_oid: str, signature: bytes, data: bytes) -> None:
    alg = sig_alg.children[0].oid()
    key = cert.public_key()
    try:
        if alg == OID_ED25519:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise TimestampError("signature algorithm does not match the signer key")
            key.verify(signature, data)
        elif alg == OID_RSA_PSS:
            params = sig_alg.children[1].children if len(sig_alg.children) > 1 else []
            h_oid, mgf_oid, salt = OID_SHA1, OID_SHA1, 20
            for p in params:
                if p.tag == 0:
                    h_oid = p.children[0].children[0].oid()
                elif p.tag == 1:
                    mgf = p.children[0]
                    if mgf.children[0].oid() != OID_MGF1:
                        raise TimestampError("unsupported PSS mask generation function")
                    mgf_oid = mgf.children[1].children[0].oid()
                elif p.tag == 2:
                    salt = p.children[0].integer()
            key.verify(signature, data, padding.PSS(padding.MGF1(_HASHES[mgf_oid]()), salt), _HASHES[h_oid]())
        elif alg == OID_RSA or alg in _RSA_SIG:
            if not isinstance(key, rsa.RSAPublicKey):
                raise TimestampError("signature algorithm does not match the signer key")
            key.verify(signature, data, padding.PKCS1v15(), _HASHES[_RSA_SIG.get(alg, digest_oid)]())
        elif alg in _ECDSA_SIG or alg == OID_EC_PUBLIC_KEY:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise TimestampError("signature algorithm does not match the signer key")
            key.verify(signature, data, ec.ECDSA(_HASHES[_ECDSA_SIG.get(alg, digest_oid)]()))
        else:
            raise TimestampError(f"unsupported signature algorithm {alg}")
    except InvalidSignature:
        raise TimestampError("TSA signature does not verify") from None


def _valid_at(cert: x509.Certificate, at: datetime) -> bool:
    return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc


def _build_chain(
    signer: x509.Certificate, pool: list[x509.Certificate], roots: list[x509.Certificate], at: datetime
) -> list[x509.Certificate]:
    root_fps = {r.fingerprint(hashes.SHA256()) for r in roots}
    path, cur = [signer], signer
    for _ in range(8):
        if cur.fingerprint(hashes.SHA256()) in root_fps:
            return path
        for issuer in [r for r in roots if r.subject == cur.issuer] + [
            c for c in pool if c.subject == cur.issuer and c != cur
        ]:
            try:
                cur.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature):
                continue
            try:
                bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not bc.ca:
                    continue
            except x509.ExtensionNotFound:
                continue
            if not _valid_at(issuer, at):
                raise TimestampError(f"certificate {issuer.subject.rfc4514_string()} was not valid at genTime")
            path.append(issuer)
            cur = issuer
            break
        else:
            raise TimestampError(f"no trusted issuer found for {cur.subject.rfc4514_string()}")
    raise TimestampError("certificate chain too long")


def verify_token(
    token: bytes,
    digest: bytes | None = None,
    nonce: int | None = None,
    trust_roots: list[x509.Certificate] | None = None,
    intermediates: list[x509.Certificate] | None = None,
) -> TimestampInfo:
    """Verify a DER RFC 3161 token (a CMS ContentInfo). Raises TimestampError on any failure."""
    try:
        return _verify_token(token, digest, nonce, trust_roots, intermediates)
    except (DERError, IndexError, KeyError, ValueError) as e:
        raise TimestampError(f"malformed timestamp token: {e}") from None


def _verify_token(token, digest, nonce, trust_roots, intermediates) -> TimestampInfo:
    ci = der.parse(token).expect(der.SEQUENCE).children
    if ci[0].oid() != OID_SIGNED_DATA:
        raise TimestampError("token is not CMS SignedData")
    sd = ci[1].expect(0, CONTEXT).children[0].expect(der.SEQUENCE).children
    encap = sd[2].children
    if encap[0].oid() != OID_TSTINFO:
        raise TimestampError("token content is not a TSTInfo")
    tst_bytes = encap[1].expect(0, CONTEXT).children[0].octets()
    tst = _parse_tstinfo(tst_bytes)

    certs: list[tuple[bytes, x509.Certificate]] = []
    signer_infos = None
    for n in sd[3:]:
        if n.cls == CONTEXT and n.tag == 0:
            for c in n.children:
                if c.is_(der.SEQUENCE):
                    certs.append((c.raw, x509.load_der_x509_certificate(c.raw)))
        elif n.is_(der.SET):
            signer_infos = n.children
    if not signer_infos or len(signer_infos) != 1:
        raise TimestampError("token must have exactly one signer")
    si = signer_infos[0].children

    warnings: list[str] = []
    if digest is not None:
        if tst["hash_oid"] != OID_SHA256:
            raise TimestampError("token imprint is not SHA-256")
        if tst["hashed_message"] != digest:
            raise TimestampError("token imprint does not match the expected hash")
    if nonce is not None and tst["nonce"] != nonce:
        raise TimestampError("token nonce does not match the request")

    cert_raw, signer = _signer_cert(si[1], certs)
    digest_oid = si[2].children[0].oid()
    idx = 3
    signed_attrs = None
    if si[idx].cls == CONTEXT and si[idx].tag == 0:
        signed_attrs = si[idx]
        idx += 1
    sig_alg, signature = si[idx], si[idx + 1].octets()

    if signed_attrs is not None:
        attrs = {a.children[0].oid(): a.children[1].children for a in signed_attrs.children}
        if OID_ATTR_CONTENT_TYPE not in attrs or attrs[OID_ATTR_CONTENT_TYPE][0].oid() != OID_TSTINFO:
            raise TimestampError("signed contentType attribute is missing or wrong")
        if OID_ATTR_MESSAGE_DIGEST not in attrs:
            raise TimestampError("signed messageDigest attribute is missing")
        if attrs[OID_ATTR_MESSAGE_DIGEST][0].octets() != _hash(digest_oid, tst_bytes):
            raise TimestampError("messageDigest does not match the TSTInfo")
        if OID_ATTR_SIGNING_CERT_V2 in attrs:
            ids = attrs[OID_ATTR_SIGNING_CERT_V2][0].children[0].children
            first = ids[0].children
            h_oid = first[0].children[0].oid() if first[0].is_(der.SEQUENCE) else OID_SHA256
            cert_hash = (first[1] if first[0].is_(der.SEQUENCE) else first[0]).octets()
            if cert_hash != _hash(h_oid, cert_raw):
                raise TimestampError("ESS signingCertificateV2 does not match the signer certificate")
        elif OID_ATTR_SIGNING_CERT in attrs:
            first = attrs[OID_ATTR_SIGNING_CERT][0].children[0].children[0].children
            if first[0].octets() != hashlib.sha1(cert_raw).digest():
                raise TimestampError("ESS signingCertificate does not match the signer certificate")
        else:
            warnings.append("token has no ESS signing-certificate attribute")
        signed_data = b"\x31" + signed_attrs.raw[1:]  # signature covers the attributes as a SET
    else:
        signed_data = tst_bytes
        warnings.append("token has no signed attributes")
    _verify_signature(signer, sig_alg, digest_oid, signature, signed_data)

    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if ExtendedKeyUsageOID.TIME_STAMPING not in eku.value:
            raise TimestampError("signer certificate is not authorised for time stamping")
        if not eku.critical:
            warnings.append("timeStamping extended key usage is not marked critical")
    except x509.ExtensionNotFound:
        raise TimestampError("signer certificate has no extended key usage") from None
    if not _valid_at(signer, tst["gen_time"]):
        raise TimestampError("signer certificate was not valid at genTime")

    info = TimestampInfo(
        gen_time=tst["gen_time"],
        serial_number=tst["serial"],
        policy=tst["policy"],
        hash_algorithm=tst["hash_oid"],
        hashed_message=tst["hashed_message"],
        nonce=tst["nonce"],
        accuracy_seconds=tst["accuracy"],
        signer=signer,
        certificates=[c for _, c in certs],
        warnings=warnings,
    )
    if trust_roots:
        info.chain = _build_chain(signer, info.certificates + list(intermediates or []), trust_roots, tst["gen_time"])
    return info


def load_certificates(pem_or_der: bytes) -> list[x509.Certificate]:
    """Load a PEM bundle (skipping any certificate that does not parse) or a single DER certificate.

    System trust bundles can contain certificates that newer ``cryptography`` releases reject
    (for example a non-positive serial number); one bad entry must not make the bundle unusable.
    """
    if b"-----BEGIN" not in pem_or_der:
        return [x509.load_der_x509_certificate(pem_or_der)]
    import warnings

    end = b"-----END CERTIFICATE-----"
    certs = []
    for chunk in pem_or_der.split(end)[:-1]:
        start = chunk.find(b"-----BEGIN CERTIFICATE-----")
        if start < 0:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                certs.append(x509.load_pem_x509_certificate(chunk[start:] + end + b"\n"))
        except ValueError:
            continue
    if not certs:
        raise ValueError("no certificates found")
    return certs


# --------------------------------------------------------------------------
# Client with ordered failover
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TSAEndpoint:
    name: str
    url: str


DEFAULT_TSAS: tuple[TSAEndpoint, ...] = (
    TSAEndpoint("Sectigo", "http://timestamp.sectigo.com"),
    TSAEndpoint("DigiCert", "http://timestamp.digicert.com"),
    TSAEndpoint("Apple", "http://timestamp.apple.com/ts01"),
    TSAEndpoint("Microsoft ACS", "http://timestamp.acs.microsoft.com"),
    TSAEndpoint("FreeTSA", "http://freetsa.org/tsr"),
)


@dataclass
class TimestampResult:
    token: bytes
    tsa: TSAEndpoint
    info: TimestampInfo
    attempts: list[str]


class AllTSAsFailed(TimestampError):
    def __init__(self, attempts: list[str]):
        super().__init__("no TSA returned a valid token:\n  " + "\n  ".join(attempts))
        self.attempts = attempts


class TSAClient:
    """Tries each TSA in order, ``attempts_per_tsa`` times with ``timeout`` seconds each."""

    def __init__(
        self,
        tsas: tuple[TSAEndpoint, ...] | list[TSAEndpoint] = DEFAULT_TSAS,
        *,
        attempts_per_tsa: int = 2,
        timeout: float = 10.0,
        retry_delay: float = 1.0,
        max_skew: timedelta = timedelta(minutes=5),
        trust_roots: list[x509.Certificate] | None = None,
        http: httpx.Client | None = None,
    ):
        if not tsas:
            raise ValueError("at least one TSA is required")
        self.tsas = list(tsas)
        self.attempts_per_tsa = attempts_per_tsa
        self.timeout = timeout
        self.retry_delay = retry_delay
        self.max_skew = max_skew
        self.trust_roots = trust_roots
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=True)

    def timestamp(self, digest: bytes, reference_time: datetime | None = None) -> TimestampResult:
        log: list[str] = []
        for tsa in self.tsas:
            for attempt in range(1, self.attempts_per_tsa + 1):
                nonce = new_nonce()
                try:
                    resp = self._http.post(
                        tsa.url,
                        content=build_request(digest, nonce),
                        headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
                        timeout=self.timeout,
                    )
                    if resp.status_code != 200:
                        raise TimestampError(f"HTTP {resp.status_code}")
                    token = parse_response(resp.content)
                    info = verify_token(token, digest, nonce, self.trust_roots)
                    if reference_time is not None and abs(info.gen_time - reference_time) > self.max_skew:
                        raise TimestampError(
                            f"genTime {info.gen_time.isoformat()} is more than {self.max_skew} from the block time"
                        )
                    log.append(f"{tsa.name} attempt {attempt}: ok")
                    return TimestampResult(token, tsa, info, log)
                except (httpx.HTTPError, TimestampError) as e:
                    log.append(f"{tsa.name} attempt {attempt}: {type(e).__name__}: {e}")
                    if attempt < self.attempts_per_tsa and self.retry_delay:
                        time.sleep(self.retry_delay)
        raise AllTSAsFailed(log)

    def close(self) -> None:
        self._http.close()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
