"""A local RFC 3161 time-stamping authority for development and tests.

It issues standard tokens (verifiable with ``openssl ts -verify``) from a
throw-away CA.  Its tokens prove nothing to a third party: never configure it
as a TSA in production.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import der
from .tsa import (
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_ATTR_SIGNING_CERT_V2,
    OID_RSA,
    OID_SHA256,
    OID_SIGNED_DATA,
    OID_TSTINFO,
    TSAEndpoint,
    parse_request,
)

DEV_POLICY = "1.3.6.1.4.1.32473.1.1"  # documentation-only enterprise arc (RFC 5612)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "POLARYS development"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class DevTSA:
    def __init__(self, ca_key, ca_cert: x509.Certificate, tsa_key, tsa_cert: x509.Certificate, clock=None):
        self.ca_key, self.ca_cert = ca_key, ca_cert
        self.tsa_key, self.tsa_cert = tsa_key, tsa_cert
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.issued = 0

    @classmethod
    def create(cls, name: str = "POLARYS Dev TSA", clock=None) -> "DevTSA":
        now = datetime.now(timezone.utc) - timedelta(days=1)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name + " Root CA"))
            .issuer_name(_name(name + " Root CA"))
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        tsa_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(ca_cert.subject)
            .public_key(tsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return cls(ca_key, ca_cert, tsa_key, tsa_cert, clock)

    @classmethod
    def load_or_create(cls, directory, clock=None) -> "DevTSA":
        """Keep the development TSA's CA and signing key in ``directory`` so tokens verify across restarts."""
        from pathlib import Path

        d = Path(directory)
        names = ("ca.pem", "ca.key", "tsa.pem", "tsa.key")
        if all((d / n).exists() for n in names):
            load_key = lambda n: serialization.load_pem_private_key((d / n).read_bytes(), password=None)  # noqa: E731
            return cls(load_key("ca.key"), x509.load_pem_x509_certificate((d / "ca.pem").read_bytes()),
                       load_key("tsa.key"), x509.load_pem_x509_certificate((d / "tsa.pem").read_bytes()), clock)
        dev = cls.create(clock=clock)
        d.mkdir(parents=True, exist_ok=True)
        pem_key = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,  # noqa: E731
                                            serialization.NoEncryption())
        (d / "ca.pem").write_bytes(dev.ca_pem())
        (d / "tsa.pem").write_bytes(dev.tsa_cert.public_bytes(serialization.Encoding.PEM))
        for n, k in (("ca.key", dev.ca_key), ("tsa.key", dev.tsa_key)):
            (d / n).write_bytes(pem_key(k))
            (d / n).chmod(0o600)
        return dev

    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def respond(self, request_der: bytes) -> bytes:
        """DER TimeStampResp for a DER TimeStampReq."""
        try:
            req = parse_request(request_der)
        except Exception:
            return der.seq(der.seq(der.integer(2), der.seq(der.tlv(0x0C, b"bad request"))))
        if req.hash_oid != OID_SHA256:
            return der.seq(der.seq(der.integer(2), der.seq(der.tlv(0x0C, b"only SHA-256 is supported"))))
        self.issued += 1
        tst_parts = [
            der.integer(1),
            der.oid(DEV_POLICY),
            req.imprint_raw,
            der.integer(int.from_bytes(os.urandom(15), "big")),
            der.generalized_time(self.clock()),
            der.seq(der.integer(1)),
        ]
        if req.nonce is not None:
            tst_parts.append(der.integer(req.nonce))
        tst = der.seq(*tst_parts)

        cert_der = self.tsa_cert.public_bytes(serialization.Encoding.DER)
        attrs = der.set_of(
            der.seq(der.oid(OID_ATTR_CONTENT_TYPE), der.set_of(der.oid(OID_TSTINFO))),
            der.seq(der.oid(OID_ATTR_MESSAGE_DIGEST), der.set_of(der.octet_string(hashlib.sha256(tst).digest()))),
            der.seq(
                der.oid(OID_ATTR_SIGNING_CERT_V2),
                der.set_of(der.seq(der.seq(der.seq(der.octet_string(hashlib.sha256(cert_der).digest()))))),
            ),
        )
        signature = self.tsa_key.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
        signer_info = der.seq(
            der.integer(1),
            der.seq(self.tsa_cert.issuer.public_bytes(), der.integer(self.tsa_cert.serial_number)),
            der.algorithm_identifier(OID_SHA256),
            b"\xa0" + attrs[1:],  # [0] IMPLICIT SET OF Attribute
            der.algorithm_identifier(OID_RSA),
            der.octet_string(signature),
        )
        certs = [cert_der]
        if req.cert_req:
            certs.append(self.ca_cert.public_bytes(serialization.Encoding.DER))
        signed_data = der.seq(
            der.integer(3),
            der.set_of(der.algorithm_identifier(OID_SHA256)),
            der.seq(der.oid(OID_TSTINFO), der.explicit(0, der.octet_string(tst))),
            der.implicit_constructed(0, b"".join(sorted(certs))),
            der.set_of(signer_info),
        )
        token = der.seq(der.oid(OID_SIGNED_DATA), der.explicit(0, signed_data))
        return der.seq(der.seq(der.integer(0)), token)

    # -- plumbing for TSAClient in tests and demos ---------------------------

    def endpoint(self) -> TSAEndpoint:
        return TSAEndpoint("POLARYS Dev TSA", "http://dev-tsa.invalid/tsr")

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=self.respond(request.content), headers={"Content-Type": "application/timestamp-reply"})

        return httpx.MockTransport(handler)
