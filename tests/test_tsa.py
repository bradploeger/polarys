import hashlib
import shutil
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization

from polarys import der
from polarys.devtsa import DevTSA
from polarys.tsa import (
    AllTSAsFailed,
    TimestampError,
    TSAClient,
    TSAEndpoint,
    build_request,
    new_nonce,
    now_utc,
    parse_request,
    parse_response,
    verify_token,
)

from helpers import Clock

DIGEST = hashlib.sha256(b"block header").digest()


class TokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tsa = DevTSA.create()

    def issue(self, digest=DIGEST, nonce=None):
        return parse_response(self.tsa.respond(build_request(digest, nonce)))

    def test_request_roundtrip(self):
        req = parse_request(build_request(DIGEST, 42))
        self.assertEqual((req.digest, req.nonce, req.cert_req), (DIGEST, 42, True))

    def test_valid_token_with_chain(self):
        n = new_nonce()
        info = verify_token(self.issue(nonce=n), DIGEST, n, trust_roots=[self.tsa.ca_cert])
        self.assertEqual(info.hashed_message, DIGEST)
        self.assertEqual(info.nonce, n)
        self.assertTrue(info.chain_verified)
        self.assertEqual(info.warnings, [])

    def test_wrong_digest_and_nonce(self):
        tok = self.issue(nonce=7)
        with self.assertRaisesRegex(TimestampError, "imprint"):
            verify_token(tok, hashlib.sha256(b"other").digest())
        with self.assertRaisesRegex(TimestampError, "nonce"):
            verify_token(tok, DIGEST, nonce=8)

    def test_untrusted_root(self):
        other = DevTSA.create("Other TSA")
        with self.assertRaisesRegex(TimestampError, "no trusted issuer"):
            verify_token(self.issue(), DIGEST, trust_roots=[other.ca_cert])

    def test_every_byte_of_signature_region_is_protected(self):
        tok = self.issue()
        for pos in (len(tok) - 3, len(tok) - 100, len(tok) // 2, 120):
            bad = bytearray(tok)
            bad[pos] ^= 0x01
            with self.assertRaises(TimestampError, msg=f"byte {pos}"):
                verify_token(bytes(bad), DIGEST, trust_roots=[self.tsa.ca_cert])

    def test_refusal_is_reported(self):
        refused = der.seq(der.seq(der.integer(2), der.seq(der.tlv(0x0C, b"policy not supported"))))
        with self.assertRaisesRegex(TimestampError, "rejection.*policy not supported"):
            parse_response(refused)


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class OpenSSLInteropTests(unittest.TestCase):
    """Cross-check against an independent RFC 3161 implementation in both directions."""

    @classmethod
    def setUpClass(cls):
        cls.tsa = DevTSA.create()
        cls.dir = Path(tempfile.mkdtemp())
        d = cls.dir
        (d / "ca.pem").write_bytes(cls.tsa.ca_pem())
        (d / "tsa.pem").write_bytes(cls.tsa.tsa_cert.public_bytes(serialization.Encoding.PEM))
        (d / "tsa.key").write_bytes(cls.tsa.tsa_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (d / "serial").write_text("01\n")
        (d / "tsa.cnf").write_text(f"""
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = {d}
serial = $dir/serial
crypto_device = builtin
signer_cert = $dir/tsa.pem
certs = $dir/ca.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1, millisecs:500, microsecs:100
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")

    def test_openssl_verifies_our_tokens(self):
        tok = parse_response(self.tsa.respond(build_request(DIGEST, 99)))
        (self.dir / "ours.der").write_bytes(tok)
        r = subprocess.run(["openssl", "ts", "-verify", "-in", str(self.dir / "ours.der"), "-token_in",
                            "-digest", DIGEST.hex(), "-CAfile", str(self.dir / "ca.pem")], capture_output=True, text=True)
        self.assertIn("Verification: OK", r.stdout + r.stderr)

    def test_we_verify_openssl_tokens(self):
        data = self.dir / "data.bin"
        data.write_bytes(b"block header")
        subprocess.run(["openssl", "ts", "-query", "-data", str(data), "-sha256", "-cert", "-out", str(self.dir / "q.tsq")], check=True, capture_output=True)
        subprocess.run(["openssl", "ts", "-reply", "-config", str(self.dir / "tsa.cnf"), "-queryfile", str(self.dir / "q.tsq"),
                        "-out", str(self.dir / "r.tsr")], check=True, capture_output=True)
        token = parse_response((self.dir / "r.tsr").read_bytes())
        info = verify_token(token, DIGEST, trust_roots=[self.tsa.ca_cert])
        self.assertTrue(info.chain_verified)
        self.assertAlmostEqual(info.accuracy_seconds, 1.5001)
        with self.assertRaises(TimestampError):
            verify_token(token, hashlib.sha256(b"x").digest())


class ClientTests(unittest.TestCase):
    def test_failover_order_and_success(self):
        good = DevTSA.create()
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.host)
            if request.url.host == "down.example":
                return httpx.Response(503)
            if request.url.host == "garbage.example":
                return httpx.Response(200, content=b"\x30\x03\x02\x01\x00")
            return httpx.Response(200, content=good.respond(request.content))

        tsas = [TSAEndpoint("Down", "http://down.example/"), TSAEndpoint("Garbage", "http://garbage.example/"), TSAEndpoint("Good", "http://good.example/")]
        client = TSAClient(tsas, http=httpx.Client(transport=httpx.MockTransport(handler)), retry_delay=0)
        res = client.timestamp(DIGEST, now_utc())
        self.assertEqual(res.tsa.name, "Good")
        self.assertEqual(calls, ["down.example", "down.example", "garbage.example", "garbage.example", "good.example"])
        self.assertEqual(len(res.attempts), 5)

    def test_all_fail(self):
        client = TSAClient([TSAEndpoint("A", "http://a.example/"), TSAEndpoint("B", "http://b.example/")],
                           http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))), retry_delay=0)
        with self.assertRaises(AllTSAsFailed) as cm:
            client.timestamp(DIGEST)
        self.assertEqual(len(cm.exception.attempts), 4)

    def test_clock_skew_rejected(self):
        clock = Clock(now_utc() + timedelta(minutes=10))
        bad = DevTSA.create(clock=clock)
        client = TSAClient([bad.endpoint()], http=httpx.Client(transport=bad.transport()), retry_delay=0)
        with self.assertRaisesRegex(AllTSAsFailed, "genTime"):
            client.timestamp(DIGEST, now_utc())

    def test_default_order(self):
        from polarys.tsa import DEFAULT_TSAS

        self.assertEqual([t.name for t in DEFAULT_TSAS], ["Sectigo", "DigiCert", "Apple", "Microsoft ACS", "FreeTSA"])


if __name__ == "__main__":
    unittest.main()
