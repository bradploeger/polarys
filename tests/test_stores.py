import base64
import hashlib
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone

import httpx

from polarys.store import ObjectExists, ObjectNotFound, Retention, StoreError, StoreUnavailable
from polarys.store.local import LocalFSStore
from polarys.store.s3 import EMPTY_SHA256, S3Store, sigv4_headers
from polarys.store.spool import SpoolingStore

AK, SK = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
FIXED = datetime(2013, 5, 24, tzinfo=timezone.utc)


def _sig(h):
    return h["Authorization"].split("Signature=")[1]


class SigV4Vectors(unittest.TestCase):
    """Examples from the AWS S3 Signature Version 4 documentation."""

    def sign(self, method, path, query, headers, payload_hash):
        return sigv4_headers(method, "examplebucket.s3.amazonaws.com", path, query, headers, payload_hash,
                             access_key=AK, secret_key=SK, region="us-east-1", amz_date="20130524T000000Z")

    def test_get_object(self):
        h = self.sign("GET", "/test.txt", {}, {"Range": "bytes=0-9"}, EMPTY_SHA256)
        self.assertEqual(_sig(h), "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
        self.assertIn("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,", h["Authorization"])

    def test_put_object(self):
        body = b"Welcome to Amazon S3."
        h = self.sign("PUT", "/test$file.text", {}, {"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"},
                      hashlib.sha256(body).hexdigest())
        self.assertEqual(_sig(h), "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")

    def test_get_bucket_lifecycle(self):
        self.assertEqual(_sig(self.sign("GET", "/", {"lifecycle": ""}, {}, EMPTY_SHA256)),
                         "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")

    def test_list_objects(self):
        self.assertEqual(_sig(self.sign("GET", "/", {"max-keys": "2", "prefix": "J"}, {}, EMPTY_SHA256)),
                         "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")


class FakeS3:
    """In-memory S3 that re-derives every request's signature and checks S3 semantics."""

    def __init__(self):
        self.objects: dict[str, tuple[bytes, dict]] = {}
        self.fail_next = 0
        self.fail_status = 503
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_next:
            self.fail_next -= 1
            return httpx.Response(self.fail_status, text="<Error><Code>SlowDown</Code><Message>busy</Message></Error>")
        auth = request.headers["authorization"]
        signed = auth.split("SignedHeaders=")[1].split(",")[0].split(";")
        hdrs = {k: request.headers[k] for k in signed if k not in ("host", "x-amz-date", "x-amz-content-sha256")}
        body = request.content
        payload_hash = request.headers["x-amz-content-sha256"]
        if payload_hash != (hashlib.sha256(body).hexdigest() if body else EMPTY_SHA256):
            return httpx.Response(400, text="<Error><Code>XAmzContentSHA256Mismatch</Code></Error>")
        from urllib.parse import unquote

        expect = sigv4_headers(request.method, request.url.host + (f":{request.url.port}" if request.url.port else ""),
                               unquote(request.url.raw_path.decode()), {}, hdrs, payload_hash,
                               access_key=AK, secret_key=SK, region="us-east-1", amz_date=request.headers["x-amz-date"])
        if expect["Authorization"] != auth:
            return httpx.Response(403, text="<Error><Code>SignatureDoesNotMatch</Code></Error>")
        key = unquote(request.url.raw_path.decode())
        if request.method == "PUT":
            if base64.b64decode(request.headers["content-md5"]) != hashlib.md5(body).digest():
                return httpx.Response(400, text="<Error><Code>BadDigest</Code></Error>")
            if request.headers.get("if-none-match") == "*" and key in self.objects:
                return httpx.Response(412, text="<Error><Code>PreconditionFailed</Code></Error>")
            self.objects[key] = (body, dict(request.headers))
            return httpx.Response(200)
        if key not in self.objects:
            return httpx.Response(404)
        return httpx.Response(200, content=self.objects[key][0] if request.method == "GET" else b"")


class S3StoreTests(unittest.TestCase):
    def make(self, fake, **kw):
        return S3Store("records-bucket", endpoint_url="http://minio.local:9000", access_key=AK, secret_key=SK,
                       http=httpx.Client(transport=httpx.MockTransport(fake.handler)), attempts=3, **kw)

    def test_put_get_exists_and_lock_headers(self):
        fake = FakeS3()
        s3 = self.make(fake, prefix="polarys")
        until = datetime(2033, 9, 27, 4, 0, 0, 123456, tzinfo=timezone.utc)
        s3.put("records/2026/09/27/x/a b+c.bin", b"cipher", "application/json", Retention(retain_until=until))
        s3.put("records/2026/09/27/x/held.bin", b"held", retention=Retention(legal_hold=True))
        self.assertEqual(s3.get("records/2026/09/27/x/a b+c.bin"), b"cipher")
        self.assertTrue(s3.exists("records/2026/09/27/x/held.bin"))
        self.assertFalse(s3.exists("nope"))
        with self.assertRaises(ObjectNotFound):
            s3.get("nope")
        _, h = fake.objects["/records-bucket/polarys/records/2026/09/27/x/a b+c.bin"]
        self.assertEqual(h["x-amz-object-lock-mode"], "COMPLIANCE")
        self.assertEqual(h["x-amz-object-lock-retain-until-date"], "2033-09-27T04:00:00.000Z")
        self.assertNotIn("x-amz-object-lock-legal-hold", h)
        _, h2 = fake.objects["/records-bucket/polarys/records/2026/09/27/x/held.bin"]
        self.assertEqual(h2["x-amz-object-lock-legal-hold"], "ON")
        self.assertNotIn("x-amz-object-lock-mode", h2)

    def test_no_overwrite(self):
        fake = FakeS3()
        s3 = self.make(fake)
        s3.put("k", b"1")
        with self.assertRaises(ObjectExists):
            s3.put("k", b"2")
        self.assertEqual(s3.get("k"), b"1")

    def test_transient_errors_retry_then_unavailable(self):
        fake = FakeS3()
        s3 = self.make(fake)
        fake.fail_next = 2
        s3.put("k", b"ok")  # third attempt succeeds
        fake.fail_next = 3
        with self.assertRaises(StoreUnavailable):
            s3.put("k2", b"x")

    def test_auth_errors_are_not_spoolable(self):
        fake = FakeS3()
        s3 = S3Store("b", endpoint_url="http://minio.local:9000", access_key=AK, secret_key="wrong",
                     http=httpx.Client(transport=httpx.MockTransport(fake.handler)))
        with self.assertRaises(StoreError) as cm:
            s3.put("k", b"x")
        self.assertNotIsInstance(cm.exception, StoreUnavailable)
        self.assertIn("SignatureDoesNotMatch", str(cm.exception))

    def test_virtual_host_addressing_on_aws(self):
        fake = FakeS3()
        s3 = S3Store("my-bucket", region="us-east-2", access_key=AK, secret_key=SK,
                     http=httpx.Client(transport=httpx.MockTransport(lambda r: (fake.requests.append(r), httpx.Response(200))[1])))
        s3.put("a/b.bin", b"x")
        self.assertEqual(str(fake.requests[0].url), "https://my-bucket.s3.us-east-2.amazonaws.com/a/b.bin")
        self.assertIn("/us-east-2/s3/aws4_request", fake.requests[0].headers["authorization"])

    def test_rejects_bad_keys(self):
        s3 = self.make(FakeS3())
        for bad in ("", "/abs", "a/../b", "a//b", "a\\b"):
            with self.assertRaises(StoreError):
                s3.put(bad, b"x")


class LocalStoreTests(unittest.TestCase):
    def test_write_once_read_only(self):
        st = LocalFSStore(tempfile.mkdtemp())
        st.put("records/a/b.bin", b"data", retention=Retention(legal_hold=True))
        self.assertEqual(st.get("records/a/b.bin"), b"data")
        with self.assertRaises(ObjectExists):
            st.put("records/a/b.bin", b"other")
        self.assertEqual(st.get("records/a/b.bin"), b"data")
        mode = os.stat(st.root / "records/a/b.bin").st_mode
        self.assertFalse(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        self.assertEqual([p.name for p in (st.root / "records/a").iterdir()], ["b.bin"])  # no temp files left
        with self.assertRaises(ObjectNotFound):
            st.get("records/none.bin")


class Flaky(LocalFSStore):
    down = False

    def put(self, key, data, content_type="application/octet-stream", retention=None):
        if self.down:
            raise StoreUnavailable("down")
        super().put(key, data, content_type, retention)


class SpoolTests(unittest.TestCase):
    def test_spool_and_drain(self):
        primary = Flaky(tempfile.mkdtemp())
        sp = SpoolingStore(primary, tempfile.mkdtemp())
        self.assertFalse(sp.put_or_spool("a/1.bin", b"one"))
        primary.down = True
        until = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.assertTrue(sp.put_or_spool("a/2.bin", b"two", "application/json", Retention(retain_until=until)))
        self.assertTrue(sp.put_or_spool("a/3.bin", b"three"))
        self.assertEqual(sp.get("a/2.bin"), b"two")  # readable while spooled
        with self.assertRaises(ObjectExists):
            sp.put_or_spool("a/2.bin", b"again")
        self.assertEqual(sp.drain(), ([], ["a/2.bin", "a/3.bin"]))  # still down
        primary.down = False
        done, pending = sp.drain()
        self.assertEqual((done, pending), (["a/2.bin", "a/3.bin"], []))
        self.assertEqual(primary.get("a/2.bin"), b"two")
        self.assertTrue((primary.root / ".retention/a/2.bin.json").exists())

    def test_drain_after_crash_between_upload_and_unlink(self):
        primary = Flaky(tempfile.mkdtemp())
        sp = SpoolingStore(primary, tempfile.mkdtemp())
        primary.down = True
        sp.put_or_spool("k.bin", b"same")
        primary.down = False
        primary.put("k.bin", b"same")  # uploaded, spool file not yet removed
        self.assertEqual(sp.drain(), (["k.bin"], []))


if __name__ == "__main__":
    unittest.main()
