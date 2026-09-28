"""Minimal ASN.1 DER encoder / decoder for RFC 3161 and CMS.

Only what timestamping needs: definite-length TLVs, INTEGER, OID, OCTET
STRING, BOOLEAN, NULL, GeneralizedTime, SEQUENCE / SET and context tags.
Decoding keeps each element's raw bytes so signatures can be checked over
exactly what was signed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID = 1, 2, 3, 4, 5, 6
UTF8_STRING, SEQUENCE, SET, PRINTABLE_STRING, UTC_TIME, GENERALIZED_TIME = 12, 16, 17, 19, 23, 24


class DERError(ValueError):
    pass


@dataclass
class Node:
    cls: int
    constructed: bool
    tag: int
    content: bytes
    raw: bytes
    _children: list["Node"] | None = field(default=None, repr=False)

    @property
    def children(self) -> list["Node"]:
        if not self.constructed:
            raise DERError("primitive element has no children")
        if self._children is None:
            self._children = decode_all(self.content)
        return self._children

    def is_(self, tag: int, cls: int = UNIVERSAL) -> bool:
        return self.cls == cls and self.tag == tag

    def expect(self, tag: int, cls: int = UNIVERSAL) -> "Node":
        if not self.is_(tag, cls):
            raise DERError(f"expected tag {cls}/{tag}, found {self.cls}/{self.tag}")
        return self

    # -- value accessors -------------------------------------------------------

    def integer(self) -> int:
        self.expect(INTEGER)
        return int.from_bytes(self.content, "big", signed=True)

    def oid(self) -> str:
        self.expect(OID)
        return decode_oid(self.content)

    def octets(self) -> bytes:
        self.expect(OCTET_STRING)
        return self.content

    def boolean(self) -> bool:
        self.expect(BOOLEAN)
        return self.content != b"\x00"

    def generalized_time(self) -> datetime:
        self.expect(GENERALIZED_TIME)
        return parse_generalized_time(self.content.decode("ascii"))


def decode(data: bytes, offset: int = 0) -> tuple[Node, int]:
    start = offset
    if offset + 2 > len(data):
        raise DERError("truncated element")
    b = data[offset]
    offset += 1
    cls, constructed, tag = b >> 6, bool(b & 0x20), b & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            if offset >= len(data):
                raise DERError("truncated tag")
            c = data[offset]
            offset += 1
            tag = tag << 7 | c & 0x7F
            if not c & 0x80:
                break
    if offset >= len(data):
        raise DERError("truncated length")
    ln = data[offset]
    offset += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or nbytes > 4:
            raise DERError("unsupported length encoding")
        ln = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    end = offset + ln
    if end > len(data):
        raise DERError("element runs past end of data")
    return Node(cls, constructed, tag, data[offset:end], data[start:end]), end


def decode_all(data: bytes) -> list[Node]:
    out, off = [], 0
    while off < len(data):
        node, off = decode(data, off)
        out.append(node)
    return out


def parse(data: bytes) -> Node:
    node, end = decode(data)
    if end != len(data):
        raise DERError("trailing data after element")
    return node


def decode_oid(content: bytes) -> str:
    if not content:
        raise DERError("empty OID")
    arcs, val = [], 0
    for b in content:
        val = val << 7 | b & 0x7F
        if not b & 0x80:
            arcs.append(val)
            val = 0
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def parse_generalized_time(s: str) -> datetime:
    if not s.endswith("Z"):
        raise DERError("GeneralizedTime must be UTC (Z)")
    body = s[:-1]
    main, _, frac = body.partition(".")
    dt = datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    return dt


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(first_byte: int, content: bytes) -> bytes:
    return bytes([first_byte]) + _len(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))  # DER: SET OF sorted by encoding


def integer(n: int) -> bytes:
    length = max(1, (n.bit_length() + 8) // 8)
    return tlv(0x02, n.to_bytes(length, "big", signed=True))


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def null() -> bytes:
    return b"\x05\x00"


def octet_string(b: bytes) -> bytes:
    return tlv(0x04, b)


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytearray()
    for i, a in enumerate([arcs[0] * 40 + arcs[1]] + arcs[2:]):
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | a & 0x7F)
            a >>= 7
        body.extend(reversed(chunk))
    return tlv(0x06, bytes(body))


def generalized_time(dt: datetime) -> bytes:
    dt = dt.astimezone(timezone.utc)
    s = dt.strftime("%Y%m%d%H%M%S")
    if dt.microsecond:
        s += "." + f"{dt.microsecond:06d}".rstrip("0")
    return tlv(0x18, (s + "Z").encode("ascii"))


def explicit(tag: int, content: bytes) -> bytes:
    """[tag] EXPLICIT wrapping of an already-encoded element."""
    return tlv(0xA0 | tag, content)


def implicit_constructed(tag: int, content: bytes) -> bytes:
    """[tag] IMPLICIT for a constructed type, given the inner content bytes."""
    return tlv(0xA0 | tag, content)


def algorithm_identifier(oid_: str, params_null: bool = True) -> bytes:
    return seq(oid(oid_), null()) if params_null else seq(oid(oid_))
