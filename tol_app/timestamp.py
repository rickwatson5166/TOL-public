"""Trusted timestamps (RFC 3161): an independent authority signs "this fingerprint existed at this time".

What is sent: a 32-byte SHA-256 fingerprint of the evidence package's manifest, nothing else. What comes back: a
signed token naming the time. After that, the time of the package no longer depends on this device's clock.

This module is standard library only, on purpose: the packaged Mac app cannot load the `cryptography` library, and an
evidence package must be checkable on a computer with nothing installed but Python.
  * it BUILDS the request, SENDS it, and READS the answer's structure (status, time, fingerprint, nonce, policy,
    certificates), and refuses an answer that is not for our fingerprint or our nonce;
  * `verify_token` CHECKS the authority's signature and certificate chain itself (RSA, SHA-256 or stronger), against a
    list of trusted root certificates (the computer's own list, or a file you name). It does not check certificate
    revocation. Where it cannot decide (an algorithm it does not handle, a root it does not trust) it says "not
    verified", never "verified"; OpenSSL (`openssl ts -verify`) remains a second route when it is installed.

The same file is copied into every evidence package (as tol_timestamp.py) so verify.py can read tokens without TOL.
"""
import base64
import calendar
import hashlib
import hmac
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.request
from typing import List, Optional

DEFAULT_TSA = "http://timestamp.digicert.com"
FALLBACK_TSAS = ("http://timestamp.sectigo.com", "https://freetsa.org/tsr")
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
CONTENT_TYPE_REQ = "application/timestamp-query"
GRANTED = (0, 1)                      # PKIStatus granted / grantedWithMods
_SHA256_ALG_DER = bytes.fromhex("300d06096086480165030402010500")


class TimestampFailed(RuntimeError):
    """The authority could not be asked, refused, or answered something that is not for our fingerprint."""


# --- DER building -----------------------------------------------------------------
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")        # leading 00 keeps it positive
    return _tlv(0x02, b)


def build_request(digest: bytes, nonce: int) -> bytes:
    """TimeStampReq for a SHA-256 digest, asking the authority to include its certificates (certReq TRUE)."""
    if len(digest) != 32:
        raise ValueError("expected a SHA-256 digest (32 bytes)")
    imprint = _tlv(0x30, _SHA256_ALG_DER + _tlv(0x04, digest))
    return _tlv(0x30, _int(1) + imprint + _int(nonce) + _tlv(0x01, b"\xff"))


# --- DER / BER reading --------------------------------------------------------------
class Node:
    __slots__ = ("tag", "body", "children_cache")

    def __init__(self, tag: int, body: bytes):
        self.tag, self.body, self.children_cache = tag, body, None

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> List["Node"]:
        if self.children_cache is None:
            self.children_cache = _read_all(self.body)
        return self.children_cache


def _read_one(buf: bytes, pos: int):
    """Read one TLV at pos. Handles definite lengths and BER indefinite lengths (some authorities use them)."""
    if pos + 2 > len(buf):
        raise ValueError("truncated")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("high tag numbers are not used here")
    pos += 1
    first = buf[pos]
    pos += 1
    if first == 0x80:                                             # indefinite: runs until 00 00
        if not tag & 0x20:
            raise ValueError("indefinite length on a primitive")
        start, kids = pos, []
        while True:
            if buf[pos:pos + 2] == b"\x00\x00":
                return Node(tag, buf[start:pos]), pos + 2
            child, pos = _read_one(buf, pos)
            kids.append(child)
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0 or k > 4 or pos + k > len(buf):
            raise ValueError("bad length")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        raise ValueError("truncated")
    return Node(tag, buf[pos:pos + n]), pos + n


def _read_all(buf: bytes) -> List[Node]:
    out, pos = [], 0
    while pos < len(buf):
        node, pos = _read_one(buf, pos)
        out.append(node)
    return out


def parse_der(buf: bytes) -> Node:
    node, end = _read_one(buf, 0)
    if end != len(buf):
        raise ValueError("trailing data")
    return node


def _oid(body: bytes) -> str:
    parts, val = [], 0
    for i, b in enumerate(body):
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            if not parts:
                parts += [min(val // 40, 2), val - 40 * min(val // 40, 2)]
            else:
                parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _to_int(body: bytes) -> int:
    return int.from_bytes(body, "big", signed=True)


def _pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"


def _walk_to_tstinfo(signed_data: Node):
    """SignedData -> (TSTInfo Node, [certificate DER bytes])."""
    kids = signed_data.children()
    encap = next(k for k in kids if k.tag == 0x30 and k.children() and k.children()[0].tag == 0x06
                 and _oid(k.children()[0].body) == OID_TSTINFO)
    explicit = encap.children()[1]                                 # [0] EXPLICIT
    octets = explicit.children()[0]
    if octets.tag == 0x24:                                         # BER constructed OCTET STRING: join the pieces
        content = b"".join(c.body for c in octets.children())
    else:
        content = octets.body
    certs = []
    for k in kids:
        if k.tag == 0xA0:                                          # [0] IMPLICIT SET OF Certificate
            for c in k.children():
                certs.append(_tlv(c.tag, c.body))
    return parse_der(content), certs


def parse_response(raw: bytes) -> dict:
    """Read a TimeStampResp (or a bare token). Returns the facts; checks nothing cryptographic.

    {"status": int, "granted": bool, "gen_time": "2026-10-05T19:58:40Z" (UTC), "gen_time_raw", "imprint_hex",
     "hash_oid", "nonce": int|None, "serial": int, "policy": oid, "certs_der": [bytes], "tsa_name": str|None}"""
    try:
        top = parse_der(raw)
        kids = top.children()
        if kids and kids[0].tag == 0x30 and kids[0].children() and kids[0].children()[0].tag == 0x02:
            status = _to_int(kids[0].children()[0].body)             # TimeStampResp
            token = kids[1] if len(kids) > 1 else None
        else:
            status, token = 0, top                                   # a bare TimeStampToken (ContentInfo)
        info = {"status": status, "granted": status in GRANTED}
        if token is None:
            return info
        signed = token.children()[1].children()[0]                   # ContentInfo -> [0] EXPLICIT -> SignedData
        tst, certs = _walk_to_tstinfo(signed)
        f = tst.children()
        mi = f[2].children()
        gen_raw = f[4].body.decode("ascii")
        nonce, tsa_name = None, None
        for extra in f[5:]:
            if extra.tag == 0x02:
                nonce = _to_int(extra.body)
            elif extra.tag == 0xA0:
                tsa_name = extra.body.decode("latin-1", "replace")
        info.update({
            "policy": _oid(f[1].body), "hash_oid": _oid(mi[0].children()[0].body), "imprint_hex": mi[1].body.hex(),
            "serial": _to_int(f[3].body), "gen_time_raw": gen_raw, "gen_time": _iso(gen_raw), "nonce": nonce,
            "tsa_name": tsa_name, "certs_der": certs})
        return info
    except (ValueError, IndexError, StopIteration, UnicodeDecodeError) as e:
        raise TimestampFailed(f"the answer could not be read as a timestamp ({type(e).__name__}: {e})") from e


def _iso(gen: str) -> str:
    d = gen.rstrip("Z").split(".")[0]
    if len(d) != 14 or not d.isdigit():
        raise ValueError(f"unexpected time format {gen!r}")
    return f"{d[0:4]}-{d[4:6]}-{d[6:8]}T{d[8:10]}:{d[10:12]}:{d[12:14]}Z"


def certs_pem(info: dict) -> str:
    return "".join(_pem(c) for c in info.get("certs_der", []))


# --- asking an authority ---------------------------------------------------------------
def _context():
    try:
        from .netutil import ssl_context
        return ssl_context()
    except ImportError:                                               # running inside an evidence package
        return ssl.create_default_context()


def request_timestamp(digest: bytes, url: str = DEFAULT_TSA, timeout: float = 15, opener=None) -> dict:
    """Ask `url` to timestamp `digest`. Returns {"url", "request": bytes, "response": bytes, "info": parsed, "nonce"}.
    Raises TimestampFailed with the reason on any problem, including an answer that is not for our fingerprint."""
    nonce = secrets.randbits(63) | 1
    req_bytes = build_request(digest, nonce)
    req = urllib.request.Request(url, data=req_bytes, headers={
        "Content-Type": CONTENT_TYPE_REQ, "Accept": "application/timestamp-reply"})
    try:
        if opener is not None:
            raw = opener(req, timeout)
        else:
            with urllib.request.urlopen(req, timeout=timeout, context=_context()) as r:
                raw = r.read(1 << 20)
    except urllib.error.HTTPError as e:
        raise TimestampFailed(f"the authority answered HTTP {e.code}") from e
    except Exception as e:                                            # noqa: BLE001 - report whatever happened
        raise TimestampFailed(f"{type(e).__name__}: {getattr(e, 'reason', None) or e}") from e
    info = parse_response(raw)
    check_answer(info, digest, nonce)
    return {"url": url, "request": req_bytes, "response": raw, "info": info, "nonce": nonce}


def check_answer(info: dict, digest: bytes, nonce: Optional[int]):
    """Refuse anything that is not a granted timestamp for exactly this fingerprint (and nonce, if we sent one)."""
    if not info.get("granted"):
        raise TimestampFailed(f"the authority refused (status {info.get('status')})")
    if "imprint_hex" not in info:
        raise TimestampFailed("the answer contained no timestamp")
    if info["hash_oid"] != OID_SHA256 or info["imprint_hex"] != digest.hex():
        raise TimestampFailed("the timestamp is for a different fingerprint than the one we sent")
    if nonce is not None and info.get("nonce") != nonce:
        raise TimestampFailed("the answer does not repeat our one-time number (replayed or wrong answer)")


def sha256_file(path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()


# ===================================================================================================
# Verifying the authority's signature and certificate chain (RFC 3161 token = CMS SignedData, RFC 5652)
# ===================================================================================================
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"          # ESS signingCertificate (SHA-1 certificate hash)
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"       # ESS signingCertificateV2
OID_RSA = "1.2.840.113549.1.1.1"
OID_EKU_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
HASHES = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
SIG_HASH = {"1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512"}
_DIGEST_INFO = {                                          # DER prefix of DigestInfo, then the hash itself
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440")}
_IGNORED_CRITICAL = {"2.5.29.14", "2.5.29.35", "2.5.29.32", "2.5.29.31", "1.3.6.1.5.5.7.1.1", "2.5.29.17"}
MIN_RSA_BITS = 2048
MAX_CHAIN = 6


class Unsupported(Exception):
    """Something this checker does not handle: the answer is "not verified", never "verified"."""


class Invalid(Exception):
    """The token or a certificate is definitely wrong."""


class VerifyResult:
    def __init__(self, status: str, reason: str = "", signer: str = "", root: str = "", chain=None, roots_source: str = ""):
        self.status, self.reason, self.signer, self.root = status, reason, signer, root       # "verified" | "failed" | "unverified"
        self.chain, self.roots_source = chain or [], roots_source

    @property
    def ok(self) -> bool:
        return self.status == "verified"

    def __repr__(self):
        return f"VerifyResult({self.status!r}, {self.reason!r})"


def _raw_items(buf: bytes):
    """Split a DER body into [(tag, whole_tlv_bytes, body_bytes)]. Definite lengths only, as DER requires."""
    out, pos = [], 0
    while pos < len(buf):
        start = pos
        tag = buf[pos]
        pos += 1
        if tag & 0x1F == 0x1F or pos >= len(buf):
            raise ValueError("bad tag")
        first = buf[pos]
        pos += 1
        if first < 0x80:
            n = first
        elif first == 0x80:
            raise ValueError("indefinite length is not allowed in a certificate")
        else:
            k = first & 0x7F
            if k > 4 or pos + k > len(buf):
                raise ValueError("bad length")
            n = int.from_bytes(buf[pos:pos + k], "big")
            pos += k
        if pos + n > len(buf):
            raise ValueError("truncated")
        out.append((tag, buf[start:pos + n], buf[pos:pos + n]))
        pos += n
    return out


def _time_value(tag: int, body: bytes) -> int:
    t = body.decode("ascii")
    if not t.endswith("Z"):
        raise ValueError("time without Z")
    t = t[:-1]
    if tag == 0x17 and len(t) == 12 and t.isdigit():
        yy = int(t[:2])
        t = ("19" if yy >= 50 else "20") + t
    elif not (tag == 0x18 and len(t) == 14 and t.isdigit()):
        raise ValueError("unexpected time format")
    return calendar.timegm(time.strptime(t, "%Y%m%d%H%M%S"))


def _decode_string(tag: int, body: bytes) -> str:
    if tag == 0x1E:
        return body.decode("utf-16-be", "replace")
    return body.decode("utf-8" if tag == 0x0C else "latin-1", "replace")


def _name_text(name_raw: bytes) -> str:
    """Best-effort 'CN, O' for display only; comparisons always use the raw bytes."""
    want, found = {"2.5.4.3": "CN", "2.5.4.10": "O"}, {}
    try:
        for _t, _r, rdn in _raw_items(_raw_items(name_raw)[0][2]):
            for _t2, _r2, atv in _raw_items(rdn):
                kids = _raw_items(atv)
                oid = _oid(kids[0][2])
                if oid in want and want[oid] not in found:
                    found[want[oid]] = _decode_string(kids[1][0], kids[1][2])
    except (ValueError, IndexError):
        return "(unreadable name)"
    return ", ".join(found[k] for k in ("CN", "O") if k in found) or "(unnamed)"


class Cert:
    """The parts of an X.509 certificate this checker needs. Parsing is strict: anything odd raises."""

    def __init__(self, der: bytes):
        self.der = der
        top = _raw_items(der)
        if len(top) != 1 or top[0][0] != 0x30:
            raise ValueError("not a certificate")
        tbs, sigalg, sigbits = _raw_items(top[0][2])[:3]
        self.tbs_raw = tbs[1]
        self.sig_alg_raw = sigalg[1]
        self.sig_alg = _oid(_raw_items(sigalg[2])[0][2])
        if sigbits[0] != 0x03 or sigbits[2][:1] != b"\x00":
            raise ValueError("bad signature field")
        self.signature = sigbits[2][1:]
        f = _raw_items(tbs[2])
        i = 1 if f[0][0] == 0xA0 else 0
        self.serial = _to_int(f[i][2])
        if f[i + 1][1] != sigalg[1]:
            raise ValueError("the two signature algorithm fields differ")
        self.issuer_raw, self.subject_raw = f[i + 2][1], f[i + 4][1]
        nb, na = _raw_items(f[i + 3][2])[:2]
        self.not_before, self.not_after = _time_value(nb[0], nb[2]), _time_value(na[0], na[2])
        self.n = self.e = None
        spki = _raw_items(f[i + 5][2])
        if _oid(_raw_items(spki[0][2])[0][2]) == OID_RSA and spki[1][2][:1] == b"\x00":
            rsa = _raw_items(_raw_items(spki[1][2][1:])[0][2])
            self.n, self.e = int.from_bytes(rsa[0][2], "big"), int.from_bytes(rsa[1][2], "big")
        self.is_ca, self.path_len, self.key_usage, self.eku, self.eku_critical = None, None, None, None, False
        self.ski, self.unknown_critical = None, []
        for tag, _r, body in f[i + 6:]:
            if tag != 0xA3:
                continue
            for _t, _r2, ext in _raw_items(_raw_items(body)[0][2]):
                parts = _raw_items(ext)
                oid = _oid(parts[0][2])
                critical = len(parts) == 3 and parts[1][2] != b"\x00"
                value = parts[-1][2]
                if oid == "2.5.29.19":                                       # basicConstraints
                    seq = _raw_items(_raw_items(value)[0][2])
                    self.is_ca = bool(seq and seq[0][0] == 0x01 and seq[0][2] != b"\x00")
                    ints = [x for x in seq if x[0] == 0x02]
                    self.path_len = int.from_bytes(ints[0][2], "big") if ints else None
                elif oid == "2.5.29.15":                                     # keyUsage
                    bits = _raw_items(value)[0][2]
                    self.key_usage = bits[1] if len(bits) > 1 else 0
                elif oid == "2.5.29.37":                                     # extendedKeyUsage
                    self.eku = {_oid(x[2]) for x in _raw_items(_raw_items(value)[0][2])}
                    self.eku_critical = critical
                elif oid == "2.5.29.14":                                     # subjectKeyIdentifier
                    self.ski = _raw_items(value)[0][2]
                elif critical and oid not in _IGNORED_CRITICAL:
                    self.unknown_critical.append(oid)

    def valid_at(self, at: int) -> bool:
        return self.not_before <= at <= self.not_after


def _rsa_verify(cert: "Cert", signature: bytes, hash_name: str, digest: bytes) -> bool:
    """RSA PKCS#1 v1.5. The expected block is BUILT and compared whole, so no padding is ever 'parsed' leniently."""
    n, e = cert.n, cert.e
    if n is None or e is None:
        raise Unsupported("the signing key is not an RSA key")
    if n.bit_length() < MIN_RSA_BITS or e < 3 or e % 2 == 0:
        raise Invalid("the signing key is too weak or malformed")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    tail = _DIGEST_INFO[hash_name] + digest
    pad = k - len(tail) - 3
    if pad < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * pad + b"\x00" + tail
    return hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), expected)


def _cert_signed_by(cert: "Cert", issuer: "Cert") -> bool:
    name = SIG_HASH.get(cert.sig_alg)
    if name is None:
        raise Unsupported(f"certificate signature algorithm {cert.sig_alg} is not handled (SHA-1 and others are refused)")
    return _rsa_verify(issuer, cert.signature, name, hashlib.new(name, cert.tbs_raw).digest())


def _ca_usable(c: "Cert", below: int, at: int) -> bool:
    if not c.valid_at(at) or c.is_ca is not True or c.unknown_critical:
        return False
    if c.key_usage is not None and not c.key_usage & 0x04:                  # keyCertSign
        return False
    return c.path_len is None or below <= c.path_len


def _leaf_problem(c: "Cert", at: int) -> str:
    if not c.valid_at(at):
        return "the signing certificate was not valid at the time the authority stamped"
    if c.is_ca is True:
        return "the signing certificate is a CA certificate"
    if c.unknown_critical:
        return "the signing certificate has a critical extension this checker does not understand"
    if not c.eku or OID_EKU_TIMESTAMPING not in c.eku or not c.eku_critical:
        return "the signing certificate is not marked (critically) for time stamping"
    if c.key_usage is not None and not c.key_usage & 0xC0:                  # digitalSignature or nonRepudiation
        return "the signing certificate's key usage does not allow signing"
    return ""


def build_chain(leaf: "Cert", others, anchors, at: int):
    """A path leaf -> ... -> trusted root, or None. Tries trusted roots first, then the certificates sent with the token."""
    by_subject = {}
    for c in others:
        by_subject.setdefault(c.subject_raw, []).append(c)
    anchor_by_subject = {}
    for c in anchors:
        anchor_by_subject.setdefault(c.subject_raw, []).append(c)

    def walk(cert, chain):
        below = len(chain) - 1                                              # CA certificates already between us and the leaf
        for a in anchor_by_subject.get(cert.issuer_raw, []):
            if _ca_usable(a, below, at) and _cert_signed_by(cert, a):
                return chain + [a]
        if len(chain) >= MAX_CHAIN:
            return None
        for c in by_subject.get(cert.issuer_raw, []):
            if any(c.der == x.der for x in chain) or not _ca_usable(c, below, at):
                continue
            if _cert_signed_by(cert, c):
                found = walk(c, chain + [c])
                if found:
                    return found
        return None

    return walk(leaf, [leaf])


# --- trusted roots ---------------------------------------------------------------------------
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
ROOT_FILES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
              "/opt/homebrew/etc/openssl@3/cert.pem", "/usr/local/etc/openssl@3/cert.pem")


def pem_to_der_list(text: str):
    out = []
    for m in _PEM_RE.finditer(text):
        try:
            out.append(base64.b64decode("".join(m.group(1).split())))
        except ValueError:
            pass
    return out


def load_trust_roots(cafile=None):
    """(list of certificate DER bytes, where they came from). `cafile` is a PEM bundle; otherwise this computer's own list."""
    if cafile:
        with open(cafile, "r", encoding="ascii", errors="ignore") as f:
            return pem_to_der_list(f.read()), str(cafile)
    env = os.environ.get("SSL_CERT_FILE")
    if env and os.path.isfile(env):
        with open(env, "r", encoding="ascii", errors="ignore") as f:
            return pem_to_der_list(f.read()), env
    if hasattr(ssl, "enum_certificates"):                                      # Windows: the system certificate store
        try:
            ders = [c for store in ("ROOT", "CA") for c, enc, _t in ssl.enum_certificates(store) if enc == "x509_asn"]
            if ders:
                return ders, "the Windows certificate store"
        except OSError:
            pass
    candidates = list(ROOT_FILES)
    paths = ssl.get_default_verify_paths()
    candidates += [x for x in (paths.cafile, paths.openssl_cafile) if x]
    for c in candidates:
        if os.path.isfile(c):
            with open(c, "r", encoding="ascii", errors="ignore") as f:
                return pem_to_der_list(f.read()), c
    return [], "no trusted root list was found"


# --- the token ---------------------------------------------------------------------------------
def _signed_parts(raw: bytes):
    """(eContent bytes, [certificate DER], signer-info Node, signed-data Node)."""
    top = parse_der(raw)
    kids = top.children()
    token = kids[1] if kids and kids[0].tag == 0x30 and kids[0].children() and kids[0].children()[0].tag == 0x02 else top
    signed = token.children()[1].children()[0]
    skids = signed.children()
    encap = next(k for k in skids if k.tag == 0x30 and k.children() and k.children()[0].tag == 0x06
                 and _oid(k.children()[0].body) == OID_TSTINFO)
    octets = encap.children()[1].children()[0]
    content = b"".join(c.body for c in octets.children()) if octets.tag == 0x24 else octets.body
    certs = [_tlv(c.tag, c.body) for k in skids if k.tag == 0xA0 for c in k.children()]
    signer_infos = [k for k in skids if k.tag == 0x31][-1].children()
    if len(signer_infos) != 1:
        raise Invalid("expected exactly one signature on the timestamp")
    return content, certs, signer_infos[0], signed


def _attribute_values(attrs_node):
    out = {}
    for a in attrs_node.children():
        kids = a.children()
        out.setdefault(_oid(kids[0].body), []).append(kids[1].children())
    return out


def verify_token(raw: bytes, cafile=None, roots=None, extra_certs=(), at=None) -> VerifyResult:
    """Check the authority's signature on a timestamp answer and that its certificate chains to a trusted root.

    `raw` is the saved answer (or a bare token). `roots` is a list of certificate DER bytes (default: `cafile`, else this
    computer's own list). `at` (epoch seconds) is the moment to judge validity at; default: the time the token says.
    Certificate revocation is NOT checked. Returns "verified", "failed" (definitely wrong) or "unverified" (could not
    decide: an unsupported algorithm, or no path to a trusted root)."""
    try:
        return _verify_token(raw, cafile, roots, extra_certs, at)
    except Invalid as e:
        return VerifyResult("failed", str(e))
    except Unsupported as e:
        return VerifyResult("unverified", str(e))
    except OSError as e:                                                    # the root file could not be read
        return VerifyResult("unverified", f"the trusted root list could not be read ({e.strerror or type(e).__name__})")
    except (ValueError, IndexError, StopIteration, KeyError, UnicodeDecodeError) as e:
        return VerifyResult("failed", f"the timestamp could not be read ({type(e).__name__}: {e})")


def _verify_token(raw, cafile, roots, extra_certs, at) -> VerifyResult:
    content, token_certs, signer, _signed = _signed_parts(raw)
    sk = signer.children()
    sid, digest_alg = sk[1], sk[2]
    attrs = next((k for k in sk if k.tag == 0xA0), None)
    if attrs is None:
        raise Invalid("the signature carries no signed attributes")
    sig_alg = _oid(next(k for k in sk[3:] if k.tag == 0x30).children()[0].body)
    signature = next(k for k in sk[3:] if k.tag == 0x04).body
    hash_name = HASHES.get(_oid(digest_alg.children()[0].body))
    if hash_name is None:
        raise Unsupported("the timestamp uses a hash algorithm this checker does not accept (SHA-1 and others are refused)")
    if sig_alg != OID_RSA and SIG_HASH.get(sig_alg) != hash_name:
        raise Unsupported(f"signature algorithm {sig_alg} is not handled (only RSA with SHA-2)")

    # 1. the signed attributes cover exactly this content
    values = _attribute_values(attrs)
    ctype = values.get(OID_CONTENT_TYPE, [[]])[0]
    if not ctype or _oid(ctype[0].body) != OID_TSTINFO:
        raise Invalid("the signed content type is not a timestamp")
    digests = values.get(OID_MESSAGE_DIGEST, [[]])[0]
    if not digests or not hmac.compare_digest(digests[0].body, hashlib.new(hash_name, content).digest()):
        raise Invalid("the signature does not cover this timestamp's contents (they were changed)")

    # 2. which certificate signed
    certs = []
    for der in list(token_certs) + list(extra_certs):
        try:
            certs.append(Cert(der))
        except (ValueError, IndexError):
            continue                                                       # a certificate we cannot read is simply not used
    if sid.tag == 0x30:                                                    # issuer and serial number
        issuer_raw, serial = sid.children()[0], sid.children()[1]
        want = [c for c in certs if c.issuer_raw == _tlv(issuer_raw.tag, issuer_raw.body) and c.serial == _to_int(serial.body)]
    elif sid.tag == 0x80:                                                  # subject key identifier
        want = [c for c in certs if c.ski == sid.body]
    else:
        raise Unsupported("unrecognised way of naming the signing certificate")
    if not want:
        raise Invalid("the signing certificate is not included with the timestamp")
    leaf = want[0]

    # 3. the signing certificate is the one the signed attributes name (ESS signingCertificate)
    named = values.get(OID_SIGNING_CERT_V2) or values.get(OID_SIGNING_CERT)
    if not named:
        raise Invalid("the signature does not name its certificate")
    ess_certs = named[0][0].children()[0].children()
    first = ess_certs[0].children()
    if values.get(OID_SIGNING_CERT_V2):
        alg = HASHES.get(_oid(first[0].children()[0].body)) if first[0].tag == 0x30 else "sha256"
        cert_hash = (first[1] if first[0].tag == 0x30 else first[0]).body
    else:
        alg, cert_hash = "sha1", first[0].body
    if alg is None or not hmac.compare_digest(hashlib.new(alg, leaf.der).digest(), cert_hash):
        raise Invalid("the signing certificate is not the one the signature names")

    # 4. the signature itself, over the DER of the signed attributes
    signed_bytes = _tlv(0x31, attrs.body)
    if not _rsa_verify(leaf, signature, hash_name, hashlib.new(hash_name, signed_bytes).digest()):
        raise Invalid("the signature is not valid")

    # 5. the certificate chain, judged at the time the authority stamped
    gen = parse_response(raw).get("gen_time")
    when = at if at is not None else calendar.timegm(time.strptime(gen, "%Y-%m-%dT%H:%M:%SZ"))
    problem = _leaf_problem(leaf, when)
    if problem:
        raise Invalid(problem)
    if roots is None:
        roots, source = load_trust_roots(cafile)
    else:
        source = "the supplied roots"
    anchors = []
    for der in roots:
        try:
            anchors.append(Cert(der))
        except (ValueError, IndexError):
            continue
    if not anchors:
        return VerifyResult("unverified", f"no trusted root certificates were available ({source})", roots_source=source,
                            signer=_name_text(leaf.subject_raw))
    chain = build_chain(leaf, [c for c in certs if c is not leaf], anchors, when)
    names = [_name_text(c.subject_raw) for c in chain] if chain else []
    if chain is None:
        return VerifyResult("unverified", "the signature is valid, but its certificate does not chain to a root in the trusted list "
                            f"({len(anchors)} roots from {source})", signer=_name_text(leaf.subject_raw), roots_source=source)
    return VerifyResult("verified", signer=names[0], root=names[-1], chain=names, roots_source=source)
