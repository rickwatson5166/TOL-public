"""TOL's own check of a timestamp authority's signature (no OpenSSL needed).

The main material is REAL answers saved from DigiCert, Sectigo and FreeTSA, plus tokens from a local OpenSSL authority.
The point of most tests is to attack it: every change to what the authority signed must stop it saying "verified"."""
import hashlib
import math
import secrets
import subprocess
import types
from pathlib import Path

import pytest

from tol_app import timestamp as ts
from tsa_fixture import LocalTSA, openssl_has_ts

FIX = Path(__file__).parent / "fixtures" / "timestamps"
ROOTS = ts.pem_to_der_list((FIX / "roots.pem").read_text(encoding="ascii"))
needs_openssl = pytest.mark.skipif(not openssl_has_ts(), reason="OpenSSL with `ts` support is not available")


def raw(name):
    return (FIX / name).read_bytes()


def verify(data, roots=ROOTS, **kw):
    return ts.verify_token(data, roots=roots, **kw)


# --- real tokens ---------------------------------------------------------------------------------
def test_a_real_digicert_answer_verifies_and_names_its_chain():
    r = verify(raw("digicert.tsr"))
    assert r.ok and r.status == "verified"
    assert r.signer.startswith("DigiCert SHA256 RSA4096 Timestamp Responder")
    assert r.root.startswith("DigiCert Trusted Root G4") and len(r.chain) == 3        # signer, its CA, the root


def test_a_real_sectigo_answer_verifies_through_a_four_certificate_chain():
    r = verify(raw("sectigo.tsr"))
    assert r.ok and r.root.startswith("USERTrust RSA Certification Authority") and len(r.chain) == 4


def test_an_ecdsa_authority_is_not_verified_and_says_why_instead_of_guessing():
    r = verify(raw("freetsa.tsr"), roots=ts.pem_to_der_list((FIX / "freetsa-root.pem").read_text(encoding="ascii")))
    assert r.status == "unverified" and "not handled" in r.reason and not r.ok


def test_the_wrong_roots_do_not_verify():
    sectigo_root_only = ROOTS[1:]
    r = verify(raw("digicert.tsr"), roots=sectigo_root_only)
    assert r.status == "unverified" and "does not chain" in r.reason
    r = verify(raw("digicert.tsr"), roots=[])
    assert r.status == "unverified" and "no trusted root" in r.reason


def test_an_unreadable_root_file_gives_not_verified_not_a_crash(tmp_path):
    r = ts.verify_token(raw("digicert.tsr"), cafile=str(tmp_path / "missing.pem"))
    assert r.status == "unverified" and "could not be read" in r.reason


def test_a_root_file_can_be_named():
    r = ts.verify_token(raw("digicert.tsr"), cafile=str(FIX / "roots.pem"))
    assert r.ok and r.roots_source.endswith("roots.pem")


def test_validity_is_judged_when_the_authority_stamped_not_now_and_not_at_another_time():
    assert verify(raw("digicert.tsr")).ok                                    # default: the time inside the token
    year_2100 = 4102444800
    year_2000 = 946684800
    for when in (year_2100, year_2000):
        r = verify(raw("digicert.tsr"), at=when)
        assert not r.ok and "not valid at the time" in r.reason


def test_reading_the_tokens_never_crashes_on_junk():
    for junk in (b"", b"\x30", bytes(range(256)), b"\x30\x80\x00\x00", raw("digicert.tsr")[:300], raw("digicert.tsr")[:-40]):
        assert not verify(junk).ok


# --- attacks on a real token -----------------------------------------------------------------------
def regions(data):
    """Byte ranges that matter: what the authority signed, the signature, the signed attributes, the signing certificate."""
    content, certs, signer, _signed = ts._signed_parts(data)
    sk = signer.children()
    attrs = next(k for k in sk if k.tag == 0xA0)
    signature = next(k for k in sk[3:] if k.tag == 0x04).body
    leaf = next(c for c in (ts.Cert(d) for d in certs) if not c.is_ca).der
    out = {}
    for name, blob in (("content", content), ("attributes", attrs.body), ("signature", signature), ("certificate", leaf)):
        at = data.find(blob)
        assert at >= 0, name
        out[name] = (at, at + len(blob))
    return out


@pytest.mark.parametrize("name", ["digicert.tsr", "sectigo.tsr"])
def test_flipping_any_byte_of_what_was_signed_or_the_signature_or_the_signer_is_never_verified(name):
    data = raw(name)
    assert verify(data).ok
    for part, (lo, hi) in regions(data).items():
        step = 1 if part != "certificate" else 3
        for i in range(lo, hi, step):
            bad = bytearray(data)
            bad[i] ^= 0x01
            assert not verify(bytes(bad)).ok, f"{part} byte {i - lo} was changed and it still verified"


def test_changing_the_stamped_time_or_the_fingerprint_is_reported_as_changed_contents():
    data = raw("digicert.tsr")
    info = ts.parse_response(data)
    for needle in (info["gen_time_raw"].encode(), bytes.fromhex(info["imprint_hex"])):
        at = data.find(needle)
        assert at >= 0
        bad = bytearray(data)
        bad[at] ^= 0x01
        r = verify(bytes(bad))
        assert r.status == "failed" and "contents" in r.reason


def test_swapping_in_another_authoritys_signature_fails():
    a, b = raw("digicert.tsr"), raw("sectigo.tsr")
    sig_a = next(k for k in ts._signed_parts(a)[2].children()[3:] if k.tag == 0x04).body
    sig_b = next(k for k in ts._signed_parts(b)[2].children()[3:] if k.tag == 0x04).body
    assert len(sig_a) == len(sig_b) == 512
    swapped = a.replace(sig_a, sig_b)
    assert swapped != a and not verify(swapped).ok


def test_a_token_whose_signing_certificate_is_removed_fails():
    data = raw("digicert.tsr")
    _c, certs, _s, _x = ts._signed_parts(data)
    leaf = next(c for c in certs if not ts.Cert(c).is_ca)
    broken = data.replace(leaf, b"\x30\x03\x02\x01\x01" + b"\x00" * (len(leaf) - 5))
    assert len(broken) == len(data) and not verify(broken).ok


# --- the RSA step on its own -----------------------------------------------------------------------
def _is_prime(n, rounds=24):
    if n < 4 or n % 2 == 0:
        return n in (2, 3)
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_prime(c):
            return c


@pytest.fixture(scope="module")
def key():
    """A throw-away 2048-bit RSA key made here in plain Python, so these tests need no openssl."""
    while True:
        p, q = _prime(1024), _prime(1024)
        e = 65537
        if p != q and math.gcd(e, (p - 1) * (q - 1)) == 1:
            return types.SimpleNamespace(n=p * q, e=e, d=pow(e, -1, (p - 1) * (q - 1)))


def sign(key, em):
    k = (key.n.bit_length() + 7) // 8
    return pow(int.from_bytes(em, "big"), key.d, key.n).to_bytes(k, "big")


def good_block(key, name, digest):
    k = (key.n.bit_length() + 7) // 8
    tail = ts._DIGEST_INFO[name] + digest
    return b"\x00\x01" + b"\xff" * (k - len(tail) - 3) + b"\x00" + tail


def test_rsa_accepts_a_correct_signature_and_nothing_loose(key):
    d = hashlib.sha256(b"x").digest()
    good = sign(key, good_block(key, "sha256", d))
    assert ts._rsa_verify(key, good, "sha256", d)
    assert not ts._rsa_verify(key, good, "sha256", hashlib.sha256(b"y").digest())          # another message
    assert not ts._rsa_verify(key, good[:-1], "sha256", d)                                  # wrong length
    assert not ts._rsa_verify(key, b"\x00" * len(good), "sha256", d)
    tail = ts._DIGEST_INFO["sha256"] + d
    k = (key.n.bit_length() + 7) // 8
    # garbage after the hash (the classic forgery shape): a block that is not EXACTLY the expected one
    sloppy = b"\x00\x01" + b"\xff" * 8 + b"\x00" + tail + b"\x00" * (k - len(tail) - 11)
    assert not ts._rsa_verify(key, sign(key, sloppy), "sha256", d)
    short_pad = b"\x00\x01" + b"\xff" * 4 + b"\x00" + tail + b"\xff" * (k - len(tail) - 7)
    assert not ts._rsa_verify(key, sign(key, short_pad), "sha256", d)
    wrong_type = b"\x00\x02" + good_block(key, "sha256", d)[2:]                             # block type 2
    assert not ts._rsa_verify(key, sign(key, wrong_type), "sha256", d)
    assert not ts._rsa_verify(key, (key.n + 1).to_bytes(k + 1, "big")[-k:], "sha256", d)    # not smaller than the modulus


def test_weak_keys_are_refused(key):
    weak = types.SimpleNamespace(n=(1 << 1023) + 1, e=65537)
    with pytest.raises(ts.Invalid):
        ts._rsa_verify(weak, b"\x00" * 128, "sha256", b"\x00" * 32)
    odd = types.SimpleNamespace(n=key.n, e=4)
    with pytest.raises(ts.Invalid):
        ts._rsa_verify(odd, b"\x00" * 256, "sha256", b"\x00" * 32)
    ec = types.SimpleNamespace(n=None, e=None)
    with pytest.raises(ts.Unsupported):
        ts._rsa_verify(ec, b"", "sha256", b"")


# --- a local authority and hand-made chains ---------------------------------------------------------
DIGEST = hashlib.sha256(b"manifest contents").digest()


@pytest.fixture(scope="module")
def tsa(tmp_path_factory):
    t = LocalTSA(tmp_path_factory.mktemp("tsa"))
    yield t
    t.close()


@needs_openssl
def test_tokens_from_a_local_authority_verify_against_its_own_root_and_not_against_nothing(tsa):
    got = ts.request_timestamp(DIGEST, tsa.url)
    root = ts.pem_to_der_list((tsa.dir / "ca.crt").read_text(encoding="ascii"))
    r = ts.verify_token(got["response"], roots=root)
    assert r.ok and r.signer == "Test TSA" and r.root == "Test Root CA"
    assert not ts.verify_token(got["response"], roots=ROOTS).ok                          # a real root list does not trust it
    other = got["response"].replace(DIGEST, hashlib.sha256(b"another").digest())
    assert not ts.verify_token(other, roots=root).ok                                      # fingerprint changed after signing


def make_chain(tmp, spec):
    """spec: list of (name, extensions) root first. Returns {name: DER}. Each is signed by the one before it."""
    def run(*a):
        subprocess.run(a, check=True, capture_output=True)
    made, prev = {}, None
    for name, ext in spec:
        key, crt = tmp / f"{name}.key", tmp / f"{name}.crt"
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(tmp / f"{name}.csr"),
            "-subj", f"/CN={name}")
        (tmp / f"{name}.ext").write_text(ext + "\n", encoding="utf-8")
        if prev is None:
            run("openssl", "x509", "-req", "-in", str(tmp / f"{name}.csr"), "-signkey", str(key), "-out", str(crt), "-days", "30",
                "-extfile", str(tmp / f"{name}.ext"))
        else:
            run("openssl", "x509", "-req", "-in", str(tmp / f"{name}.csr"), "-CA", str(tmp / f"{prev}.crt"),
                "-CAkey", str(tmp / f"{prev}.key"), "-CAcreateserial", "-out", str(crt), "-days", "30",
                "-extfile", str(tmp / f"{name}.ext"))
        made[name] = ts.pem_to_der_list(crt.read_text(encoding="ascii"))[0]
        prev = name
    return made


CA = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign"
LEAF = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping"


@needs_openssl
def test_chain_rules(tmp_path):
    c = make_chain(tmp_path, [("root", CA), ("mid", CA), ("leaf", LEAF)])
    now = ts.calendar.timegm(ts.time.gmtime()) + 5                     # after the certificates were made
    root, mid, leaf = (ts.Cert(c[n]) for n in ("root", "mid", "leaf"))
    assert [x.der for x in ts.build_chain(leaf, [mid], [root], now)] == [c["leaf"], c["mid"], c["root"]]
    assert ts.build_chain(leaf, [], [root], now) is None                                  # the middle certificate is missing
    assert ts.build_chain(leaf, [mid], [], now) is None                                   # no trusted root
    assert ts.build_chain(leaf, [mid], [root], now + 100 * 86400) is None                 # all expired by then
    assert ts._leaf_problem(leaf, now) == ""

    not_ca = make_chain(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path,
                        [("root", CA), ("mid", "basicConstraints=CA:FALSE\nkeyUsage=critical,keyCertSign"), ("leaf", LEAF)])
    r, m, lf = (ts.Cert(not_ca[n]) for n in ("root", "mid", "leaf"))
    assert ts.build_chain(lf, [m], [r], now) is None                                      # an intermediate that is not a CA

    (tmp_path / "y").mkdir()
    short = make_chain(tmp_path / "y", [("root", CA), ("mid", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign"),
                                        ("mid2", CA), ("leaf", LEAF)])
    r, m, m2, lf = (ts.Cert(short[n]) for n in ("root", "mid", "mid2", "leaf"))
    assert ts.build_chain(lf, [m2, m], [r], now) is None                                  # the path-length limit is honoured

    (tmp_path / "z").mkdir()
    bad_leaf = make_chain(tmp_path / "z", [("root", CA), ("leaf", "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth")])
    problem = ts._leaf_problem(ts.Cert(bad_leaf["leaf"]), now)
    assert "time stamping" in problem
    (tmp_path / "w").mkdir()
    unknown = make_chain(tmp_path / "w", [("root", CA), ("leaf", LEAF + "\nnameConstraints=critical,permitted;DNS:example.com")])
    assert "critical extension" in ts._leaf_problem(ts.Cert(unknown["leaf"]), now)
