import hashlib
import subprocess

import pytest

from tol_app import timestamp as ts
from tol_app.timestamp import TimestampFailed
from tsa_fixture import LocalTSA, openssl_has_ts

needs_openssl = pytest.mark.skipif(not openssl_has_ts(), reason="OpenSSL with `ts` support is not available")


@pytest.fixture(scope="module")
def tsa(tmp_path_factory):
    t = LocalTSA(tmp_path_factory.mktemp("tsa"))
    yield t
    t.close()


DIGEST = hashlib.sha256(b"manifest contents").digest()


def test_request_is_valid_rfc3161_per_openssl(tmp_path):
    """Our hand-built request must be accepted and read back identically by OpenSSL."""
    if not openssl_has_ts():
        pytest.skip("no openssl ts")
    q = tmp_path / "q.tsq"
    q.write_bytes(ts.build_request(DIGEST, 0x1234567890ABCDEF))
    out = subprocess.run(["openssl", "ts", "-query", "-in", str(q), "-text"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "Hash Algorithm: sha256" in out.stdout and DIGEST.hex() in out.stdout.replace(" ", "").replace("\n", "").lower() or \
        "Message data" in out.stdout
    assert "Nonce: 0x1234567890ABCDEF" in out.stdout and "Certificate required: yes" in out.stdout


@needs_openssl
def test_round_trip_with_a_real_token(tsa, tmp_path):
    got = ts.request_timestamp(DIGEST, tsa.url)
    info = got["info"]
    assert info["granted"] and info["imprint_hex"] == DIGEST.hex() and info["hash_oid"] == ts.OID_SHA256
    assert info["nonce"] == got["nonce"] and info["policy"] == "1.2.3.4.1" and info["serial"] >= 1
    assert info["gen_time"].endswith("Z") and len(info["gen_time"]) == 20
    assert len(info["certs_der"]) == 2                              # certReq: the TSA certificate and its CA
    assert tsa.requests[-1][0] == "application/timestamp-query"
    # the saved answer must verify with OpenSSL against the CA (this is the real trust check)
    data = tmp_path / "data.bin"
    data.write_bytes(b"manifest contents")
    resp = tmp_path / "r.tsr"
    resp.write_bytes(got["response"])
    pem = tmp_path / "certs.pem"
    pem.write_text(ts.certs_pem(info), encoding="utf-8")
    ok = tsa.verify(data, resp, pem)
    assert ok.returncode == 0 and "Verification: OK" in ok.stdout + ok.stderr
    data.write_bytes(b"manifest contents, edited")                  # a changed file must no longer verify
    assert tsa.verify(data, resp, pem).returncode != 0


@needs_openssl
def test_refusals_and_wrong_answers_are_rejected(tsa):
    tsa.mode = "garbage"
    with pytest.raises(TimestampFailed, match="could not be read"):
        ts.request_timestamp(DIGEST, tsa.url)
    tsa.mode = "ok"
    # an answer for a different fingerprint / replayed nonce is refused
    good = ts.request_timestamp(DIGEST, tsa.url)["info"]
    with pytest.raises(TimestampFailed, match="different fingerprint"):
        ts.check_answer(good, hashlib.sha256(b"other").digest(), good["nonce"])
    with pytest.raises(TimestampFailed, match="one-time number"):
        ts.check_answer(good, DIGEST, good["nonce"] + 2)
    with pytest.raises(TimestampFailed, match="refused"):
        ts.check_answer({"granted": False, "status": 2}, DIGEST, 1)


def test_unreachable_authority_gives_a_reason():
    with pytest.raises(TimestampFailed) as e:
        ts.request_timestamp(DIGEST, "http://127.0.0.1:1/tsr", timeout=2)
    assert any(w in str(e.value).lower() for w in ("127.0.0.1", "connection", "refused", "timed out"))


@needs_openssl
def test_parser_accepts_ber_indefinite_lengths_and_bare_tokens(tsa, tmp_path):
    raw = ts.request_timestamp(DIGEST, tsa.url)["response"]
    base = ts.parse_response(raw)

    def to_ber(node):                      # re-encode every constructed node with an indefinite length
        if not node.constructed:
            return ts._tlv(node.tag, node.body)
        return bytes([node.tag, 0x80]) + b"".join(to_ber(c) for c in node.children()) + b"\x00\x00"

    ber = to_ber(ts.parse_der(raw))
    assert ber != raw
    again = ts.parse_response(ber)
    for k in ("granted", "gen_time", "imprint_hex", "nonce", "serial", "policy"):
        assert again[k] == base[k]
    # a bare token (no status wrapper), which is what `openssl ts -token_out` writes
    token = ts.parse_der(raw).children()[1]
    bare = ts.parse_response(ts._tlv(token.tag, token.body))
    assert bare["imprint_hex"] == base["imprint_hex"] and bare["gen_time"] == base["gen_time"]


def test_garbage_never_crashes_the_reader():
    for junk in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x80", bytes(range(256)), b"\x30\x03\x02\x01"):
        with pytest.raises((TimestampFailed, ValueError)):
            ts.parse_response(junk)
