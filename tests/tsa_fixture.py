"""A local RFC 3161 timestamp authority built on the `openssl ts` command, for tests.

It issues REAL tokens (CMS signed with a throwaway CA and TSA certificate), so the parser and the verification are
tested against genuine data, not hand-made bytes. Tests that use it skip themselves where OpenSSL has no `ts`."""
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

CONF = """[ tsa ]
default_tsa = tsa1
[ tsa1 ]
dir = {d}
serial = $dir/tsaserial
crypto_device = builtin
signer_cert = $dir/tsa.crt
certs = $dir/chain.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha256, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""
TSA_EXT = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n"


def openssl_has_ts() -> bool:
    exe = shutil.which("openssl")
    if not exe:
        return False
    ver = subprocess.run([exe, "version"], capture_output=True, text=True).stdout
    if not ver.startswith("OpenSSL"):                 # Apple's LibreSSL has no timestamp tools, or different ones
        return False
    r = subprocess.run([exe, "ts", "-help"], capture_output=True, text=True)
    return "Usage: ts" in (r.stdout + r.stderr) or "-reply" in (r.stdout + r.stderr)


def run(*args, **kw):
    subprocess.run(args, check=True, capture_output=True, **kw)


class LocalTSA:
    def __init__(self, folder: Path):
        d = self.dir = Path(folder)
        d.mkdir(parents=True, exist_ok=True)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "ca.key"), "-out", str(d / "ca.crt"),
            "-subj", "/CN=Test Root CA", "-days", "30")
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "tsa.key"), "-out", str(d / "tsa.csr"),
            "-subj", "/CN=Test TSA")
        (d / "ext.cnf").write_text(TSA_EXT, encoding="utf-8")
        run("openssl", "x509", "-req", "-in", str(d / "tsa.csr"), "-CA", str(d / "ca.crt"), "-CAkey", str(d / "ca.key"),
            "-CAcreateserial", "-out", str(d / "tsa.crt"), "-days", "30", "-extfile", str(d / "ext.cnf"))
        (d / "chain.pem").write_text((d / "ca.crt").read_text(encoding="utf-8"), encoding="utf-8")      # the signer is added by openssl itself
        (d / "tsaserial").write_text("01\n", encoding="utf-8")
        (d / "tsa.conf").write_text(CONF.format(d=d.as_posix()), encoding="utf-8")
        self.requests = []
        self.mode = "ok"                      # "ok" | "refuse" | "garbage" | "wrong-imprint"
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append((self.headers.get("Content-Type"), body))
                if outer.mode == "garbage":
                    out = b"<html>not a timestamp</html>"
                else:
                    (d / "q.tsq").write_bytes(body)
                    run("openssl", "ts", "-reply", "-config", str(d / "tsa.conf"), "-section", "tsa1",
                        "-queryfile", str(d / "q.tsq"), "-out", str(d / "r.tsr"))
                    out = (d / "r.tsr").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/tsr"

    @property
    def ca(self) -> Path:
        return self.dir / "ca.crt"

    def verify(self, data: Path, response: Path, untrusted: Path = None) -> subprocess.CompletedProcess:
        cmd = ["openssl", "ts", "-verify", "-data", str(data), "-in", str(response), "-CAfile", str(self.ca)]
        if untrusted:
            cmd += ["-untrusted", str(untrusted)]
        return subprocess.run(cmd, capture_output=True, text=True)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
