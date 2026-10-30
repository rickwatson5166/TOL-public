"""Small shared helpers for the (opt-in) registry lookups.

Two things went wrong in the first packaged Mac builds, both fixed here:
  * the bundled Python on macOS often has no CA certificate list, so every HTTPS lookup failed to verify the
    registry's certificate. We now find a CA bundle (certifi if present, else the OS file) and never turn
    certificate checking off.
  * every failure looked the same as "the registry has no record". A lookup that could not be made now raises
    LookupFailed with the real reason, so it is shown, not saved as evidence, and retried later.
"""
import os
import ssl
import urllib.error
import urllib.request

CA_FILES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")


class LookupFailed(RuntimeError):
    """The registry could not be asked (network, certificate, timeout, server error)."""


def ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:                                   # certifi absent or unusable: fall through
        pass
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0) == 0:   # no CA certs loaded: use the operating system's file
        for path in CA_FILES:
            if os.path.isfile(path):
                try:
                    ctx.load_verify_locations(cafile=path)
                    break
                except (ssl.SSLError, OSError):
                    continue
    return ctx


def rdap_get(ip: str, url="https://rdap.org/ip/{ip}", timeout=8):
    """(raw bytes, final URL) for the registry's answer, or None if the registry says it has no record (HTTP 404).
    Any other problem raises LookupFailed with the reason."""
    req = urllib.request.Request(url.format(ip=ip), headers={"Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
            return r.read(), r.geturl()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise LookupFailed(f"registry answered HTTP {e.code}") from e
    except Exception as e:                              # noqa: BLE001 - report whatever happened
        reason = getattr(e, "reason", None) or e
        raise LookupFailed(f"{type(e).__name__}: {reason}") from e
