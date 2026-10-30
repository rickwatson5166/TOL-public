"""Tiny dependency-free hash chain used by receipts and evidence packages.

RFC 8785-style canonical JSON (float-free), SHA-256 over each entry, `previous_hash` links. `evidence_verify.py` carries its
own copy of the same rules so a package can be checked without TOL at all, and tests check the two agree.
"""
import hashlib
import json

GENESIS = "0" * 64


def _ser(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_ser(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _ser(v) for k, v in items) + "}"
    raise TypeError(f"not canonically serializable: {type(obj).__name__} (floats are rejected)")


def entry_hash(entry: dict) -> str:
    return hashlib.sha256(_ser(entry).encode("utf-8")).hexdigest()


class HashChain:
    def __init__(self):
        self.entries = []

    def append(self, body: dict) -> dict:
        entry = dict(body)
        entry["seq"] = len(self.entries)
        entry["previous_hash"] = entry_hash(self.entries[-1]) if self.entries else GENESIS
        self.entries.append(entry)
        return entry

    def root(self) -> str:
        return entry_hash(self.entries[-1]) if self.entries else GENESIS
