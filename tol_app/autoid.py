"""Auto-identify: look up newly seen destinations in the background and save a receipt for each.

Off by default. It only runs after the user has switched it on and confirmed that each lookup sends an IP
address (never traffic contents) to the public RDAP/WHOIS service. It is deliberately gentle:
  - one lookup per network block (a receipt for one address covers its whole block)
  - never local addresses, never rows the user's own registry already verifies ("Likely" rows, whose name is only
    a hostname guess, are looked up so they get real registry proof)
  - at most one lookup every `interval` seconds and `per_hour` per hour
  - an address whose lookup fails is not retried for 10 minutes
"""
import threading
import time
from collections import deque

BACKOFF = 600


class AutoIdentifier:
    def __init__(self, engine, receipts, settings, clock=time.time, interval=1.5, per_hour=120):
        self.engine, self.receipts, self.settings = engine, receipts, settings
        self.clock, self.interval, self.per_hour = clock, interval, per_hour
        self._done = deque()                # timestamps of lookups in the last hour
        self._failed = {}                   # ip -> retry-after time
        self.total = 0
        self.last_error = None

    # --- control --------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self.settings.get("auto_identify"))

    def enable(self, consent: bool, now=None):
        """Turning it on requires explicit consent (the dashboard asks before sending consent=1)."""
        if not consent:
            raise PermissionError("consent required")
        now = self.clock() if now is None else now
        self.settings.set(auto_identify=True, auto_identify_consented_at=int(now))

    def disable(self):
        self.settings.set(auto_identify=False)

    # --- work -----------------------------------------------------------------
    def _prune(self, now):
        while self._done and self._done[0] < now - 3600:
            self._done.popleft()

    def pending(self, now=None):
        now = self.clock() if now is None else now
        return [ip for ip in self.engine.unidentified_ips() if self._failed.get(ip, 0) <= now]

    def step(self, now=None):
        """Do at most one lookup. Returns the IP looked up, or None."""
        if not self.enabled:
            return None
        now = self.clock() if now is None else now
        self._prune(now)
        if len(self._done) >= self.per_hour:
            return None
        for ip in self.pending(now):
            try:
                self.receipts.create(ip)
            except (ValueError, RuntimeError, OSError) as e:
                self._failed[ip] = now + BACKOFF
                self.last_error = f"{ip}: {e}"
                continue
            self._done.append(now)
            self.total += 1
            return ip
        return None

    def run(self, stop: threading.Event):
        while not stop.wait(self.interval):
            try:
                self.step()
            except Exception as e:                     # never let the worker die silently
                self.last_error = str(e)

    def status(self, now=None) -> dict:
        now = self.clock() if now is None else now
        self._prune(now)
        enabled = self.enabled
        failing = sum(1 for t in self._failed.values() if t > now)
        return {"enabled": enabled, "looked_up": self.total, "waiting": len(self.pending(now)) if enabled else 0,
                "failing": failing,
                "rate_limited": enabled and len(self._done) >= self.per_hour, "last_error": self.last_error,
                "consented_at": self.settings.get("auto_identify_consented_at")}

