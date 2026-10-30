"""Small persisted user settings (~/.tol/settings.json). Anything that sends data off the machine defaults to off."""
import json
import os
import threading
from pathlib import Path

DEFAULTS = {"auto_identify": False, "auto_identify_consented_at": None,
            "tsa_url": "http://timestamp.digicert.com"}      # which timestamp authority to ask (only when the user clicks)


class Settings:
    def __init__(self, data_dir):
        self.path = Path(data_dir) / "settings.json" if data_dir else None
        self._lock = threading.Lock()
        self._data = dict(DEFAULTS)
        if self.path and self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                self._data.update({k: loaded[k] for k in DEFAULTS if k in loaded})
            except (ValueError, OSError):
                pass

    def get(self, key):
        with self._lock:
            return self._data[key]

    def set(self, **changes):
        with self._lock:
            for k, v in changes.items():
                if k not in DEFAULTS:
                    raise KeyError(k)
                self._data[k] = v
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
                os.replace(tmp, self.path)
