"""Runs only on a real Mac (e.g. the CI macOS runner): checks the nettop parser against real output."""
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")


def test_real_nettop_output_parses():
    from tol_collector_mac import read_mac_sockets
    socks = read_mac_sockets()
    assert socks, "nettop ran but nothing parsed: the parser does not match this macOS's format"
    for s in socks:
        assert isinstance(s["bytes_sent"], int) and isinstance(s["bytes_received"], int)
        assert s["process"] and isinstance(s["pid"], int)
        assert 0 <= s["dport"] < 65536
