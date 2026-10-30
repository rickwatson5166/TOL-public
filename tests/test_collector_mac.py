import pathlib

from tol_registry import lookup_company
from tol_app.labeler import Labeler
from tol_collector import Collector
from tol_collector_mac import parse_endpoint, parse_nettop

SAMPLE = (pathlib.Path(__file__).parent / "fixtures" / "nettop_sample.csv").read_text()


def test_parse_endpoint_forms():
    assert parse_endpoint("93.184.216.34:443") == ("93.184.216.34", 443)
    assert parse_endpoint("2607:f8b0:4004:c1b::5e.443") == ("2607:f8b0:4004:c1b::5e", 443)
    assert parse_endpoint("fe80::1%en0.5353") == ("fe80::1", 5353)
    assert parse_endpoint("*:*") is None and parse_endpoint("example.com:443") is None


def test_parse_nettop_sample_attributes_connections_to_processes():
    socks = parse_nettop(SAMPLE)
    assert [(s["process"], s["pid"], s["dst"], s["dport"], s["proto"]) for s in socks] == [
        ("Safari", 4242, "151.101.1.69", 443, "tcp"),
        ("Safari", 4242, "2607:f8b0:4004:c1b::5e", 443, "tcp"),
        ("Safari", 4242, "142.250.80.46", 443, "udp"),
        ("curl", 5151, "151.101.128.223", 443, "tcp"),
        ("Google Chrome H", 777, "34.149.66.165", 443, "tcp"),
    ]
    first = socks[0]
    assert (first["bytes_sent"], first["bytes_received"], first["state"]) == (900000, 48000000, 1)
    assert all(s["state"] != 10 for s in socks)                    # listeners dropped


def test_parser_tolerates_reordered_columns_and_garbage():
    text = ("junk line\n\ntime,,state,bytes_out,bytes_in,interface\n"
            "1,curl.9,,,,\n1,tcp4 10.0.0.2:1000<->8.8.4.4:443,Established,70,90,en0\n"
            "1,tcp4 10.0.0.2:1001<->8.8.4.4:443,Established,notanumber,5,en0\n")
    (s,) = parse_nettop(text)
    assert (s["bytes_sent"], s["bytes_received"], s["dst"]) == (70, 90, "8.8.4.4")
    assert parse_nettop("") == [] and parse_nettop("totally,unrelated,csv\n1,2,3\n") == []


def test_header_without_time_column_is_supported():
    text = ",interface,state,bytes_in,bytes_out\nssh.12,,,,\ntcp4 10.0.0.2:22<->1.2.3.4:22,en0,Established,5,6\n"
    (s,) = parse_nettop(text)
    assert (s["process"], s["bytes_received"], s["bytes_sent"]) == ("ssh", 5, 6)


def test_collector_with_mac_reader_end_to_end():
    first = parse_nettop(SAMPLE)
    later = parse_nettop(SAMPLE.replace("48000000,900000", "48500000,1400000").replace("3784,784,0,0,0,9.0", "3784,784,0,0,0,9.0"))
    snaps = iter([first, later])
    c = Collector(reader=lambda: next(snaps), owners=None, labeler=Labeler(registry={}, lookups=False).label)
    assert c.poll(1.0) == []                                       # baseline
    entries = c.poll(2.0)
    (e,) = entries
    assert (e["process_name"], e["bytes_sent"], e["bytes_received"], e["endpoint_ip"]) == (
        "Safari", 500000, 500000, "151.101.1.69")
    assert e["source"] == "live" and e["pid"] == 4242 and e["protocol"] == "HTTPS"


def test_udp_flows_are_labelled_quic():
    snaps = iter([parse_nettop(SAMPLE), parse_nettop(SAMPLE.replace("2200,1800", "9200,5800"))])
    c = Collector(reader=lambda: next(snaps), owners=None, labeler=lambda ip, host: lookup_company(ip, host, {}))
    c.poll(1.0)
    (e,) = c.poll(2.0)
    assert e["protocol"] == "QUIC" and e["bytes_sent"] == 4000
