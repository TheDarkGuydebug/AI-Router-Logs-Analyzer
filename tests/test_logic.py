import importlib.util
import csv
import json
import re
import socket
import sys
import types
import unittest
from pathlib import Path

# The logic tests do not start Flask. Lightweight stubs allow the single-file
# application to be imported in minimal/offline CI environments.
if "flask" not in sys.modules:
    flask = types.ModuleType("flask")

    class DummyFlask:
        def __init__(self, *args, **kwargs):
            self.config = {}
            self.logger = types.SimpleNamespace(exception=lambda *a, **k: None)

        def get(self, *args, **kwargs):
            return lambda fn: fn

        post = get
        errorhandler = get

        def run(self, *args, **kwargs):
            return None

    flask.Flask = DummyFlask
    flask.jsonify = lambda value=None, **kwargs: value if value is not None else kwargs
    flask.render_template_string = lambda text, **kwargs: text
    flask.request = types.SimpleNamespace(files={}, args={}, get_json=lambda **kwargs: {})
    sys.modules["flask"] = flask

if "werkzeug.utils" not in sys.modules:
    werkzeug = types.ModuleType("werkzeug")
    utils = types.ModuleType("werkzeug.utils")
    utils.secure_filename = lambda value: value
    werkzeug.utils = utils
    sys.modules["werkzeug"] = werkzeug
    sys.modules["werkzeug.utils"] = utils

MODULE_PATH = Path(__file__).resolve().parents[1] / "pcap_insight.py"
spec = importlib.util.spec_from_file_location("pcap_insight", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def packet(frame, epoch, **extra):
    row = {
        "frame": str(frame),
        "epoch": str(epoch),
        "relative": str(epoch),
        "timestamp_india": mod.india_timestamp(epoch),
        "protocol": extra.pop("protocol", "DNS"),
        "info": extra.pop("info", ""),
        "ip_src": extra.pop("ip_src", "192.0.2.10"),
        "ip_dst": extra.pop("ip_dst", "192.0.2.53"),
        "ipv6_src": extra.pop("ipv6_src", ""),
        "ipv6_dst": extra.pop("ipv6_dst", ""),
        "udp_sport": extra.pop("udp_sport", "53000"),
        "udp_dport": extra.pop("udp_dport", "53"),
    }
    row.update(extra)
    return row


class LogicTests(unittest.TestCase):
    def dns_result(self, rows):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        analyzer.extract = lambda display_filter, specs: [dict(r) for r in rows]
        return analyzer.dns()

    def empty_wan(self):
        return {"diagnostics": {"break_stage": None}}

    def test_india_timestamp(self):
        self.assertEqual(mod.india_timestamp(0), "01-Jan-1970 05:30:00.000 IST")
        value = mod.india_timestamp(1760184000.123)
        self.assertRegex(value, r"^\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3} IST$")
        self.assertNotIn("UTC", value)

    def test_cli_port_argument_and_default_auto_port_selection(self):
        args = mod.parse_cli(["--port", "9123", "--ai-model", "test-model:7b", "--ai-api-style", "native"])
        self.assertEqual(args.port, 9123)
        self.assertEqual(args.ai_model, "test-model:7b")
        self.assertEqual(args.ai_api_style, "native")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen(1)
            busy = occupied.getsockname()[1]
            selected = mod.choose_available_port("127.0.0.1", busy, attempts=3)
        self.assertGreater(selected, busy)

    def test_cleartext_http_body_and_cwmp_semantics(self):
        xml = (
            '<soap:Envelope><soap:Body><cwmp:Inform><Event>'
            '<EventStruct><EventCode>1 BOOT</EventCode><CommandKey>scheduled-reboot</CommandKey>'
            '</EventStruct></Event><ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name>'
            '<Value>1.2.3</Value></ParameterValueStruct></cwmp:Inform></soap:Body></soap:Envelope>'
        )
        body, state = mod.visible_payload(xml.encode().hex())
        semantics = mod.cwmp_semantics(body)
        self.assertEqual(state, "visible_cleartext")
        self.assertIn("Inform", semantics["operations"])
        self.assertIn("1 BOOT", semantics["event_codes"])
        self.assertTrue(any("SoftwareVersion=1.2.3" in value for value in semantics["parameters"]))
        self.assertTrue(semantics["reboot_reset_evidence"])

    def test_binary_payload_is_not_claimed_as_body(self):
        body, state = mod.visible_payload("00010203fffe")
        self.assertEqual(body, "")
        self.assertEqual(state, "binary_or_undecodable")

    def test_http_exposes_only_visible_cleartext_body(self):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        xml = '<soap:Body><cwmp:Inform><EventCode>2 PERIODIC</EventCode></cwmp:Inform></soap:Body>'
        analyzer.extract = lambda display_filter, specs: [
            packet(5, 5, protocol="HTTP", method="POST", host="tms.airtelbroadband.in",
                   uri="/acs", stream="2", body_data=xml.encode().hex(), content_type="text/xml")
        ]
        analyzer.proto_filter = lambda *protocols: "http"
        result = analyzer.http()
        self.assertEqual(result["requests"][0]["body_state"], "visible_cleartext")
        self.assertIn("Inform", result["requests"][0]["cwmp"]["operations"])
        self.assertEqual(result["messages"][0]["message_type"], "HTTP POST")

    def test_http_body_over_200kb_uses_full_semantic_parse_and_bounded_display(self):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        large_xml = "<root>" + ("A" * 210_000) + "<cwmp:Inform><EventCode>2 PERIODIC</EventCode></cwmp:Inform></root>"
        encoded = large_xml.encode().hex()
        # Reproduces a TShark -T fields CSV cell above the old 131072-byte limit.
        parsed = next(csv.reader(__import__("io").StringIO(f'"{encoded}"')))[0]
        self.assertEqual(parsed, encoded)
        self.assertGreater(csv.field_size_limit(), len(encoded))
        analyzer.proto_filter = lambda *protocols: protocols[0]
        analyzer.extract = lambda display_filter, specs: [
            packet(8, 8, protocol="HTTP", method="POST", host="tms.airtelbroadband.in",
                   uri="/acs", stream="8", body_data=encoded, content_type="text/xml")
        ] if display_filter == "http" else []
        item = analyzer.http()["requests"][0]
        self.assertTrue(item["body_truncated"])
        self.assertGreater(item["body_total_bytes"], 200_000)
        self.assertIn("truncated,", item["body"])
        self.assertLess(len(item["body"].encode()), 70_000)
        # Inform lies beyond the 64 KiB display boundary but must still be parsed.
        self.assertIn("Inform", item["cwmp"]["operations"])

    def test_dhcp_client_card_fields_and_bound_state(self):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        analyzer.proto_filter = lambda *protocols: "dhcp"
        analyzer.extract = lambda display_filter, specs: [
            packet(10, 10, protocol="DHCP", eth_src="00:11:22:33:44:55", mac="00:11:22:33:44:55",
                   xid="0x1234", message_type="1", hostname="cpe", vendor_class="AirtelCPE",
                   parameter_list="1,3,6,15", requested_ip="192.0.2.10", client_id="01:00:11:22:33:44:55",
                   user_class="home", fqdn="cpe.example", vlan_ids="100"),
            packet(11, 11, protocol="DHCP", eth_dst="00:11:22:33:44:55", mac="00:11:22:33:44:55",
                   xid="0x1234", message_type="5", your_ip="192.0.2.10", server_id="192.0.2.1",
                   subnet="255.255.255.0", router="192.0.2.1", dns_servers="1.1.1.1,8.8.8.8",
                   domain="example", lease_time="86400", renewal_time="43200", rebinding_time="75600",
                   relay_agent="circuit-1", giaddr="198.51.100.1", vlan_ids="100"),
        ]
        client = analyzer.dhcp()["clients"][0]
        self.assertEqual(client["status"], "Bound")
        self.assertEqual(client["ipv4_addresses"], ["192.0.2.10"])
        self.assertEqual(client["requested_ips"], ["192.0.2.10"])
        self.assertIn("AirtelCPE", client["vendor_classes"])
        self.assertEqual(client["dns_servers"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(client["vlans"], ["100"])

    def test_management_does_not_decode_tls_application_payload(self):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        old_fields = mod.TSharkAnalyzer._field_catalog
        try:
            mod.TSharkAnalyzer._field_catalog = {"dns.qry.name", "tls.handshake.extensions_server_name"}
            fake_xml = '<cwmp:FactoryReset/>'.encode().hex()
            analyzer.extract = lambda display_filter, specs: [
                packet(6, 6, protocol="TLSv1.3", tls_sni="tms.airtelbroadband.in", body_data=fake_xml)
            ]
            result = analyzer.management({"transactions": []})
        finally:
            mod.TSharkAnalyzer._field_catalog = old_fields
        event = result["events"][0]
        self.assertEqual(event["body_state"], "encrypted_not_decrypted")
        self.assertEqual(event["body"], "")
        self.assertEqual(event["cwmp"]["operations"], [])

    def test_management_names_cleartext_inform_from_captured_body(self):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        old_fields = mod.TSharkAnalyzer._field_catalog
        try:
            mod.TSharkAnalyzer._field_catalog = {"http.host"}
            xml = '<soap:Body><cwmp:Inform><EventCode>4 VALUE CHANGE</EventCode></cwmp:Inform></soap:Body>'
            analyzer.extract = lambda display_filter, specs: [
                packet(7, 7, protocol="HTTP", http_host="tms.airtelbroadband.in",
                       http_method="POST", http_uri="/acs", body_data=xml.encode().hex())
            ]
            result = analyzer.management({"transactions": []})
        finally:
            mod.TSharkAnalyzer._field_catalog = old_fields
        event = result["events"][0]
        self.assertEqual(event["action"], "CWMP/TR-069 Inform")
        self.assertIn("4 VALUE CHANGE", event["cwmp"]["event_codes"])
        self.assertEqual(event["body_state"], "visible_cleartext")

    def test_protocol_module_failure_is_isolated_and_warned(self):
        analyzer = mod.TSharkAnalyzer.__new__(mod.TSharkAnalyzer)
        analyzer.warnings = []
        analyzer.core_timeline = lambda: [packet(1, 1)]
        analyzer.tcp = lambda: {"packet_count": 0, "mss_distribution": [], "mss_events": [], "anomalies": [], "retransmissions": 0, "out_of_order": 0}
        analyzer.dns = lambda: {"packet_count": 0, "transactions": [], "domain_outcomes": [], "rows": []}
        analyzer.http = lambda: (_ for _ in ()).throw(csv.Error("field larger than field limit"))
        analyzer.dhcp = lambda: {"packet_count": 0, "clients": [], "events": []}
        analyzer.mdns = lambda: {"packet_count": 0, "transactions": [], "events": []}
        analyzer.management = lambda dns: {"target": mod.TARGET_HOST, "resolved_ips": [], "events": [], "packet_count": 0}
        analyzer.wan = lambda: {
            **{k: [] for k in ("pppoe", "lcp", "pap", "ipcp", "ipv6cp", "dhcpv6")},
            "diagnostics": mod.TSharkAnalyzer._build_wan_diagnostics([], [], [], [], [], []),
            "summary": {"pppoe_sessions": [], "lcp_echo_requests": 0, "lcp_echo_replies": 0,
                        "pap_success": 0, "pap_failure": 0, "ipv4_allocations": [], "ipcp_dns_servers": [],
                        "ipv6_interface_ids": [], "dhcpv6_addresses": [], "dhcpv6_prefixes": [], "dhcpv6_dns_servers": []},
        }
        analyzer._tshark_version = lambda: "TShark test"
        result = analyzer.analyze("isolated.pcap")
        self.assertEqual(result["http"]["messages"], [])
        self.assertEqual(result["metadata"]["packets"], 1)
        self.assertTrue(any("HTTP/TLS module failed" in warning for warning in result["warnings"]))

    def test_dns_alarm_suppressed_when_either_family_resolves(self):
        rows = [
            packet(1, 0, dns_id="0x10", response="0", qname="example.test", qtype="1", info="A query"),
            packet(2, 1, dns_id="0x10", response="1", qname="example.test", qtype="1", rcode="2", info="SERVFAIL"),
            packet(3, 2, dns_id="0x11", response="0", qname="example.test", qtype="28", info="AAAA query"),
            packet(4, 3, dns_id="0x11", response="1", qname="example.test", qtype="28", rcode="0", aaaa="2001:db8::7", info="AAAA response"),
        ]
        dns = self.dns_result(rows)
        self.assertTrue(dns["domain_outcomes"][0]["resolved"])
        alarms = mod.TSharkAnalyzer._build_alarms({}, dns, {"events": []}, self.empty_wan())
        self.assertFalse(any(a["type"] == "dns_resolution_failure" for a in alarms))

    def test_dns_alarm_when_neither_family_resolves(self):
        rows = [
            packet(1, 0, dns_id="0x20", response="0", qname="broken.test", qtype="1", info="A query"),
            packet(2, 1, dns_id="0x20", response="1", qname="broken.test", qtype="1", rcode="3", info="NXDOMAIN"),
            packet(3, 2, dns_id="0x21", response="0", qname="broken.test", qtype="28", info="AAAA query"),
            packet(4, 3, dns_id="0x21", response="1", qname="broken.test", qtype="28", rcode="0", info="NOERROR empty"),
        ]
        dns = self.dns_result(rows)
        self.assertFalse(dns["domain_outcomes"][0]["resolved"])
        alarms = mod.TSharkAnalyzer._build_alarms({}, dns, {"events": []}, self.empty_wan())
        self.assertEqual([a["type"] for a in alarms], ["dns_resolution_failure"])
        self.assertIn("Neither an IPv4 A address nor an IPv6 AAAA", alarms[0]["detail"])

    def test_pppoe_discovery_break_is_packet_evidence_based(self):
        pppoe = [
            packet(10, 10, protocol="PPPoED", event="PADI"),
            packet(11, 11, protocol="PPPoED", event="PADO"),
            packet(12, 12, protocol="PPPoED", event="PADR"),
        ]
        result = mod.TSharkAnalyzer._build_wan_diagnostics(pppoe, [], [], [], [], [])
        self.assertEqual(result["break_stage"]["stage"], "PPPoE discovery")
        self.assertEqual(result["break_stage"]["status"], "incomplete")
        self.assertIn("PADS is not visible", result["break_stage"]["reason"])

    def test_wan_reports_last_success_and_ipcp_break(self):
        pppoe = [packet(20, 20, protocol="PPPoED", event="PADS", session_id="0x0010")]
        lcp = [packet(21, 21, protocol="LCP", event="Configure-Ack")]
        pap = [packet(22, 22, protocol="PAP", event="Authenticate-Ack")]
        ipcp = [packet(23, 23, protocol="IPCP", event="Configure-Request")]
        result = mod.TSharkAnalyzer._build_wan_diagnostics(pppoe, lcp, pap, ipcp, [], [])
        self.assertEqual(result["last_successful_stage"], "PAP")
        self.assertEqual(result["break_stage"]["stage"], "IPCP")
        self.assertEqual(result["break_stage"]["frames"], ["23"])

    def test_no_wan_packets_does_not_invent_a_break(self):
        result = mod.TSharkAnalyzer._build_wan_diagnostics([], [], [], [], [], [])
        self.assertIsNone(result["break_stage"])
        self.assertEqual(result["overall_status"], "not_observed")

    def test_ai_context_is_single_analysis_normalized_and_excludes_bodies_by_default(self):
        analysis = {
            "metadata": {"filename": "only-this-capture.pcap", "packets": 2},
            "summary": {"alarms": 0},
            "http": {"messages": [{"frame": "7", "body": "captured-secret-body", "body_state": "visible_cleartext",
                                     "password": "direct-secret", "info": "PAP password='wire-secret' Authorization: Bearer abc123"}]},
            "timeline": [{"frame": "7", "category": "HTTP", "summary": "POST /acs"}],
            "flow_graph": {"nodes": [{"id": "not-needed"}]},
        }
        text, meta = mod.build_ai_context(analysis, include_bodies=False)
        context = json.loads(text)
        self.assertEqual(context["metadata"]["filename"], "only-this-capture.pcap")
        self.assertNotIn("captured-secret-body", text)
        self.assertNotIn("direct-secret", text)
        self.assertNotIn("wire-secret", text)
        self.assertNotIn("abc123", text)
        self.assertIn("REDACTED CREDENTIAL", text)
        self.assertNotIn("flow_graph", context)
        self.assertGreater(meta["bytes"], 0)

    def test_backend_ai_request_uses_only_supplied_pcap_context_and_extracts_frames(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({"choices": [{"message": {"content": "The request is visible at Frame 7."}}]}).encode()

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data.decode())
            captured["timeout"] = timeout
            return FakeResponse()

        old = (mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_API_KEY, mod.AI_ALLOW_REMOTE, mod.AI_API_STYLE)
        try:
            mod.AI_CHAT_URL = "http://agent.test/v1/chat/completions"
            mod.AI_BASE_URL = ""
            mod.AI_MODEL = "test-agent"
            mod.AI_API_KEY = ""
            mod.AI_ALLOW_REMOTE = True
            mod.AI_API_STYLE = "openai"
            answer = mod.call_backend_ai(
                "What happened?",
                {"metadata": {"filename": "scope-marker.pcap"}, "timeline": [{"frame": "7", "summary": "request"}]},
                opener=fake_open,
            )
        finally:
            mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_API_KEY, mod.AI_ALLOW_REMOTE, mod.AI_API_STYLE = old
        self.assertEqual(captured["url"], "http://agent.test/v1/chat/completions")
        user_content = captured["payload"]["messages"][1]["content"]
        self.assertIn("scope-marker.pcap", user_content)
        self.assertIn("What happened?", user_content)
        self.assertEqual(answer["frames"], ["7"])
        self.assertEqual(answer["model"], "test-agent")
        self.assertEqual(answer["provider"], "openai_compatible")

    def test_native_ollama_chat_and_health_model_check(self):
        requests = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(self.payload).encode()

        def fake_open(request, timeout):
            requests.append(request.full_url)
            if request.full_url.endswith("/api/tags"):
                return FakeResponse({"models": [{"name": "qwen2.5:7b"}]})
            payload = json.loads(request.data.decode())
            self.assertFalse(payload["stream"])
            return FakeResponse({"message": {"content": "Observed at Frame 9."}})

        old = (mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_API_STYLE, mod.AI_ALLOW_REMOTE)
        try:
            mod.AI_CHAT_URL = ""
            mod.AI_BASE_URL = "http://127.0.0.1:11434"
            mod.AI_MODEL = "qwen2.5:7b"
            mod.AI_API_STYLE = "native"
            mod.AI_ALLOW_REMOTE = False
            status = mod.ai_backend_status(force=True, opener=fake_open)
            answer = mod.call_backend_ai("What is visible?", {"timeline": [{"frame": "9", "summary": "event"}]}, opener=fake_open)
        finally:
            mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_API_STYLE, mod.AI_ALLOW_REMOTE = old
        self.assertTrue(status["available"])
        self.assertEqual(status["status"], "ready")
        self.assertEqual(answer["provider"], "ollama_native")
        self.assertTrue(any(url.endswith("/api/chat") for url in requests))

    def test_non_local_ai_endpoint_requires_explicit_opt_in(self):
        old = (mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_ALLOW_REMOTE)
        try:
            mod.AI_CHAT_URL = ""
            mod.AI_BASE_URL = "https://remote-agent.example"
            mod.AI_MODEL = "remote-model"
            mod.AI_ALLOW_REMOTE = False
            status = mod.ai_backend_status(force=True)
        finally:
            mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_ALLOW_REMOTE = old
        self.assertFalse(status["available"])
        self.assertEqual(status["status"], "blocked")

    def test_ollama_running_without_model_reports_model_missing(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({"models": [{"name": "another-model:latest"}]}).encode()

        old = (mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_ALLOW_REMOTE)
        try:
            mod.AI_CHAT_URL = ""
            mod.AI_BASE_URL = "http://127.0.0.1:11434"
            mod.AI_MODEL = "qwen2.5:7b"
            mod.AI_ALLOW_REMOTE = False
            status = mod.ai_backend_status(force=True, opener=lambda request, timeout: FakeResponse())
        finally:
            mod.AI_CHAT_URL, mod.AI_BASE_URL, mod.AI_MODEL, mod.AI_ALLOW_REMOTE = old
        self.assertFalse(status["available"])
        self.assertEqual(status["status"], "model_missing")
        self.assertIn("ollama pull qwen2.5:7b", status["detail"])

    def test_ladder_carries_visible_details_and_alarm_marker(self):
        dns = self.dns_result([
            packet(30, 30, dns_id="0x30", response="0", qname="fail.test", qtype="1", info="A query")
        ])
        alarms = mod.TSharkAnalyzer._build_alarms({}, dns, {"events": []}, self.empty_wan())
        ladder = mod.TSharkAnalyzer._build_ladder(
            {"anomalies": [], "mss_events": []}, dns, {"requests": [], "responses": []},
            {"events": []}, {"events": []}, {"events": []},
            {k: [] for k in ("pppoe", "lcp", "pap", "ipcp", "ipv6cp", "dhcpv6")}, alarms,
        )
        self.assertEqual(ladder[0]["timestamp_india"], "01-Jan-1970 05:30:30.000 IST")
        self.assertIn("A query", ladder[0]["summary"])
        self.assertTrue(ladder[0]["is_alarm"])
        self.assertTrue(ladder[0]["alarm_ids"])

    def test_call_flow_keeps_ppp_protocols_separate_and_hides_generic_session_data(self):
        wan = {k: [] for k in ("pppoe", "lcp", "pap", "ipcp", "ipv6cp", "dhcpv6")}
        wan["pppoe"] = [packet(40, 40, protocol="PPPoE", event="Session data", session_id="0x10")]
        wan["lcp"] = [packet(41, 41, protocol="LCP", event="Configure-Request", identifier="7")]
        flow = mod.TSharkAnalyzer._build_ladder(
            {"anomalies": [], "mss_events": []}, {"transactions": []},
            {"messages": []}, {"events": []}, {"events": []}, {"events": []}, wan, [],
        )
        self.assertEqual([item["category"] for item in flow], ["LCP"])
        self.assertEqual(flow[0]["message_type"], "Configure-Request")

    def test_ppp_session_ladder_includes_discovery_and_control_messages(self):
        wan = {k: [] for k in ("pppoe", "lcp", "pap", "ipcp", "ipv6cp", "dhcpv6")}
        wan["pppoe"] = [
            packet(50, 50, protocol="PPPoE", event="PADI", session_id="0x0000", host_uniq="aa"),
            packet(51, 51, protocol="PPPoE", event="PADO", session_id="0x0000", host_uniq="aa"),
            packet(52, 52, protocol="PPPoE", event="PADR", session_id="0x0000", host_uniq="aa"),
            packet(53, 53, protocol="PPPoE", event="PADS", session_id="0x0010", host_uniq="aa"),
        ]
        wan["lcp"] = [packet(54, 54, protocol="LCP", event="Echo-Request", pppoe_session_id="0x0010")]
        sessions = mod.TSharkAnalyzer._build_ppp_sessions(wan)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["session_id"], "0x0010")
        self.assertEqual([m["event"] for m in sessions[0]["messages"]], ["PADI", "PADO", "PADR", "PADS", "Echo-Request"])


if __name__ == "__main__":
    unittest.main()
