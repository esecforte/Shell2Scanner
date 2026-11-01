#!/usr/bin/env python3
"""Self-contained offline test suite for shell2scan (standard library only).

No third-party test runner is required. Run it with either::

    python test_shell2scan.py
    python -m unittest test_shell2scan

Every check is offline — the HTTP session is replaced with in-memory doubles,
so nothing here touches the network.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import shell2scan
from core import Finding, VULNERABLE, CLEAR, LIKELY, __version__
from core import net, ports, waf
from core import node2shell as n
from core import php2shell as p


# --------------------------------------------------------------------------- #
# HTTP doubles
# --------------------------------------------------------------------------- #
class FakeCookies:
    def __init__(self, names=None):
        self._names = list(names or [])

    def keys(self):
        return list(self._names)


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, cookies=None):
        self.status_code = status_code
        self.text = text
        self.headers = dict(headers or {})
        self.cookies = FakeCookies(cookies)


class ScriptedSession:
    """get/post driven by queued behaviours (FakeResponse to return, Exception to raise)."""

    def __init__(self, posts=None, gets=None, verify=False, timeout=5.0):
        self._posts = list(posts or [])
        self._gets = list(gets or [])
        self.verify = verify
        self.timeout = timeout
        self.cookies = FakeCookies()

    @staticmethod
    def _resolve(behaviour):
        if isinstance(behaviour, BaseException):
            raise behaviour
        if isinstance(behaviour, type) and issubclass(behaviour, BaseException):
            raise behaviour()
        return behaviour

    def post(self, url, data=None, headers=None, **kwargs):
        return self._resolve(self._posts.pop(0)) if self._posts else FakeResponse(200)

    def get(self, url, **kwargs):
        return self._resolve(self._gets.pop(0)) if self._gets else FakeResponse(200)


# --------------------------------------------------------------------------- #
# net
# --------------------------------------------------------------------------- #
class TestNet(unittest.TestCase):
    def test_normalize_target_valid(self):
        cases = {
            "example.com": "example.com",
            "http://example.com": "example.com",
            "https://example.com:8443/x?y=1": "example.com:8443",
            "  example.com/path  ": "example.com",
            "10.0.0.5": "10.0.0.5",
            "10.0.0.5:8080": "10.0.0.5:8080",
            "sub.domain.co.uk": "sub.domain.co.uk",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(net.normalize_target(raw), expected)

    def test_normalize_target_ipv6(self):
        cases = {
            "2001:db8::1": "[2001:db8::1]",
            "::1": "[::1]",
            "[::1]:8080": "[::1]:8080",
            "http://[2001:db8::1]:8080/x": "[2001:db8::1]:8080",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(net.normalize_target(raw), expected)

    def test_normalize_target_invalid(self):
        for raw in ["", "   ", "bad host", "-bad-.com", "...", "http://"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                net.normalize_target(raw)

    def test_split_host_port(self):
        cases = {
            "example.com": ("example.com", None),
            "example.com:443": ("example.com", 443),
            "10.0.0.5:8080": ("10.0.0.5", 8080),
            "[::1]:8443": ("::1", 8443),
            "[2001:db8::1]": ("2001:db8::1", None),
            "2001:db8::1": ("2001:db8::1", None),
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(net.split_host_port(target), expected)

    def test_join_host_port(self):
        cases = [
            ("example.com", 443, "example.com:443"),
            ("10.0.0.5", 80, "10.0.0.5:80"),
            ("::1", 8443, "[::1]:8443"),
            ("[::1]", 8443, "[::1]:8443"),
        ]
        for host, port, expected in cases:
            with self.subTest(host=host, port=port):
                self.assertEqual(net.join_host_port(host, port), expected)

    def test_base_urls_default_order(self):
        self.assertEqual(net.base_urls("example.com", None),
                         ["https://example.com", "http://example.com"])

    def test_base_urls_forced_scheme(self):
        self.assertEqual(net.base_urls("example.com", "http"), ["http://example.com"])
        self.assertEqual(net.base_urls("example.com", "https"), ["https://example.com"])

    def test_session_has_timeout_and_verify(self):
        s = net.session(timeout=7.5, verify_tls=True)
        try:
            self.assertEqual(s.timeout, 7.5)
            self.assertIs(s.verify, True)
            self.assertIn("User-Agent", s.headers)
            self.assertIs(s.get_adapter("http://x"), s.get_adapter("https://x.y"))
        finally:
            s.close()


# --------------------------------------------------------------------------- #
# ports
# --------------------------------------------------------------------------- #
class TestPorts(unittest.TestCase):
    def test_default_web_ports_unique_and_in_range(self):
        self.assertEqual(len(ports.DEFAULT_WEB_PORTS), len(set(ports.DEFAULT_WEB_PORTS)))
        self.assertTrue(all(1 <= p <= 65535 for p in ports.DEFAULT_WEB_PORTS))

    def test_hint_sets_are_disjoint(self):
        self.assertTrue(ports.HTTP_HINT_PORTS.isdisjoint(ports.HTTPS_HINT_PORTS))

    def test_parse_ports_single_and_range(self):
        self.assertEqual(ports.parse_ports("80,443,8000-8002"),
                         [80, 443, 8000, 8001, 8002])

    def test_parse_ports_dedup_and_sort(self):
        self.assertEqual(ports.parse_ports("443,80,80,443,22"), [22, 80, 443])

    def test_parse_ports_reversed_range(self):
        self.assertEqual(ports.parse_ports("8002-8000"), [8000, 8001, 8002])

    def test_parse_ports_all(self):
        allports = ports.parse_ports("all")
        self.assertEqual(allports[0], 1)
        self.assertEqual(allports[-1], 65535)
        self.assertEqual(len(allports), 65535)

    def test_parse_ports_empty_raises(self):
        with self.assertRaises(ValueError):
            ports.parse_ports("")

    def test_parse_ports_bad_token(self):
        with self.assertRaises(ValueError):
            ports.parse_ports("80,abc,443")

    def test_parse_ports_out_of_range(self):
        with self.assertRaises(ValueError):
            ports.parse_ports("70000")

    def test_scheme_for_port(self):
        cases = {80: "http", 443: "https", 3000: "http", 8080: "http",
                 8443: "https", 6443: "https", 10443: "https", 9999: "http",
                 22: None, 12345: None}
        for port, expected in cases.items():
            with self.subTest(port=port):
                self.assertEqual(ports.scheme_for_port(port), expected)

    def test_scan_ports_empty_list(self):
        self.assertEqual(ports.scan_ports("127.0.0.1", [], timeout=0.1), [])

    def test_scan_ports_zero_workers_does_not_crash(self):
        result = ports.scan_ports("127.0.0.1", [1], timeout=0.1, workers=0)
        self.assertIsInstance(result, list)


# --------------------------------------------------------------------------- #
# version verdicts
# --------------------------------------------------------------------------- #
class TestVersions(unittest.TestCase):
    def test_node_version_verdict(self):
        cases = [
            (None, None), ((22, 23, 3), "vulnerable"), ((22, 23, 4), "patched"),
            ((24, 0, 0), "vulnerable"), ((24, 22, 1), "patched"), ((26, 12, 1), "patched"),
            ((21, 0, 0), "vulnerable"), ((23, 5, 0), "vulnerable"), ((18, 0, 0), "vulnerable"),
            ((9, 0, 0), None), ((27, 0, 0), None),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                self.assertEqual(n._node_version_verdict(version), expected)

    def test_bun_version_verdict(self):
        cases = [
            (None, None), ((1, 4, 3), "vulnerable"), ((1, 4, 4), "patched"),
            ((1, 0, 20), None), ((1, 2, 0), "vulnerable"),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                self.assertEqual(n._bun_version_verdict(version), expected)

    def test_php_version_verdict(self):
        cases = [
            ((8, 2, 34), "vulnerable"), ((8, 2, 35), "patched"), ((8, 5, 12), "patched"),
            ((8, 5, 11), "vulnerable"), ((8, 1, 0), "vulnerable"), ((7, 4, 0), "vulnerable"),
            ((8, 6, 0), None),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                self.assertEqual(p._version_verdict(version), expected)

    def test_envoy_verdict_none(self):
        self.assertEqual(n._envoy_verdict("Server: nginx"), (None, None))

    def test_envoy_verdict_vulnerable(self):
        verdict, label = n._envoy_verdict("server: envoy/1.37.5")
        self.assertEqual(verdict, "vulnerable")
        self.assertIn("1.37.5", label)

    def test_envoy_verdict_patched(self):
        verdict, _ = n._envoy_verdict("server: envoy/1.40.0")
        self.assertEqual(verdict, "patched")

    def test_envoy_verdict_unknown_no_version(self):
        verdict, label = n._envoy_verdict("via: envoy")
        self.assertEqual(verdict, "unknown")
        self.assertIn("Envoy", label)


# --------------------------------------------------------------------------- #
# WAF
# --------------------------------------------------------------------------- #
class TestWaf(unittest.TestCase):
    def test_detect_waf_header_key(self):
        self.assertEqual(waf.detect_waf(FakeResponse(headers={"cf-ray": "abc"})), "Cloudflare")
        self.assertEqual(waf.detect_waf(FakeResponse(headers={"x-sucuri-id": "1"})), "Sucuri")

    def test_detect_waf_server_regex(self):
        self.assertEqual(waf.detect_waf(FakeResponse(headers={"Server": "Apache mod_security"})),
                         "ModSecurity")
        self.assertEqual(waf.detect_waf(FakeResponse(headers={"Server": "cloudflare"})), "Cloudflare")

    def test_detect_waf_cookie(self):
        self.assertEqual(waf.detect_waf(FakeResponse(cookies=["visid_incap_9"])), "Imperva")
        self.assertEqual(waf.detect_waf(FakeResponse(cookies=["datadome"])), "DataDome")

    def test_detect_waf_none(self):
        self.assertIsNone(waf.detect_waf(FakeResponse(headers={"Server": "nginx"})))

    def test_bypass_multipart_headers(self):
        h = waf.bypass_multipart_headers("BND")
        self.assertIn("boundary=BND", h["Content-Type"])
        self.assertEqual(h["Transfer-Encoding"], "chunked")
        self.assertEqual(h["X-Forwarded-For"], "127.0.0.1")

    def test_bypass_brotli_headers_sets_encoding(self):
        h = waf.bypass_brotli_headers({"Accept": "*/*"})
        self.assertEqual(h["Content-Encoding"], "br")
        self.assertEqual(h["Transfer-Encoding"], "chunked")
        self.assertEqual(h["Accept"], "*/*")


# --------------------------------------------------------------------------- #
# PHP active-probe state machine
# --------------------------------------------------------------------------- #
class TestPhpProbe(unittest.TestCase):
    def test_active_check_fatal_is_vulnerable_signal(self):
        session = ScriptedSession(posts=[
            FakeResponse(200, "PHP Fatal error: Allowed memory size of 134217728 bytes "
                              "exhausted (tried to allocate ...)"),
        ])
        state, _, _ = p._active_check(session, "http://t/index.php", pre_control=FakeResponse(200))
        self.assertEqual(state, "fatal")

    def test_active_check_host_drops_both(self):
        import requests
        session = ScriptedSession(posts=[requests.ConnectionError(), requests.ConnectionError()])
        state, detail, _ = p._active_check(session, "http://t/index.php", pre_control=FakeResponse(200))
        self.assertEqual(state, "probe_inconclusive")
        self.assertIn("unreachable", detail)

    def test_active_check_timeout_degrades(self):
        import requests
        session = ScriptedSession(posts=[requests.Timeout(), FakeResponse(200)])
        state, detail, _ = p._active_check(session, "http://t/index.php", pre_control=FakeResponse(200))
        self.assertEqual(state, "probe_inconclusive")
        self.assertIn("limit", detail)

    def test_dropped_probe_is_never_vulnerable(self):
        import requests
        session = ScriptedSession(posts=[requests.ConnectionError(), FakeResponse(200)])
        state, _, _ = p._active_check(session, "http://t/index.php", pre_control=FakeResponse(200))
        self.assertNotIn(state, ("fatal", "empty_500"))
        self.assertEqual(state, "probe_inconclusive")

    def test_dropped_probe_with_vuln_distro_is_likely(self):
        import requests
        php_headers = {"X-Powered-By": "PHP/8.2.10-ubuntu", "Server": "Apache"}
        session = ScriptedSession(
            gets=[FakeResponse(200, headers=php_headers)] * 3,
            posts=[FakeResponse(200), requests.ConnectionError(), FakeResponse(200)],
        )
        _, finding = p._evaluate(session, "http://t")
        self.assertEqual(finding.verdict, LIKELY)


# --------------------------------------------------------------------------- #
# target parsing + JSON report
# --------------------------------------------------------------------------- #
class TestReport(unittest.TestCase):
    def test_read_target_file_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "targets.txt"
            f.write_text("# comment\nexample.com\n\n   \n10.0.0.5\n# trailing\n", encoding="utf-8")
            self.assertEqual(shell2scan.read_target_file(str(f)), ["example.com", "10.0.0.5"])

    def test_parse_targets_input_dedup(self):
        self.assertEqual(
            shell2scan._parse_targets_input("example.com, example.com 10.0.0.5"),
            ["example.com", "10.0.0.5"],
        )

    def test_resolve_ports_default(self):
        self.assertEqual(shell2scan.resolve_ports(""), list(ports.DEFAULT_WEB_PORTS))
        self.assertEqual(shell2scan.resolve_ports("default"), list(ports.DEFAULT_WEB_PORTS))

    def test_write_report_metadata_and_labels(self):
        groups = [
            ("example.com", [Finding("PHP2Shell", "CVE-X", "https://example.com",
                                     VULNERABLE, "vulnerable version advertised", 200)]),
            ("safe.example", [Finding("Node2Shell", "CVE-Y", "https://safe.example",
                                      CLEAR, "patched", 200)]),
        ]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.json"
            shell2scan.write_report(str(out), groups, ["PHP2Shell", "Node2Shell"],
                                    params={"scheme": None})
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(data["schema_version"], shell2scan.REPORT_SCHEMA_VERSION)
        self.assertEqual(data["tool"], "shell2scan")
        self.assertEqual(data["version"], __version__)
        self.assertEqual(data["summary"], {"targets": 2, "findings": 2, "vulnerable": 1})
        self.assertEqual(data["parameters"], {"scheme": None})
        self.assertEqual(data["targets"][0]["findings"][0]["verdict_label"], "VULNERABLE")
        self.assertEqual(data["targets"][1]["findings"][0]["verdict_label"], "NOT VULNERABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
