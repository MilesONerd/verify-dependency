# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Runtime network guard: the script only talks to allowlisted hosts over https, and never follows a redirect elsewhere.
These are behavioral tests (real sockets and a recording opener), not source analysis."""
import base64
import hashlib
import json
import os
import socketserver
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import http.server
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import check_dep as c  # noqa: E402


class AllowedUrls(unittest.TestCase):
    def test_accepts_registry_urls_over_https(self):
        for url in ("https://registry.npmjs.org/express", "https://REGISTRY.NPMJS.ORG/express", "https://api.github.com/repos/a/b",
                    "https://crates.io:443/api/v1/crates/serde"):
            with self.subTest(url=url):
                self.assertTrue(c._allowed(url))

    def test_refuses_everything_else(self):
        for url in ("http://registry.npmjs.org/express", "https://evil.example.com/x", "https://registry.npmjs.org.evil.com/x",
                    "https://registry.npmjs.org@evil.com/x", "https://user:pw@registry.npmjs.org/x", "https://registry.npmjs.org:8443/x",
                    "http://169.254.169.254/latest/meta-data", "https://localhost/x", "file:///etc/passwd", "ftp://pypi.org/x", "https://gitlab.com/a/b", ""):
            with self.subTest(url=url):
                self.assertFalse(c._allowed(url))

    def test_get_refuses_before_opening_a_connection(self):
        opener = mock.Mock()
        with mock.patch.object(c, "_OPENER", opener), self.assertRaises(c.NetErr):
            c.get("https://evil.example.com/x")
        opener.open.assert_not_called()


class Redirects(unittest.TestCase):
    def test_redirect_to_a_disallowed_host_is_refused(self):
        handler = c._SafeRedirect()
        req = urllib.request.Request("https://registry.npmjs.org/x")
        for target in ("https://evil.example.com/x", "http://registry.npmjs.org/x", "https://registry.npmjs.org@evil.com/", "http://127.0.0.1/"):
            with self.subTest(target=target), self.assertRaises(urllib.error.URLError):
                handler.redirect_request(req, None, 302, "Found", {}, target)

    def test_redirect_within_the_allowlist_is_followed(self):
        handler = c._SafeRedirect()
        new = handler.redirect_request(urllib.request.Request("https://api.github.com/repos/a/b"), None, 301, "Moved", {}, "https://api.github.com/repositories/1")
        self.assertEqual(new.full_url, "https://api.github.com/repositories/1")


class LocalServers(unittest.TestCase):
    """Two real servers on different host names: A redirects to B, and B must never be contacted."""

    def setUp(self):
        self.hits_b = []
        hits = self.hits_b

        class B(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"reached": "B"}')

            def log_message(self, *a):
                pass

        self.b = socketserver.TCPServer(("127.0.0.1", 0), B)
        port_b = self.b.server_address[1]

        class A(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/ok":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"ok": true}')
                elif self.path == "/same-host":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.end_headers()
                else:
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{port_b}/stolen")
                    self.end_headers()

            def log_message(self, *a):
                pass

        self.a = socketserver.TCPServer(("127.0.0.1", 0), A)
        self.port_a = self.a.server_address[1]
        for srv in (self.a, self.b):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        patches = [mock.patch.object(c, "FETCH_HOSTS", frozenset({"127.0.0.1"})), mock.patch.object(c, "ALLOWED_SCHEMES", ("http", "https")),
                   mock.patch.object(c, "ALLOWED_PORTS", (None, 443, self.port_a)),
                   mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_positive_control_an_allowed_host_works(self):
        self.assertEqual(c.get(f"http://127.0.0.1:{self.port_a}/ok"), (200, {"ok": True}))

    def test_redirect_inside_the_same_allowed_host_is_followed(self):
        self.assertEqual(c.get(f"http://127.0.0.1:{self.port_a}/same-host"), (200, {"ok": True}))

    def test_redirect_to_another_host_is_refused_and_that_host_is_never_contacted(self):
        with self.assertRaises(c.NetErr):
            c.get(f"http://127.0.0.1:{self.port_a}/elsewhere")
        self.assertEqual(self.hits_b, [])


def _attestation_for(digest):
    statement = {"subject": [{"name": "pkg:npm/pkg@1.0.0", "digest": {"sha512": digest}}], "predicateType": "https://slsa.dev/provenance/v1",
                 "predicate": {"buildDefinition": {"externalParameters": {"workflow": {"repository": "https://github.com/a/b", "ref": "r"}}}}}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1", "bundle": {"dsseEnvelope": {"payload": payload}}}]}


_HEX = hashlib.sha512(b"t").hexdigest()
_NPM = {"dist-tags": {"latest": "1.0.0"}, "time": {"created": "2015-01-01T00:00:00", "1.0.0": "2020-01-01T00:00:00"}, "maintainers": [{"name": "m"}],
        "versions": {"1.0.0": {"_npmUser": {"name": "m"}, "dist": {"integrity": "sha512-" + base64.b64encode(bytes.fromhex(_HEX)).decode(),
                                                                      "attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.0"}}}},
        "repository": {"url": "git+https://github.com/a/b.git"}}
_GH = {"full_name": "a/b", "stargazers_count": 5, "archived": False, "fork": False, "pushed_at": "2026-01-01T00:00:00Z", "created_at": "2020-01-01T00:00:00Z", "license": None}
PAYLOADS = [  # (URL substring, response); the first match wins
    ("/-/npm/v1/attestations/", _attestation_for(_HEX)), ("api.npmjs.org", {"downloads": 5}), ("registry.npmjs.org", _NPM),
    ("pypistats.org", {"data": {"last_week": 5}}), ("pypi.org", {"info": {"version": "1", "project_urls": {"Source": "https://github.com/a/b"}}, "releases": {"1": [{"upload_time": "2020-01-01T00:00:00"}]}}),
    ("crates.io/api", {"crate": {"max_version": "1", "created_at": "2020-01-01T00:00:00", "repository": "https://github.com/a/b"}, "versions": [{"num": "1", "created_at": "2020-01-01T00:00:00"}]}),
    ("rubygems.org/api/v1/versions", [{"number": "1", "created_at": "2020-01-01T00:00:00Z"}]), ("rubygems.org", {"version": "1", "source_code_uri": "https://github.com/a/b"}),
    ("azuresearch", {"data": [{"id": "pkg", "version": "1", "totalDownloads": 5, "projectUrl": "https://github.com/a/b", "versions": [{}], "owners": []}]}),
    ("proxy.golang.org", "v1.0.0\n"), ("packagist.org", {"package": {"time": "2011-01-01T00:00:00+00:00", "repository": "https://github.com/a/b", "versions": {"1.0": {}}}}),
    ("aur.archlinux.org", {"resultcount": 1, "results": [{"Version": "1", "Maintainer": "m", "NumVotes": 1, "URL": "https://github.com/a/b"}]}),
    ("hex.pm", {"latest_version": "1", "releases": [{"version": "1", "inserted_at": "2020-01-01T00:00:00Z"}], "meta": {"links": {"GitHub": "https://github.com/a/b"}}}),
    ("pub.dev", {"latest": {"version": "1", "published": "2020-01-01T00:00:00Z", "pubspec": {"repository": "https://github.com/a/b"}}, "versions": [{"version": "1", "published": "2020-01-01T00:00:00Z"}]}),
    ("search.maven.org", {"response": {"numFound": 1, "docs": [{"latestVersion": "1", "versionCount": 1}]}}),
    ("api.github.com", _GH), ("raw.githubusercontent.com", '{"name": "pkg"}'), ("github.com", "<html>"),
]


class FakeResponse:
    def __init__(self, body):
        self._body = body if isinstance(body, str) else json.dumps(body)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body.encode()


class EveryRequestStaysOnAllowedHosts(unittest.TestCase):
    """Runs the real get() and every registry parser against a recording opener and checks each URL that would be requested."""

    def run_all(self, payloads):
        urls = []

        def fake_open(req, timeout=None):
            urls.append(req.full_url)
            for key, body in payloads:
                if key in req.full_url:
                    return FakeResponse(body)
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)

        opener = mock.Mock()
        opener.open.side_effect = fake_open
        with mock.patch.object(c, "_OPENER", opener):
            for eco, name in (("npm", "pkg"), ("pypi", "pkg"), ("crates", "pkg"), ("gem", "pkg"), ("nuget", "pkg"), ("go", "github.com/a/b"),
                              ("packagist", "v/p"), ("aur", "pkg"), ("hex", "pkg"), ("pub", "pkg"), ("maven", "g:a")):
                c.check(eco, name, repo=True)
            c.check("npm", "does-not-exist-zz", repo=True)  # exercises the search-suggestions path
        return urls

    def test_all_requests_use_https_on_allowlisted_hosts(self):
        urls = self.run_all(PAYLOADS)
        self.assertGreater(len(urls), 30)
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            self.assertEqual(parsed.scheme, "https", url)
            self.assertIn(parsed.hostname, c.FETCH_HOSTS, url)

    def test_every_allowlisted_registry_is_actually_used(self):
        hosts = {urllib.parse.urlparse(u).hostname for u in self.run_all(PAYLOADS)}
        self.assertTrue({"registry.npmjs.org", "pypi.org", "crates.io", "rubygems.org", "azuresearch-usnc.nuget.org", "proxy.golang.org", "packagist.org",
                         "aur.archlinux.org", "hex.pm", "pub.dev", "search.maven.org", "api.github.com", "raw.githubusercontent.com"} <= hosts)

    def test_repository_urls_chosen_by_a_package_never_decide_where_we_connect(self):
        evil = "https://evil.example.com/a/b"
        poisoned = []
        for key, body in PAYLOADS:
            text = json.dumps(body).replace("https://github.com/a/b", evil).replace("git+https://github.com/a/b.git", evil) if not isinstance(body, str) else body
            poisoned.append((key, text if isinstance(body, str) else json.loads(text)))
        urls = self.run_all(poisoned)
        self.assertFalse([u for u in urls if "evil.example.com" in u])
        for url in urls:
            self.assertIn(urllib.parse.urlparse(url).hostname, c.FETCH_HOSTS, url)

    def test_a_hostile_attestation_url_is_never_requested(self):
        hostile = json.loads(json.dumps(_NPM).replace("https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.0", "https://evil.example.com/steal"))
        urls = self.run_all([("registry.npmjs.org", hostile)] + [p for p in PAYLOADS if p[0] != "registry.npmjs.org"])
        self.assertFalse([u for u in urls if "evil.example.com" in u])


if __name__ == "__main__":
    unittest.main()
