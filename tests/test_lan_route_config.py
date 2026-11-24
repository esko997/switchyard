from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from switchyard import lan_route_config as lrc

CA = "a" * 64
ADOPT = "b" * 64


def document(**changes):
    data = {
        "gateway_id": "lan-web", "dns_id": "lan-dns", "zone": "example.test", "gateway_ip": "192.168.50.233",
        "ca_sha256": CA, "adopt_caddy_sha256": ADOPT,
        "adopt_routes": [{"hostname": "chat.example.test", "workload_id": "open-webui", "endpoint_id": "http"},
                         {"hostname": "cards.example.test", "workload_id": "learning-box", "endpoint_id": "https"}],
        "observed_endpoints": [
            {"workload_id": "learning-box", "endpoint_id": "https", "host_id": "host-b", "address": "192.168.50.233",
             "port": 8443, "scheme": "https", "profile": "verified-https", "ca_file": "learning-box-ca.crt"},
            {"workload_id": "usenet", "endpoint_id": "sabnzbd", "host_id": "host-b", "address": "192.168.50.233",
             "port": 9999, "scheme": "http", "profile": "plain", "hostnames": ["sab.example.test"]},
            {"workload_id": "usenet", "endpoint_id": "mylar", "host_id": "host-b", "address": "192.168.50.233",
             "port": 8090, "scheme": "http", "profile": "rewrite-redirect"},
            {"workload_id": "usenet", "endpoint_id": "prowlarr", "host_id": "host-b", "address": "192.168.50.233",
             "port": 9696, "scheme": "http", "profile": "plain"}],
    }
    data.update(changes)
    return data


def observed(workload_id, host_id="host-b", resource_kind="service"):
    return {"id": workload_id, "relation": "observed", "data": {
        "applications": [{"id": workload_id, "components": [{"id": "main", "native": {
            "kind": "observed", "backend": "podman", "resource_kind": resource_kind}}]}],
        "placements": [{"id": workload_id, "host_id": host_id, "state": "declared", "ownership": "adopted"}]}}


def deployed(instance_id, *, host_id="host-e", state="active", address="192.168.50.104", port=3000,
             protocol="tcp", check="http", scheme="http", uncertain=False):
    checks = [] if check is None else [{"id": "ready", "component": "app", "type": check, "endpoint": "http",
                                        **({"scheme": scheme} if check == "http" else {})}]
    instance = {"id": instance_id, "revision": 1, "application": {
        "id": instance_id, "endpoints": [{"id": "http", "component": "app", "protocol": protocol, "target_port": 8080}],
        "health_checks": checks}}
    placement = {"instance_id": instance_id, "generation": 1, "host_id": host_id, "state": state, "revision": 3,
                 "placement": {"endpoints": [{"endpoint": "http", "address": address, "host_port": port}]},
                 "meta": {"uncertain": uncertain}}
    return instance, placement


class FakeStore:
    """The WorkloadStore read interface endpoint_scan uses (one snapshot, static methods taking `db`)."""

    def __init__(self, observed_records=(), instances=(), claims=None):
        self.observed = {item["id"]: item for item in observed_records}
        self.instances = {instance["id"]: (instance, placement) for instance, placement in instances}
        self.claims = claims or {}
        self.reads = 0

    @contextmanager
    def reading(self):
        self.reads += 1
        yield "db"

    def records(self, db, relation=None):
        assert db == "db"
        if relation == "observed":
            return list(self.observed.values())
        if relation == "deployed":
            return [{"id": key, "relation": "deployed"} for key in sorted(self.instances)]
        raise AssertionError(relation)

    def relation_of(self, db, workload_id):
        if workload_id in self.observed:
            return "observed"
        return "deployed" if workload_id in self.instances else None

    def instance_row(self, db, instance_id):
        return deepcopy(self.instances[instance_id][0])

    def placement_row(self, db, instance_id):
        return deepcopy(self.instances[instance_id][1])

    def claims_for(self, db, owner_id):
        return list(self.claims.get(owner_id, []))


def claim(host_id, address, port, protocol="tcp", owner_kind="placement"):
    return {"host_id": host_id, "address": address, "protocol": protocol, "port": port, "endpoint": "e",
            "owner_kind": owner_kind, "generation": 1, "expires_at": None}


def standard_store(**extra):
    instances = [deployed("open-webui"), deployed("comfyui", state="fenced", port=8188),
                 deployed("lan-web", host_id="host-b", address="192.168.50.233", port=443)]
    return FakeStore([observed("learning-box"), observed("usenet")], instances + list(extra.get("instances", [])),
                     claims=extra.get("claims"))


class ConfigTests(unittest.TestCase):
    def test_normalize_sorts_and_fills_optional_keys(self):
        config = lrc.normalize(document())
        self.assertEqual([r["hostname"] for r in config["adopt_routes"]], ["cards.example.test", "chat.example.test"])
        self.assertEqual([(e["workload_id"], e["endpoint_id"]) for e in config["observed_endpoints"]],
                         [("learning-box", "https"), ("usenet", "mylar"), ("usenet", "prowlarr"), ("usenet", "sabnzbd")])
        self.assertIsNone(config["observed_endpoints"][1]["hostnames"])
        self.assertEqual([e["ca_file"] for e in config["observed_endpoints"]], ["learning-box-ca.crt", None, None, None])
        minimal = lrc.normalize({"gateway_id": "lan-web", "dns_id": "lan-dns", "zone": "example.test", "ca_sha256": CA})
        self.assertEqual(minimal, {"gateway_id": "lan-web", "dns_id": "lan-dns", "zone": "example.test", "gateway_ip": None,
                                   "ca_sha256": CA, "adopt_caddy_sha256": None, "adopt_routes": [], "observed_endpoints": []})

    def test_refuses_unknown_keys_bad_values_and_injection(self):
        def endpoint(**changes):
            item = dict(document()["observed_endpoints"][3])
            item.update(changes)
            return document(observed_endpoints=[item])

        bad = [
            document(extra=1), document(ca_sha256="A" * 64), document(zone="Example.test"), document(gateway_id="lan-dns"),
            document(gateway_ip="8.8.8.8"), document(gateway_ip="127.0.0.1"), document(adopt_caddy_sha256=None),
            document(adopt_routes=[{"hostname": "chat.other.lan", "workload_id": "a", "endpoint_id": "b"}]),
            document(adopt_routes=[{"hostname": "example.test", "workload_id": "a", "endpoint_id": "b"}]),
            document(adopt_routes=[{"hostname": "x.example.test", "workload_id": "a", "endpoint_id": "b"}] * 2),
            document(adopt_routes=[{"hostname": "x.example.test {\n", "workload_id": "a", "endpoint_id": "b"}]),
            endpoint(address="0.0.0.0"), endpoint(address="8.8.8.8"), endpoint(address="127.0.0.1"),
            endpoint(address="192.168.050.233"), endpoint(address="fd00::1"), endpoint(port=0), endpoint(port=True),
            endpoint(port="80"), endpoint(scheme="https"), endpoint(profile="raw"), endpoint(workload_id="lan-web"),
            endpoint(endpoint_id="a b"), endpoint(unknown=1), endpoint(hostnames=[]), endpoint(hostnames=["x.other.lan"]),
            endpoint(profile="verified-https", scheme="https"), endpoint(ca_file="x.crt"),
            *[endpoint(profile="verified-https", scheme="https", ca_file=name)
              for name in ("../x.crt", "/etc/x.crt", "Caddyfile", ".x.crt", "x.crt\n", "a b.crt", 1)],
            document(observed_endpoints=[document()["observed_endpoints"][3]] * 2),
            document(observed_endpoints=[{**document()["observed_endpoints"][3], "endpoint_id": f"e{i}"} for i in range(2)]),
            document(observed_endpoints=[{**document()["observed_endpoints"][3], "endpoint_id": f"e{i}", "port": 1000 + i}
                                         for i in range(lrc.MAX_ENDPOINTS + 1)]),
        ]
        for data in bad:
            with self.subTest(data=json.dumps(data)[:160]), self.assertRaises(ValueError):
                lrc.normalize(data)

    def test_load_requires_private_bounded_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "home-lab.lan-routes.json"
            path.write_text(json.dumps(document()))
            os.chmod(path, 0o600)
            self.assertEqual(lrc.load(path), lrc.normalize(document()))
            os.chmod(path, 0o620)
            with self.assertRaisesRegex(ValueError, "writable"):
                lrc.load(path)
            os.chmod(path, 0o600)
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                lrc.load(link)
            path.write_text(json.dumps({**document(), "pad": "x" * lrc.CONFIG_LIMIT}))
            with self.assertRaisesRegex(ValueError, "larger"):
                lrc.load(path)
            path.write_text('{"gateway_id": NaN}')
            with self.assertRaisesRegex(ValueError, "JSON"):
                lrc.load(path)
            with self.assertRaises(FileNotFoundError):  # unconfigured, not an error
                lrc.load(Path(directory) / "missing.json")


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.config = lrc.normalize(document())

    def test_rows_are_configured_observed_and_checked_deployed_only(self):
        rows, skipped = lrc.endpoint_scan(standard_store(), self.config)
        self.assertEqual([(r["workload_id"], r["endpoint_id"], r["relation"]) for r in rows], [
            ("comfyui", "http", "deployed"), ("learning-box", "https", "observed"), ("open-webui", "http", "deployed"),
            ("usenet", "mylar", "observed"), ("usenet", "prowlarr", "observed"), ("usenet", "sabnzbd", "observed")])
        self.assertEqual(skipped, [])
        webui = next(r for r in rows if r["workload_id"] == "open-webui")
        self.assertEqual(webui, {"workload_id": "open-webui", "endpoint_id": "http", "address": "192.168.50.104",
                                 "port": 3000, "scheme": "http", "profile": "plain", "host_id": "host-e",
                                 "relation": "deployed", "hostnames": None, "ca_file": None})
        sab = next(r for r in rows if r["endpoint_id"] == "sabnzbd")
        self.assertEqual(sab["hostnames"], ["sab.example.test"])
        self.assertEqual(lrc.endpoint_candidates(standard_store(), self.config), rows)

    def test_deployed_endpoints_need_lan_tcp_claim_http_check_and_a_certain_placement(self):
        cases = {
            "wild": deployed("wild", address="0.0.0.0"), "loop": deployed("loop", address="127.0.0.1"),
            "udp": deployed("udp", protocol="udp"), "nocheck": deployed("nocheck", check=None),
            "tcpcheck": deployed("tcpcheck", check="tcp"), "tlscheck": deployed("tlscheck", scheme="https"),
            "unsure": deployed("unsure", uncertain=True),
        }
        hidden = [deployed("gone", state="retired"), deployed("lan-dns", host_id="host-b", address="192.168.50.233", port=8080)]
        rows, skipped = lrc.endpoint_scan(standard_store(instances=list(cases.values()) + hidden), self.config)
        ids = {r["workload_id"] for r in rows}
        self.assertFalse(ids & (set(cases) | {"gone", "lan-dns", "lan-web"}))
        self.assertEqual(sorted(item["workload_id"] for item in skipped), sorted(cases))
        self.assertIn("uncertain", next(i for i in skipped if i["workload_id"] == "unsure")["reason"])

    def test_observed_endpoints_verify_record_host_registry_and_gateway_claims(self):
        store = FakeStore([observed("learning-box", host_id="other"), observed("usenet", resource_kind="scheduled-job")],
                          [deployed("open-webui")])
        rows, skipped = lrc.endpoint_scan(store, self.config)
        self.assertEqual([r["workload_id"] for r in rows], ["open-webui"])
        reasons = {(i["workload_id"], i["endpoint_id"]): i["reason"] for i in skipped}
        self.assertIn("bound on other", reasons[("learning-box", "https")])
        self.assertIn("not a service", reasons[("usenet", "mylar")])

        store = FakeStore([], [deployed("learning-box")])  # same ID, but deployed: not the configured observed service
        rows, skipped = lrc.endpoint_scan(store, self.config)
        self.assertIn("(it is deployed)", next(i for i in skipped if i["workload_id"] == "learning-box")["reason"])

        hosts = [{"id": "host-b", "collector": {"transport": "ssh", "target": "operator@192.168.50.232"}}]
        rows, skipped = lrc.endpoint_scan(standard_store(), self.config, hosts=hosts)
        self.assertFalse([r for r in rows if r["relation"] == "observed"])
        self.assertTrue(all("registry address 192.168.50.232" in i["reason"] for i in skipped))
        hosts[0]["collector"]["target"] = "operator@192.168.50.233"
        rows, _ = lrc.endpoint_scan(standard_store(), self.config, hosts=hosts)
        self.assertEqual(len([r for r in rows if r["relation"] == "observed"]), 4)

        claims = {"lan-web": [claim("host-b", "0.0.0.0", 9696)], "lan-dns": [claim("host-e", "192.168.50.104", 3000)]}
        rows, skipped = lrc.endpoint_scan(standard_store(claims=claims), self.config)
        self.assertEqual({(i["workload_id"], i["endpoint_id"]) for i in skipped}, {("usenet", "prowlarr"), ("open-webui", "http")})
        claims = {"lan-web": [claim("host-b", "0.0.0.0", 3000), claim("host-b", "192.168.50.233", 9696, owner_kind="plan")]}
        rows, skipped = lrc.endpoint_scan(standard_store(claims=claims), self.config)
        self.assertEqual(skipped, [])  # another host's wildcard and an unplaced plan claim block nothing


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.config = lrc.normalize(document())
        self.rows = lrc.endpoint_candidates(standard_store(), self.config)

    def test_route_resolves_exact_candidate_with_relative_or_full_name(self):
        expected = {"hostname": "chat.example.test", "workload_id": "open-webui", "endpoint_id": "http",
                    "address": "192.168.50.104", "port": 3000, "scheme": "http", "profile": "plain"}
        self.assertEqual(lrc.route(self.config, self.rows, "chat", "open-webui", "http"), expected)
        self.assertEqual(lrc.route(self.config, self.rows, " Chat.Example.Test. ", "open-webui", "http"), expected)

    def test_route_refusals(self):
        for hostname, workload, endpoint in [
            ("chat.other.lan", "open-webui", "http"), ("example.test", "open-webui", "http"), ("", "open-webui", "http"),
            ("a_b", "open-webui", "http"), ("x" * 64, "open-webui", "http"), ("chat\nfoo", "open-webui", "http"),
            ("chat", "open-webui", "https"), ("chat", "missing", "http"), ("chat", "lan-web", "http"),
            ("downloads", "usenet", "sabnzbd"), (None, "open-webui", "http"),
        ]:
            with self.subTest(hostname=hostname, workload=workload, endpoint=endpoint), self.assertRaises(ValueError):
                lrc.route(self.config, self.rows, hostname, workload, endpoint)
        sab = lrc.route(self.config, self.rows, "sab", "usenet", "sabnzbd")
        self.assertEqual((sab["hostname"], sab["profile"]), ("sab.example.test", "plain"))
        self.assertEqual(lrc.route(self.config, self.rows, "cards", "learning-box", "https")["profile"], "verified-https")

    def test_check_route_refuses_untrusted_profiles_and_gateway_loops(self):
        good = lrc.route(self.config, self.rows, "mylar", "usenet", "mylar")
        self.assertEqual(lrc.check_route(self.config, {**good, "url": "https://mylar.example.test/"}), good)
        for changes in [{"port": 8091}, {"profile": "plain"}, {"scheme": "https"}, {"address": "192.168.50.9"},
                        {"hostname": "mylar.example.test\n}"}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                lrc.check_route(self.config, {**good, **changes})
        plain = lrc.route(self.config, self.rows, "chat", "open-webui", "http")
        with self.assertRaises(ValueError):  # a plain route cannot claim an HTTPS upstream
            lrc.check_route(self.config, {**plain, "scheme": "https"})
        with self.assertRaises(ValueError):
            lrc.check_route(self.config, {**plain, "address": "192.168.50.233", "port": 443}, "192.168.50.233")
        with self.assertRaises(ValueError):  # a hostname allowlist holds for plain endpoints too
            lrc.check_route(self.config, {**plain, "hostname": "other.example.test", "workload_id": "usenet",
                                          "endpoint_id": "sabnzbd", "address": "192.168.50.233", "port": 9999})
        with self.assertRaises(ValueError):  # a configured endpoint's stored route must still match the configuration
            lrc.check_route(self.config, {**plain, "hostname": "prowlarr.example.test", "workload_id": "usenet",
                                          "endpoint_id": "prowlarr", "address": "192.168.50.233", "port": 9697})

    def test_probe_value_is_digest_of_snapshot_only(self):
        item = lrc.route(self.config, self.rows, "chat", "open-webui", "http")
        value = lrc.probe_value(item)
        self.assertRegex(value, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(value, lrc.probe_value({**item, "url": "https://chat.example.test/", "relation": "deployed"}))
        text = lrc.RENDER_VERSION + "\n" + json.dumps(item, sort_keys=True, separators=(",", ":"))
        self.assertEqual(value, hashlib.sha256(text.encode()).hexdigest())
        self.assertNotEqual(value, lrc.probe_value({**item, "port": 3001}))
        self.assertNotEqual(value, lrc.probe_value({**item, "hostname": "talk.example.test"}))


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.config = lrc.normalize(document())
        rows = lrc.endpoint_candidates(standard_store(), self.config)
        self.routes = [lrc.route(self.config, rows, *args) for args in [
            ("mylar", "usenet", "mylar"), ("chat", "open-webui", "http"), ("cards", "learning-box", "https"),
            ("sab", "usenet", "sabnzbd")]]

    def test_render_is_deterministic_and_keeps_baseline(self):
        text = lrc.render(self.config, "192.168.50.233", self.routes)
        self.assertEqual(text, lrc.render(self.config, "192.168.50.233", list(reversed(self.routes))))
        self.assertTrue(text.startswith("{\n    admin off\n    persist_config off\n    skip_install_trust\n"
                                        "    auto_https disable_redirects\n    https_port 8443\n"))
        self.assertIn("(lan_tls) {\n    tls internal\n}\n", text)
        self.assertIn("    @ca {\n        host 192.168.50.233\n        path /caddy-root.crt\n        method GET HEAD\n    }\n", text)
        self.assertIn('header Content-Disposition "attachment; filename=example-test-caddy-ca.crt"', text)
        self.assertIn("    @known host cards.example.test chat.example.test mylar.example.test sab.example.test\n"
                      "    handle @known {\n        redir https://{host}{uri} 308\n    }\n    handle {\n        respond 404\n", text)
        self.assertIn("http://:9090 {\n    respond /healthz 200\n}\n", text)
        sites = re.findall(r"^([a-z0-9.-]+) \{$", text, re.M)
        self.assertEqual(sites, ["cards.example.test", "chat.example.test", "mylar.example.test", "sab.example.test"])
        self.assertNotIn("{{", text)
        self.assertTrue(text.endswith("}\n"))

    def test_each_site_answers_its_probe_before_proxying(self):
        text = lrc.render(self.config, "192.168.50.233", self.routes)
        chat = next(r for r in self.routes if r["hostname"] == "chat.example.test")
        self.assertIn("chat.example.test {\n    import lan_tls\n    @switchyard_route {\n        method GET\n"
                      "        path /.well-known/switchyard-route\n    }\n    handle @switchyard_route {\n"
                      '        respond "' + lrc.probe_value(chat) + '" 200\n    }\n    handle {\n'
                      "        reverse_proxy 192.168.50.104:3000\n    }\n}\n", text)
        self.assertIn("        reverse_proxy https://192.168.50.233:8443 {\n            transport http {\n"
                      "                tls_trust_pool file /etc/caddy/learning-box-ca.crt\n            }\n        }\n", text)
        self.assertIn('        reverse_proxy 192.168.50.233:8090 {\n            header_down Location '
                      '"^http://(?:192\\.168\\.50\\.233:8090|mylar\\.example\\.test)(/.*)$" "https://mylar.example.test$1"\n'
                      "        }\n", text)
        self.assertIn("        reverse_proxy 192.168.50.233:9999\n", text)
        self.assertEqual(text.count("respond \""), 4)
        self.assertEqual(lrc.ca_files(self.config, self.routes), ["learning-box-ca.crt"])
        self.assertEqual(lrc.ca_files(self.config, [chat]), [])

    def test_ca_file_comes_from_the_configured_endpoint(self):
        data = document()
        data["observed_endpoints"][0]["ca_file"] = "home-ca.pem"
        config = lrc.normalize(data)
        cards = next(r for r in self.routes if r["hostname"] == "cards.example.test")
        self.assertIn("tls_trust_pool file /etc/caddy/home-ca.pem\n", lrc.render(config, "192.168.50.233", [cards]))
        self.assertEqual(lrc.ca_files(config, [cards]), ["home-ca.pem"])
        self.assertNotIn("learning-box", lrc.render(config, "192.168.50.233", [cards]).replace("cards.example.test", ""))

    def test_render_without_routes_has_no_known_matcher(self):
        text = lrc.render(self.config, "192.168.50.233", [])
        self.assertNotIn("@known", text)
        self.assertIn("    }\n    handle {\n        respond 404\n    }\n}\n", text)

    def test_render_refusals(self):
        chat = next(r for r in self.routes if r["hostname"] == "chat.example.test")
        for gateway_ip, routes in [
            ("8.8.8.8", []), ("192.168.50.234", []), ("192.168.50.233", [chat, dict(chat)]),
            ("192.168.50.233", [{**chat, "address": "192.168.50.104 { }"}]),
            ("192.168.50.233", [{**chat, "hostname": "chat.example.test\nevil.example.test"}]),
            ("192.168.50.233", [{**chat, "port": "3000"}]), ("192.168.50.233", [{**chat, "address": "192.168.50.233", "port": 80}]),
            ("192.168.50.233", [{k: v for k, v in chat.items() if k != "scheme"}]),
            ("192.168.50.233", "chat"),
            ("192.168.50.233", [{**chat, "hostname": f"h{i}.example.test"} for i in range(lrc.MAX_ROUTES + 1)]),
        ]:
            with self.subTest(gateway_ip=gateway_ip, routes=str(routes)[:120]), self.assertRaises(ValueError):
                lrc.render(self.config, gateway_ip, routes)
        config = lrc.normalize(document(gateway_ip=None))
        self.assertIn("host 192.168.50.234", lrc.render(config, "192.168.50.234", [chat]))

    def test_maximum_render_fits_the_config_limit(self):
        chat = next(r for r in self.routes if r["hostname"] == "chat.example.test")
        routes = [{**chat, "hostname": ("h" + str(i)).ljust(63, "x") + ".example.test"} for i in range(lrc.MAX_ROUTES)]
        text = lrc.render(self.config, "192.168.50.233", routes)
        self.assertLessEqual(len(text.encode()), 65536)


if __name__ == "__main__":
    unittest.main()
