"""Comprehensive tests for singboxconverter."""

import base64
import json
import os
import tempfile

import pytest

import singboxconverter as sbc
from singboxconverter.config.config import Config, _resolve_outbound, _parse_inbound_uri
from singboxconverter.config.outbound import (
    Direct, Block, Shadowsocks, Vmess, Vless, Trojan,
    Wireguard, Ssh, Socks, Http, Tls, Transport,
    Selector, Urltest, Wiregaurd,
)
from singboxconverter.config.inbound import (
    Mixed, Tun,
    Socks as SocksInbound,
    Http as HttpInbound,
)
from singboxconverter.config.utils import parse_rule, build_rule_sets
from singboxconverter.methods.log import build as build_log, LEVELS
from singboxconverter.methods.dns import build as build_dns, PRESETS
from singboxconverter.protocols import parse_outbound_uri
from singboxconverter.protocols import vless, shadowsocks, vmess, trojan


# ── helpers ───────────────────────────────────────────────────────────────

VLESS_URI = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fws&fp=chrome#my-vless"
TROJAN_URI = "trojan://mypassword@server.com:443?security=tls&sni=server.com#my-trojan"
SS_URI = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#my-ss"

def _vmess_uri(**overrides):
    data = {"v": "2", "ps": "my-vmess", "add": "5.6.7.8", "port": "443",
            "id": "test-uuid", "aid": "0", "scy": "auto", "net": "tcp",
            "type": "none", "host": "", "path": "", "tls": "", "sni": ""}
    data.update(overrides)
    encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"vmess://{encoded}"


def _build(config):
    """Build config and return parsed dict."""
    return json.loads(config.to_json())


# ══════════════════════════════════════════════════════════════════════════
#  1. LOG BUILDER
# ══════════════════════════════════════════════════════════════════════════

class TestLogBuilder:
    def test_all_valid_levels(self):
        for level in LEVELS:
            result = build_log(level)
            if level == "disable":
                assert result == {"disabled": True}
            else:
                assert result == {"level": level}

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            build_log("invalid")


# ══════════════════════════════════════════════════════════════════════════
#  2. DNS BUILDER
# ══════════════════════════════════════════════════════════════════════════

class TestDnsBuilder:
    def test_empty(self):
        assert build_dns([]) == {}

    def test_preset_names(self):
        result = build_dns(["google"])
        assert result["servers"][0]["address"] == "tls://8.8.8.8"
        assert result["servers"][0]["tag"] == "dns-0"
        assert result["final"] == "dns-0"

    def test_raw_address(self):
        result = build_dns(["tls://9.9.9.9"])
        assert result["servers"][0]["address"] == "tls://9.9.9.9"

    def test_multiple(self):
        result = build_dns(["google", "cloudflare"])
        assert len(result["servers"]) == 2
        assert result["servers"][0]["tag"] == "dns-0"
        assert result["servers"][1]["tag"] == "dns-1"

    def test_all_presets_exist(self):
        for name, addr in PRESETS.items():
            result = build_dns([name])
            assert result["servers"][0]["address"] == addr


# ══════════════════════════════════════════════════════════════════════════
#  3. RULE PARSING (utils.py)
# ══════════════════════════════════════════════════════════════════════════

class TestParseRule:
    def test_geosite(self):
        r = parse_rule("geosite:nsfw")
        assert r == {"rule_set": ["geosite-nsfw"]}

    def test_geoip(self):
        r = parse_rule("geoip:us")
        assert r == {"rule_set": ["geoip-us"]}

    def test_ip(self):
        r = parse_rule("1.2.3.4")
        assert r == {"ip_cidr": ["1.2.3.4/32"]}

    def test_ip_cidr(self):
        r = parse_rule("10.0.0.0/8")
        assert r == {"ip_cidr": ["10.0.0.0/8"]}

    def test_url(self):
        r = parse_rule("https://google.com/path")
        assert r == {"domain": ["google.com"]}

    def test_domain_suffix(self):
        r = parse_rule("example.com")
        assert r == {"domain_suffix": ["example.com"]}

    def test_domain_suffix_no_leading_dot(self):
        r = parse_rule("example.com")
        suffix = r["domain_suffix"][0]
        assert not suffix.startswith("."), f"domain_suffix must not have leading dot, got {suffix!r}"

    def test_domain_with_leading_dot_stripped(self):
        r = parse_rule(".example.com")
        assert r == {"domain_suffix": ["example.com"]}

    def test_invalid(self):
        with pytest.raises(ValueError):
            parse_rule("justabareword")


class TestBuildRuleSets:
    def test_geosite(self):
        rules = [{"rule_set": ["geosite-nsfw"], "outbound": "out-block"}]
        rs = build_rule_sets(rules)
        assert len(rs) == 1
        assert rs[0]["tag"] == "geosite-nsfw"
        assert rs[0]["type"] == "remote"
        assert rs[0]["format"] == "binary"
        assert "geosite-nsfw.srs" in rs[0]["url"]

    def test_geoip(self):
        rules = [{"rule_set": ["geoip-us"], "outbound": "out-direct"}]
        rs = build_rule_sets(rules)
        assert rs[0]["tag"] == "geoip-us"
        assert "geoip-us.srs" in rs[0]["url"]

    def test_dedup(self):
        rules = [
            {"rule_set": ["geosite-nsfw"], "outbound": "out-block"},
            {"rule_set": ["geosite-nsfw"], "outbound": "out-block"},
        ]
        rs = build_rule_sets(rules)
        assert len(rs) == 1

    def test_empty(self):
        assert build_rule_sets([]) == []
        assert build_rule_sets([{"outbound": "out-direct"}]) == []


# ══════════════════════════════════════════════════════════════════════════
#  4. OUTBOUND BUILDERS
# ══════════════════════════════════════════════════════════════════════════

class TestOutboundBuilders:
    def test_direct_defaults(self):
        d = Direct()
        assert d["type"] == "direct"
        assert d["tag"] == "out-direct"

    def test_block_defaults(self):
        b = Block()
        assert b["type"] == "block"
        assert b["tag"] == "out-block"

    def test_direct_custom_tag(self):
        d = Direct(tag="my-direct")
        assert d["tag"] == "my-direct"

    def test_shadowsocks(self):
        ss = Shadowsocks(tag="ss", server="1.2.3.4", server_port=8388,
                         method="aes-256-gcm", password="pass")
        assert ss["type"] == "shadowsocks"
        assert ss["server"] == "1.2.3.4"
        assert ss["server_port"] == 8388

    def test_vless(self):
        v = Vless(tag="vl", server="s.com", server_port=443, uuid="test-uuid")
        assert v["type"] == "vless"
        assert v["uuid"] == "test-uuid"

    def test_vmess(self):
        vm = Vmess(tag="vm", server="s.com", server_port=443, uuid="test-uuid")
        assert vm["type"] == "vmess"

    def test_trojan(self):
        t = Trojan(tag="tr", server="s.com", server_port=443, password="pass")
        assert t["type"] == "trojan"

    def test_ssh(self):
        s = Ssh(tag="ssh", server="s.com", server_port=22)
        assert s["type"] == "ssh"

    def test_tls_sub_object(self):
        tls = Tls(server_name="example.com", insecure=True)
        assert tls["enabled"] is True
        assert tls["server_name"] == "example.com"
        assert tls["insecure"] is True

    def test_transport_valid(self):
        t = Transport("ws", path="/ws")
        assert t["type"] == "ws"
        assert t["path"] == "/ws"

    def test_transport_invalid(self):
        with pytest.raises(ValueError):
            Transport("invalid")

    def test_selector(self):
        s = Selector(tag="sel", outbounds=["a", "b"], default="a")
        assert s["type"] == "selector"
        assert s["outbounds"] == ["a", "b"]

    def test_urltest(self):
        u = Urltest(tag="ut", outbounds=["a", "b"])
        assert u["type"] == "urltest"

    def test_wiregaurd_alias(self):
        assert Wiregaurd is Wireguard

    def test_missing_required_field(self):
        with pytest.raises((ValueError, TypeError)):
            Vless(tag="v", server="s.com", server_port=443, uuid="")

    def test_port_validation(self):
        with pytest.raises(ValueError):
            Shadowsocks(tag="s", server="x", server_port=0,
                        method="aes-256-gcm", password="p")
        with pytest.raises(ValueError):
            Shadowsocks(tag="s", server="x", server_port=70000,
                        method="aes-256-gcm", password="p")

    def test_json_serializable(self):
        ss = Shadowsocks(tag="ss", server="1.2.3.4", server_port=8388,
                         method="aes-256-gcm", password="pass")
        j = json.dumps(ss)
        parsed = json.loads(j)
        assert parsed["type"] == "shadowsocks"


# ══════════════════════════════════════════════════════════════════════════
#  5. INBOUND BUILDERS
# ══════════════════════════════════════════════════════════════════════════

class TestInboundBuilders:
    def test_mixed(self):
        m = Mixed(listen="127.0.0.1", listen_port=1080)
        assert m["type"] == "mixed"
        assert m["listen"] == "127.0.0.1"
        assert m["listen_port"] == 1080

    def test_socks(self):
        s = SocksInbound(listen="0.0.0.0", listen_port=1080)
        assert s["type"] == "socks"

    def test_http(self):
        h = HttpInbound(listen="0.0.0.0", listen_port=8080)
        assert h["type"] == "http"

    def test_tun(self):
        t = Tun(address=["172.19.0.1/30"], auto_route=True, stack="mixed")
        assert t["type"] == "tun"
        assert t["auto_route"] is True

    def test_json_serializable(self):
        m = Mixed(listen="127.0.0.1", listen_port=1080)
        parsed = json.loads(json.dumps(m))
        assert parsed["type"] == "mixed"


# ══════════════════════════════════════════════════════════════════════════
#  6. URI PARSERS
# ══════════════════════════════════════════════════════════════════════════

class TestVlessParser:
    def test_basic(self):
        out = vless.parse(VLESS_URI)
        assert out["type"] == "vless"
        assert out["tag"] == "my-vless"
        assert out["server"] == "example.com"
        assert out["server_port"] == 443
        assert out["uuid"] == "b831381d-6324-4d53-ad4f-8cda48b30811"

    def test_tls(self):
        out = vless.parse(VLESS_URI)
        assert "tls" in out
        assert out["tls"]["enabled"] is True
        assert out["tls"]["server_name"] == "example.com"

    def test_transport(self):
        out = vless.parse(VLESS_URI)
        assert "transport" in out
        assert out["transport"]["type"] == "ws"
        assert out["transport"]["path"] == "/ws"

    def test_utls(self):
        out = vless.parse(VLESS_URI)
        assert out["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}

    def test_default_port(self):
        out = vless.parse("vless://uuid@host?security=none")
        assert out["server_port"] == 443

    def test_no_tls(self):
        out = vless.parse("vless://uuid@host:1234?security=none#tag")
        assert "tls" not in out

    def test_reality(self):
        uri = "vless://uuid@host:443?security=reality&pbk=abc&sid=def&sni=x.com#tag"
        out = vless.parse(uri)
        assert out["tls"]["reality"]["enabled"] is True
        assert out["tls"]["reality"]["public_key"] == "abc"

    def test_grpc(self):
        uri = "vless://uuid@host:443?security=tls&sni=x.com&type=grpc&serviceName=mygrpc#tag"
        out = vless.parse(uri)
        assert out["transport"]["type"] == "grpc"
        assert out["transport"]["service_name"] == "mygrpc"

    def test_invalid(self):
        with pytest.raises(ValueError):
            vless.parse("ss://invalid")


class TestShadowsocksParser:
    def test_sip002(self):
        out = shadowsocks.parse(SS_URI)
        assert out["type"] == "shadowsocks"
        assert out["tag"] == "my-ss"
        assert out["server"] == "1.2.3.4"
        assert out["server_port"] == 8388
        assert out["method"] == "aes-256-gcm"
        assert out["password"] == "password"

    def test_legacy(self):
        raw = base64.urlsafe_b64encode(b"aes-256-gcm:pass@5.6.7.8:1234").decode().rstrip("=")
        out = shadowsocks.parse(f"ss://{raw}#legacy")
        assert out["server"] == "5.6.7.8"
        assert out["server_port"] == 1234
        assert out["tag"] == "legacy"

    def test_invalid(self):
        with pytest.raises(ValueError):
            shadowsocks.parse("vless://invalid")


class TestVmessParser:
    def test_basic(self):
        uri = _vmess_uri()
        out = vmess.parse(uri)
        assert out["type"] == "vmess"
        assert out["tag"] == "my-vmess"
        assert out["server"] == "5.6.7.8"
        assert out["server_port"] == 443
        assert out["uuid"] == "test-uuid"

    def test_with_tls(self):
        uri = _vmess_uri(tls="tls", sni="x.com")
        out = vmess.parse(uri)
        assert "tls" in out
        assert out["tls"]["server_name"] == "x.com"

    def test_with_ws(self):
        uri = _vmess_uri(net="ws", path="/ws", host="cdn.com")
        out = vmess.parse(uri)
        assert out["transport"]["type"] == "ws"
        assert out["transport"]["path"] == "/ws"

    def test_invalid(self):
        with pytest.raises(ValueError):
            vmess.parse("ss://invalid")


class TestTrojanParser:
    def test_basic(self):
        out = trojan.parse(TROJAN_URI)
        assert out["type"] == "trojan"
        assert out["tag"] == "my-trojan"
        assert out["password"] == "mypassword"
        assert out["server"] == "server.com"

    def test_tls_default(self):
        out = trojan.parse(TROJAN_URI)
        assert "tls" in out
        assert out["tls"]["enabled"] is True

    def test_invalid(self):
        with pytest.raises(ValueError):
            trojan.parse("vless://invalid")


class TestParseOutboundUri:
    def test_dispatch_vless(self):
        out = parse_outbound_uri(VLESS_URI)
        assert out["type"] == "vless"

    def test_dispatch_ss(self):
        out = parse_outbound_uri(SS_URI)
        assert out["type"] == "shadowsocks"

    def test_dispatch_trojan(self):
        out = parse_outbound_uri(TROJAN_URI)
        assert out["type"] == "trojan"

    def test_dispatch_vmess(self):
        out = parse_outbound_uri(_vmess_uri())
        assert out["type"] == "vmess"

    def test_unsupported(self):
        with pytest.raises(ValueError, match="Unsupported"):
            parse_outbound_uri("http://proxy:8080")


# ══════════════════════════════════════════════════════════════════════════
#  7. CONFIG CLASS
# ══════════════════════════════════════════════════════════════════════════

class TestConfigInbound:
    def test_addr_port(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct"))
        ib = c["inbounds"][0]
        assert ib["type"] == "mixed"
        assert ib["listen"] == "127.0.0.1"
        assert ib["listen_port"] == 1080

    def test_port_as_string(self):
        c = _build(Config().inbound("127.0.0.1", "1080").outbound("direct"))
        assert c["inbounds"][0]["listen_port"] == 1080

    def test_socks5_uri(self):
        c = _build(Config().inbound("socks5://127.0.0.1:1080").outbound("direct"))
        assert c["inbounds"][0]["type"] == "socks"

    def test_http_uri(self):
        c = _build(Config().inbound("http://0.0.0.0:8080").outbound("direct"))
        assert c["inbounds"][0]["type"] == "http"

    def test_mixed_uri(self):
        c = _build(Config().inbound("mixed://0.0.0.0:7890").outbound("direct"))
        assert c["inbounds"][0]["type"] == "mixed"

    def test_dict(self):
        ib = Mixed(listen="127.0.0.1", listen_port=1080)
        c = _build(Config().inbound(ib).outbound("direct"))
        assert c["inbounds"][0]["type"] == "mixed"

    def test_invalid_uri(self):
        with pytest.raises(ValueError):
            Config().inbound("ftp://invalid:123")

    def test_no_port(self):
        with pytest.raises(ValueError):
            Config().inbound("socks5://localhost")


class TestConfigOutbound:
    def test_direct_string(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct"))
        types = [o["type"] for o in c["outbounds"]]
        assert "direct" in types

    def test_block_string(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("block"))
        types = [o["type"] for o in c["outbounds"]]
        assert "block" in types

    def test_uri(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound(VLESS_URI))
        types = [o["type"] for o in c["outbounds"]]
        assert "vless" in types

    def test_dict(self):
        out = Direct(tag="my-d")
        c = _build(Config().inbound("127.0.0.1", 1080).outbound(out))
        tags = [o["tag"] for o in c["outbounds"]]
        assert "my-d" in tags

    def test_detour(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(SS_URI)
            .outbound(VLESS_URI, detour="my-ss")
        )
        vless_out = [o for o in c["outbounds"] if o["type"] == "vless"][0]
        assert vless_out["detour"] == "my-ss"

    def test_unknown_string(self):
        with pytest.raises(ValueError):
            Config().outbound("foobar")

    def test_wrong_type(self):
        with pytest.raises(TypeError):
            Config().outbound(123)


class TestConfigAutoWiring:
    def test_direct_auto_added(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound(VLESS_URI))
        types = [o["type"] for o in c["outbounds"]]
        assert "direct" in types

    def test_block_auto_added(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound(VLESS_URI))
        types = [o["type"] for o in c["outbounds"]]
        assert "block" in types

    def test_no_duplicate_direct(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct"))
        direct_count = sum(1 for o in c["outbounds"] if o["type"] == "direct")
        assert direct_count == 1

    def test_proxy_tag_resolves(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(VLESS_URI)
            .proxy("geoip:us")
            .default("proxy")
        )
        vless_tag = [o["tag"] for o in c["outbounds"] if o["type"] == "vless"][0]
        assert c["route"]["final"] == vless_tag
        proxy_rule = [r for r in c["route"]["rules"] if "geoip-us" in str(r)][0]
        assert proxy_rule["outbound"] == vless_tag

    def test_proxy_tag_last_outbound_wins(self):
        """outbound(detour=) should set proxy_tag to the LAST proxy outbound."""
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(SS_URI)
            .outbound(VLESS_URI, detour="my-ss")
            .default("proxy")
        )
        vless_tag = [o["tag"] for o in c["outbounds"] if o["type"] == "vless"][0]
        assert c["route"]["final"] == vless_tag


class TestConfigChain:
    def test_chain_wiring(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .chain(SS_URI, VLESS_URI)
            .default("proxy")
        )
        vless_out = [o for o in c["outbounds"] if o["type"] == "vless"][0]
        ss_out = [o for o in c["outbounds"] if o["type"] == "shadowsocks"][0]
        assert vless_out["detour"] == ss_out["tag"]

    def test_chain_proxy_tag_is_last(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .chain(SS_URI, VLESS_URI)
            .default("proxy")
        )
        vless_tag = [o["tag"] for o in c["outbounds"] if o["type"] == "vless"][0]
        assert c["route"]["final"] == vless_tag

    def test_chain_min_two(self):
        with pytest.raises(ValueError):
            Config().chain(SS_URI)


class TestConfigRules:
    def test_block(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").block("geosite:nsfw"))
        rule = c["route"]["rules"][0]
        assert rule["outbound"] == "out-block"
        assert rule["rule_set"] == ["geosite-nsfw"]

    def test_direct(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").direct("geoip:private"))
        rule = c["route"]["rules"][0]
        assert rule["outbound"] == "out-direct"

    def test_proxy_resolves(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(VLESS_URI)
            .proxy("geoip:us")
        )
        rule = c["route"]["rules"][0]
        assert rule["outbound"] == "my-vless"

    def test_rule_set_generated(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").block("geosite:nsfw"))
        rs = c["route"]["rule_set"]
        assert any(r["tag"] == "geosite-nsfw" for r in rs)


class TestConfigDefault:
    def test_direct(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").default("direct"))
        assert c["route"]["final"] == "out-direct"

    def test_block(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").default("block"))
        assert c["route"]["final"] == "out-block"

    def test_proxy(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound(VLESS_URI).default("proxy"))
        assert c["route"]["final"] == "my-vless"

    def test_custom(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").default("custom-tag"))
        assert c["route"]["final"] == "custom-tag"


class TestConfigDns:
    def test_dns_servers(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").dns("google"))
        assert "dns" in c
        assert c["dns"]["servers"][0]["address"] == "tls://8.8.8.8"

    def test_dns_multiple(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").dns("google", "cloudflare"))
        assert len(c["dns"]["servers"]) == 2

    def test_dns_accumulates(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").dns("google").dns("cloudflare"))
        assert len(c["dns"]["servers"]) == 2


class TestConfigLog:
    def test_log_level(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").log("debug"))
        assert c["log"] == {"level": "debug"}

    def test_log_disable(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").log("disable"))
        assert c["log"] == {"disabled": True}


class TestConfigSni:
    def test_ip_override(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .sni("216.239.38.120", domains=["docs.google.com"])
        )
        sni_rule = [r for r in c["route"]["rules"] if "override_address" in r][0]
        assert sni_rule["override_address"] == "216.239.38.120"

    def test_domain_override(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .sni("www.google.com", geosite="google")
        )
        sni_rule = [r for r in c["route"]["rules"] if "override_address" in r][0]
        assert sni_rule["override_address"] == "www.google.com"

    def test_inline_ruleset(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .sni("1.2.3.4", domains=["a.com", "b.com"], keywords=["test"])
        )
        rs = [r for r in c["route"]["rule_set"] if r["type"] == "inline"][0]
        assert rs["rules"][0]["domain"] == ["a.com", "b.com"]
        assert rs["rules"][0]["domain_keyword"] == ["test"]

    def test_geosite_ruleset(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .sni("1.2.3.4", geosite="google")
        )
        rs = [r for r in c["route"]["rule_set"] if r["tag"] == "geosite-google"][0]
        assert rs["type"] == "remote"

    def test_sni_proxy_outbound(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(VLESS_URI)
            .sni("1.2.3.4", domains=["a.com"], outbound="proxy")
        )
        sni_rule = [r for r in c["route"]["rules"] if "override_address" in r][0]
        assert sni_rule["outbound"] == "my-vless"

    def test_no_dns_for_ip_override(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .sni("1.2.3.4", domains=["a.com"])
        )
        assert "dns" not in c

    def test_sni_combined_with_rules(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(VLESS_URI)
            .sni("1.2.3.4", domains=["a.com"])
            .block("geosite:malware")
            .default("proxy")
        )
        rules = c["route"]["rules"]
        assert any("override_address" in r for r in rules)
        assert any(r.get("outbound") == "out-block" for r in rules)


class TestConfigExport:
    def test_export_returns_self(self):
        config = Config().inbound("127.0.0.1", 1080).outbound("direct")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = config.export(path)
            assert result is config
            with open(path) as f:
                data = json.load(f)
            assert "inbounds" in data
            assert "outbounds" in data
        finally:
            os.unlink(path)

    def test_to_json(self):
        config = Config().inbound("127.0.0.1", 1080).outbound("direct")
        j = config.to_json()
        data = json.loads(j)
        assert "inbounds" in data

    def test_fluent_chaining(self):
        config = (
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .block("geosite:nsfw")
            .proxy("geoip:us")
            .direct("geoip:private")
            .default("direct")
            .dns("google")
            .log("info")
        )
        data = json.loads(config.to_json())
        assert len(data["inbounds"]) == 1
        assert len(data["route"]["rules"]) == 3


class TestConfigRepr:
    def test_repr(self):
        config = Config().inbound("127.0.0.1", 1080).outbound("direct")
        r = repr(config)
        assert "inbounds=1" in r
        assert "idle" in r


# ══════════════════════════════════════════════════════════════════════════
#  8. SING-BOX COMPATIBILITY VALIDATION
# ══════════════════════════════════════════════════════════════════════════

class TestSingboxCompat:
    """Validates generated JSON matches sing-box expected structure."""

    def _validate(self, data):
        """Basic sing-box config structure validation."""
        valid_top = {"log", "dns", "inbounds", "outbounds", "route", "experimental",
                     "certificate", "endpoints", "ntp"}
        assert set(data.keys()) <= valid_top, f"Invalid top-level keys: {set(data.keys()) - valid_top}"

        for ib in data.get("inbounds", []):
            assert "type" in ib, f"Inbound missing 'type': {ib}"
            assert "tag" in ib, f"Inbound missing 'tag': {ib}"

        for ob in data.get("outbounds", []):
            assert "type" in ob, f"Outbound missing 'type': {ob}"
            assert "tag" in ob, f"Outbound missing 'tag': {ob}"

        ob_tags = [o["tag"] for o in data.get("outbounds", [])]
        assert len(ob_tags) == len(set(ob_tags)), f"Duplicate outbound tags: {ob_tags}"

        ib_tags = [i["tag"] for i in data.get("inbounds", [])]
        assert len(ib_tags) == len(set(ib_tags)), f"Duplicate inbound tags: {ib_tags}"

        route = data.get("route", {})
        if "final" in route:
            assert route["final"] in ob_tags or route["final"] == "", \
                f"route.final '{route['final']}' not in outbound tags {ob_tags}"

        for rule in route.get("rules", []):
            if "outbound" in rule:
                assert rule["outbound"] in ob_tags, \
                    f"Rule outbound '{rule['outbound']}' not in outbound tags {ob_tags}"

        for rs in route.get("rule_set", []):
            assert "tag" in rs
            assert rs.get("type") in ("remote", "inline", "local"), \
                f"Invalid rule_set type: {rs.get('type')}"

        for rule in route.get("rules", []):
            for suffix in rule.get("domain_suffix", []):
                assert not suffix.startswith("."), \
                    f"domain_suffix must not start with dot: {suffix!r}"

    def test_minimal(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct"))
        self._validate(c)

    def test_full_config(self):
        c = _build(
            Config()
            .log("info")
            .dns("google", "cloudflare")
            .inbound("socks5://127.0.0.1:1080")
            .outbound(VLESS_URI)
            .block("geosite:nsfw")
            .block("geosite:malware")
            .direct("geoip:private")
            .proxy("geoip:us")
            .default("direct")
        )
        self._validate(c)

    def test_chain_config(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .chain(SS_URI, VLESS_URI)
            .block("geosite:nsfw")
            .default("proxy")
        )
        self._validate(c)

    def test_sni_config(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound("direct")
            .sni("216.239.38.120", domains=["docs.google.com", "drive.google.com"])
            .default("direct")
        )
        self._validate(c)

    def test_sni_with_proxy(self):
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(VLESS_URI)
            .sni("1.2.3.4", geosite="google", outbound="proxy")
            .block("geosite:malware")
            .default("proxy")
        )
        self._validate(c)

    def test_domain_rule_no_dot(self):
        c = _build(Config().inbound("127.0.0.1", 1080).outbound("direct").direct("example.com"))
        self._validate(c)
        rule = c["route"]["rules"][0]
        assert rule["domain_suffix"] == ["example.com"]

    def test_multiple_inbounds(self):
        c = _build(
            Config()
            .inbound("socks5://127.0.0.1:1080")
            .inbound("http://127.0.0.1:8080")
            .outbound("direct")
        )
        self._validate(c)
        assert len(c["inbounds"]) == 2

    def test_outbound_refs_valid(self):
        """Every rule outbound must reference an existing outbound tag."""
        c = _build(
            Config()
            .inbound("127.0.0.1", 1080)
            .outbound(VLESS_URI)
            .block("geosite:nsfw")
            .proxy("geoip:us")
            .direct("geoip:private")
            .default("proxy")
        )
        self._validate(c)


# ══════════════════════════════════════════════════════════════════════════
#  9. PACKAGE LEVEL
# ══════════════════════════════════════════════════════════════════════════

class TestPackage:
    def test_config_import(self):
        assert hasattr(sbc, "Config")

    def test_version(self):
        assert hasattr(sbc, "__version__")
        assert isinstance(sbc.__version__, str)

    def test_setup(self):
        assert hasattr(sbc, "setup")
