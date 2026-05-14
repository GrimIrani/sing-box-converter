import json
import os
import subprocess
import tempfile
from urllib.parse import urlparse

from .outbound import Direct, Block
from .inbound import Mixed, Socks as SocksInbound, Http as HttpInbound
from .utils import parse_rule, build_rule_sets
from ..protocols import parse_outbound_uri
from ..methods.log import build as build_log
from ..methods.dns import build as build_dns


class Config:
    """Build a sing-box configuration step by step.

    Supports fluent chaining:
        config = Config().inbound(...).outbound(...).block(...).export(...)

    Supports context manager for connect/disconnect:
        with Config().inbound(...).outbound(...) as c:
            ...  # sing-box is running
    """

    def __init__(self, *, binary=None):
        self._inbounds = []
        self._outbounds = []
        self._rules = []
        self._final = "out-direct"
        self._proxy_tag = None
        self._dns_servers = []
        self._log_level = None
        self._process = None
        self._config_path = None
        self._sni_configs = []
        self._binary = binary

    # ── inbound / outbound ────────────────────────────────────────────────

    def inbound(self, *args):
        """Add an inbound.

        config.inbound("127.0.0.1", 1080)        -> Mixed
        config.inbound("socks5://127.0.0.1:1080") -> Socks
        config.inbound("http://127.0.0.1:8080")   -> Http
        config.inbound("mixed://127.0.0.1:7890")  -> Mixed
        """
        if len(args) == 2:
            addr, port = args[0], int(args[1])
            self._inbounds.append(Mixed(listen=addr, listen_port=port))
        elif len(args) == 1 and isinstance(args[0], str):
            uri = args[0]
            if "://" in uri:
                self._inbounds.append(_parse_inbound_uri(uri))
            else:
                raise ValueError(f"Invalid inbound: {uri!r}")
        elif len(args) == 1 and isinstance(args[0], dict):
            self._inbounds.append(args[0])
        else:
            raise ValueError("inbound() takes a URI string, (address, port), or a dict")
        return self

    def outbound(self, arg, *, detour=None):
        """Add an outbound.

        config.outbound("direct")                        -> Direct
        config.outbound("vless://...")                    -> Vless
        config.outbound("vless://...", detour="hop-1")   -> Vless through hop-1
        """
        out = _resolve_outbound(arg)
        if detour:
            out["detour"] = detour
        self._outbounds.append(out)
        if out.get("type") not in ("direct", "block") and self._proxy_tag is None:
            self._proxy_tag = out.get("tag")
        return self

    def chain(self, *outbounds):
        """Add chained outbounds (proxy chain).

        Each outbound connects through the previous one.
        The last one becomes the proxy target.

            config.chain(
                "socks5://127.0.0.1:1081#hop-1",
                "vless://uuid@server:443?security=tls&sni=example.com#proxy",
            )
            # vless connects through socks5

        Accepts URI strings or outbound dict objects.
        """
        if len(outbounds) < 2:
            raise ValueError("chain() requires at least 2 outbounds")

        parsed = [_resolve_outbound(o) for o in outbounds]

        for i in range(1, len(parsed)):
            parsed[i]["detour"] = parsed[i - 1]["tag"]

        for out in parsed:
            self._outbounds.append(out)

        if self._proxy_tag is None:
            self._proxy_tag = parsed[-1]["tag"]

        return self

    # ── routing rules ─────────────────────────────────────────────────────

    def block(self, rule_str):
        """Route matching traffic to the block outbound."""
        rule = parse_rule(rule_str)
        rule["outbound"] = "out-block"
        self._rules.append(rule)
        return self

    def proxy(self, rule_str):
        """Route matching traffic through the proxy outbound."""
        rule = parse_rule(rule_str)
        rule["outbound"] = "__proxy__"
        self._rules.append(rule)
        return self

    def direct(self, rule_str):
        """Route matching traffic to the direct outbound."""
        rule = parse_rule(rule_str)
        rule["outbound"] = "out-direct"
        self._rules.append(rule)
        return self

    def default(self, mode):
        """Set the final/default outbound for unmatched traffic."""
        if mode == "direct":
            self._final = "out-direct"
        elif mode == "block":
            self._final = "out-block"
        elif mode == "proxy":
            self._final = "__proxy__"
        else:
            self._final = mode
        return self

    # ── dns / log ─────────────────────────────────────────────────────────

    def dns(self, *servers):
        """Add DNS server(s).

        Accepts raw addresses or preset names:
            config.dns("tls://8.8.8.8")
            config.dns("google", "cloudflare")
            config.dns("https://1.1.1.1/dns-query")
        """
        for s in servers:
            self._dns_servers.append(s)
        return self

    def log(self, level="info"):
        """Set log level.

        Levels: disable, trace, debug, info, warn, error, fatal, panic
        """
        self._log_level = level
        return self

    # ── sni / override ────────────────────────────────────────────────────

    def sni(self, address, *, server_name=None, geosite=None, domains=None,
            keywords=None, domain_suffix=None, outbound="direct"):
        """Route domains to a clean IP/host using FakeIP + override_address.

            # Override to a domain (sing-box resolves it):
            config.sni("www.google.com", geosite="google")

            # Override to a specific IP:
            config.sni("216.239.38.120", geosite="google")

            # Pin IP + server_name (DNS pins server_name to the IP,
            # route overrides to server_name):
            config.sni("216.239.38.120", server_name="www.google.com",
                        geosite="google")

            # Custom domain list instead of geosite:
            config.sni("216.239.38.120", server_name="www.google.com",
                        domains=["docs.google.com", "mail.google.com"])
        """
        self._sni_configs.append({
            "address": address,
            "server_name": server_name,
            "geosite": geosite,
            "domains": domains or [],
            "keywords": keywords or [],
            "domain_suffix": domain_suffix or [],
            "outbound": outbound,
        })
        return self

    # ── build ─────────────────────────────────────────────────────────────

    def _build(self):
        outbounds = list(self._outbounds)

        if not any(o.get("type") == "direct" for o in outbounds):
            outbounds.append(Direct())
        if not any(o.get("type") == "block" for o in outbounds):
            outbounds.append(Block())

        proxy_tag = self._proxy_tag
        if proxy_tag is None:
            for o in outbounds:
                if o.get("type") not in ("direct", "block"):
                    proxy_tag = o["tag"]
                    break
        if proxy_tag is None:
            proxy_tag = "out-direct"

        rules = []
        for rule in self._rules:
            r = dict(rule)
            if r.get("outbound") == "__proxy__":
                r["outbound"] = proxy_tag
            rules.append(r)

        final = self._final
        if final == "__proxy__":
            final = proxy_tag

        config = {}

        if self._log_level:
            config["log"] = build_log(self._log_level)

        if self._dns_servers:
            config["dns"] = build_dns(self._dns_servers)

        config["inbounds"] = list(self._inbounds)
        config["outbounds"] = outbounds

        if rules or final or self._sni_configs:
            route = {"rules": rules, "final": final}
            rule_sets = build_rule_sets(rules)
            if rule_sets:
                route["rule_set"] = rule_sets
            config["route"] = route

        if self._sni_configs:
            self._apply_sni(config, proxy_tag)

        return config

    def _apply_sni(self, config, proxy_tag):
        from .utils import _IP_RE

        # DNS: add fakeip + local servers
        dns = config.setdefault("dns", {})
        dns["independent_cache"] = True
        dns["strategy"] = "ipv4_only"
        servers = dns.setdefault("servers", [])
        dns_rules = dns.setdefault("rules", [])

        if not any(s.get("tag") == "dns-local" for s in servers):
            servers.append({"type": "local", "tag": "dns-local"})
        if not any(s.get("tag") == "dns-fakeip" for s in servers):
            servers.append({
                "type": "fakeip", "tag": "dns-fakeip",
                "inet4_range": "198.18.0.0/15",
            })
        dns.setdefault("final", "dns-local")

        # Route: prepend sniff/hijack/resolve + per-target override rules
        route = config.setdefault("route", {})
        route["auto_detect_interface"] = True
        route.setdefault("default_domain_resolver", {
            "server": "dns-local", "strategy": "ipv4_only",
        })

        existing_rules = route.get("rules", [])
        rule_sets = route.setdefault("rule_set", [])
        seen_tags = {rs["tag"] for rs in rule_sets}

        sni_rules = [
            {"action": "sniff"},
            {"action": "hijack-dns", "protocol": ["dns"]},
            {"action": "resolve", "strategy": "ipv4_only"},
        ]

        override_domains = []

        for sni_cfg in self._sni_configs:
            address = sni_cfg["address"]
            server_name = sni_cfg.get("server_name")
            is_ip = bool(_IP_RE.match(address))

            if sni_cfg["geosite"]:
                tag = f"geosite-{sni_cfg['geosite']}"
            else:
                name = (server_name or address).replace(".", "-").replace(":", "-")
                tag = f"sni-{name}"

            # DNS rule: send matching domains to fakeip
            dns_rules.append({"rule_set": [tag], "server": "dns-fakeip"})

            # Determine override_address
            if is_ip and server_name:
                # Pin DNS: server_name resolves to the given IP
                dns_rules.insert(0, {
                    "action": "predefined",
                    "domain": [server_name],
                    "answer": [f"{server_name}. IN A {address}"],
                    "query_type": ["A"],
                    "rcode": "NOERROR",
                })
                override = server_name
            elif is_ip:
                override = address
            else:
                override = address
                override_domains.append(address)

            # Route rule
            out = sni_cfg["outbound"]
            if out == "direct":
                out = "out-direct"
            elif out == "proxy":
                out = proxy_tag

            sni_rules.append({
                "action": "route",
                "rule_set": [tag],
                "outbound": out,
                "override_address": override,
            })

            # Rule-set definition (deduplicated)
            if tag not in seen_tags:
                seen_tags.add(tag)
                if sni_cfg["geosite"]:
                    from .utils import GEOSITE_URL
                    rule_sets.append({
                        "tag": tag,
                        "type": "remote",
                        "format": "binary",
                        "url": f"{GEOSITE_URL}/{tag}.srs",
                        "download_detour": "out-direct",
                    })
                else:
                    inline_rule = {}
                    if sni_cfg["domains"]:
                        inline_rule["domain"] = sni_cfg["domains"]
                    if sni_cfg["keywords"]:
                        inline_rule["domain_keyword"] = sni_cfg["keywords"]
                    if sni_cfg["domain_suffix"]:
                        inline_rule["domain_suffix"] = sni_cfg["domain_suffix"]
                    rule_sets.append({
                        "type": "inline",
                        "tag": tag,
                        "rules": [inline_rule],
                    })

        # Exclude plain domain overrides from fakeip (resolve them for real)
        if override_domains:
            dns_rules.insert(0, {"domain": override_domains, "server": "dns-local"})

        route["rules"] = sni_rules + existing_rules

    # ── export ────────────────────────────────────────────────────────────

    def export(self, path):
        """Write the config to a JSON file."""
        config = self._build()
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        return self

    def to_json(self, indent=2):
        """Return the config as a JSON string."""
        return json.dumps(self._build(), indent=indent)

    # ── run / connect ─────────────────────────────────────────────────────

    def _resolve_binary(self):
        if self._binary:
            return self._binary
        from ..runtime import ensure_binary
        return ensure_binary()

    def run(self):
        """Download sing-box if needed, export config, and run (blocking).

        Blocks until the process exits or is interrupted with Ctrl+C.
        """
        binary = self._resolve_binary()
        config = self._build()

        fd, path = tempfile.mkstemp(suffix=".json", prefix="singbox-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(config, f, indent=2)
            print("Starting sing-box...")
            subprocess.run([binary, "run", "-c", path])
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            if os.path.exists(path):
                os.unlink(path)
        return self

    def connect(self):
        """Download dependencies, export config, and run sing-box in background.

        Use disconnect() to stop, or use as a context manager:
            with config.connect() as c:
                ...
        """
        if self._process and self._process.poll() is None:
            raise RuntimeError("Already connected, call disconnect() first")

        binary = self._resolve_binary()
        config = self._build()

        fd, self._config_path = tempfile.mkstemp(suffix=".json", prefix="singbox-")
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)

        self._process = subprocess.Popen(
            [binary, "run", "-c", self._config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"sing-box started (PID {self._process.pid})")
        return self

    def disconnect(self):
        """Stop a background sing-box process started by connect()."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            print("sing-box stopped")
        self._process = None

        if self._config_path and os.path.exists(self._config_path):
            os.unlink(self._config_path)
        self._config_path = None
        return self

    @property
    def is_running(self):
        """True if a background sing-box process is alive."""
        return self._process is not None and self._process.poll() is None

    # ── context manager / cleanup ─────────────────────────────────────────

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()

    def __del__(self):
        if self._process and self._process.poll() is None:
            self._process.terminate()
        if self._config_path and os.path.exists(self._config_path):
            try:
                os.unlink(self._config_path)
            except OSError:
                pass

    def __repr__(self):
        status = "running" if self.is_running else "idle"
        return (
            f"Config(inbounds={len(self._inbounds)}, "
            f"outbounds={len(self._outbounds)}, "
            f"rules={len(self._rules)}, {status})"
        )


def _resolve_outbound(arg):
    if isinstance(arg, dict):
        return arg
    if isinstance(arg, str):
        if arg == "direct":
            return Direct()
        if "://" in arg:
            return parse_outbound_uri(arg)
        raise ValueError(f"Unknown outbound: {arg!r}")
    raise TypeError(f"Expected str or dict, got {type(arg)}")


def _parse_inbound_uri(uri):
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or "0.0.0.0"
    port = parsed.port

    if port is None:
        raise ValueError(f"Inbound URI must include a port: {uri!r}")

    if scheme in ("socks5", "socks"):
        return SocksInbound(listen=host, listen_port=port)
    elif scheme == "http":
        return HttpInbound(listen=host, listen_port=port)
    elif scheme == "mixed":
        return Mixed(listen=host, listen_port=port)
    else:
        raise ValueError(f"Unsupported inbound scheme: {scheme!r}")
