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

    def outbound(self, *args):
        """Add an outbound.

        config.outbound("direct")       -> Direct
        config.outbound("vless://...")   -> Vless
        config.outbound("ss://...")      -> Shadowsocks
        config.outbound("vmess://...")   -> Vmess
        config.outbound("trojan://...") -> Trojan
        """
        if len(args) != 1:
            raise ValueError("outbound() takes exactly one argument")

        arg = args[0]
        if isinstance(arg, dict):
            self._outbounds.append(arg)
            if arg.get("type") not in ("direct", "block") and self._proxy_tag is None:
                self._proxy_tag = arg.get("tag")
        elif isinstance(arg, str):
            if arg == "direct":
                self._outbounds.append(Direct())
            elif "://" in arg:
                out = parse_outbound_uri(arg)
                self._outbounds.append(out)
                if self._proxy_tag is None:
                    self._proxy_tag = out["tag"]
            else:
                raise ValueError(f"Unknown outbound: {arg!r}")
        else:
            raise TypeError(f"outbound() expects str or dict, got {type(arg)}")
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

        if rules or final:
            route = {"rules": rules, "final": final}
            rule_sets = build_rule_sets(rules)
            if rule_sets:
                route["rule_set"] = rule_sets
            config["route"] = route

        return config

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
