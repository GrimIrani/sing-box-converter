import json
from urllib.parse import urlparse

from .outbound import Direct, Block
from .inbound import Mixed, Socks as SocksInbound, Http as HttpInbound
from .utils import parse_rule
from ..protocols import parse_outbound_uri


class Config:
    """Build a sing-box configuration step by step.

    Supports fluent chaining:
        config = Config().inbound(...).outbound(...).block(...).export(...)
    """

    def __init__(self):
        self._inbounds = []
        self._outbounds = []
        self._rules = []
        self._final = "out-direct"
        self._proxy_tag = None

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

        config = {
            "inbounds": list(self._inbounds),
            "outbounds": outbounds,
        }

        if rules or final:
            config["route"] = {"rules": rules, "final": final}

        return config

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

    def __repr__(self):
        return (
            f"Config(inbounds={len(self._inbounds)}, "
            f"outbounds={len(self._outbounds)}, "
            f"rules={len(self._rules)})"
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
