from urllib.parse import urlparse, parse_qs, unquote

from ..config.outbound import Trojan, Tls, Transport


def parse(uri):
    """Parse a trojan:// URI into a Trojan outbound dict."""
    if not uri.startswith("trojan://"):
        raise ValueError(f"Not a Trojan URI: {uri}")

    parsed = urlparse(uri)

    password = unquote(parsed.username or "")
    server = parsed.hostname
    server_port = parsed.port or 443
    tag = parsed.fragment or "out-trojan"

    if not password or not server:
        raise ValueError("Invalid Trojan URI: missing password or server")

    params = parse_qs(parsed.query)

    def p(key, default=None):
        vals = params.get(key)
        return vals[0] if vals else default

    kwargs = {}

    security = p("security", "tls")
    if security != "none":
        tls_kwargs = {}
        sni = p("sni") or p("serverName")
        if sni:
            tls_kwargs["server_name"] = sni

        alpn = p("alpn")
        if alpn:
            tls_kwargs["alpn"] = alpn.split(",")

        insecure = p("allowInsecure", "0") == "1"
        if insecure:
            tls_kwargs["insecure"] = True

        fp = p("fp")
        if fp:
            tls_kwargs["utls"] = {"enabled": True, "fingerprint": fp}

        kwargs["tls"] = Tls(**tls_kwargs)

    transport_type = p("type", "tcp")
    if transport_type and transport_type != "tcp":
        transport_kwargs = {}
        if transport_type == "ws":
            transport_kwargs["path"] = p("path", "/")
            host = p("host")
            if host:
                transport_kwargs["headers"] = {"Host": host}
        elif transport_type == "grpc":
            service_name = p("serviceName")
            if service_name:
                transport_kwargs["service_name"] = service_name
        elif transport_type == "http":
            transport_kwargs["path"] = p("path", "/")
            host = p("host")
            if host:
                transport_kwargs["host"] = [host]

        kwargs["transport"] = Transport(transport_type, **transport_kwargs)

    return Trojan(
        tag=tag, server=server, server_port=server_port, password=password, **kwargs
    )
