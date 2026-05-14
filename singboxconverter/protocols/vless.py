from urllib.parse import urlparse, parse_qs

from ..config.outbound import Vless, Tls, Transport


def parse(uri):
    """Parse a vless:// URI into a Vless outbound dict."""
    if not uri.startswith("vless://"):
        raise ValueError(f"Not a VLESS URI: {uri}")

    parsed = urlparse(uri)

    uuid = parsed.username
    server = parsed.hostname
    server_port = parsed.port or 443
    tag = parsed.fragment or "out-vless"

    if not uuid or not server:
        raise ValueError(f"Invalid VLESS URI: missing uuid or server")

    params = parse_qs(parsed.query)

    def p(key, default=None):
        vals = params.get(key)
        return vals[0] if vals else default

    kwargs = {}

    flow = p("flow")
    if flow:
        kwargs["flow"] = flow

    security = p("security", "none")
    if security in ("tls", "reality"):
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

        if security == "reality":
            reality = {"enabled": True}
            pbk = p("pbk")
            if pbk:
                reality["public_key"] = pbk
            sid = p("sid")
            if sid:
                reality["short_id"] = sid
            tls_kwargs["reality"] = reality

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
        elif transport_type == "httpupgrade":
            transport_kwargs["path"] = p("path", "/")
            host = p("host")
            if host:
                transport_kwargs["host"] = host

        kwargs["transport"] = Transport(transport_type, **transport_kwargs)

    return Vless(
        tag=tag, server=server, server_port=server_port, uuid=uuid, **kwargs
    )
