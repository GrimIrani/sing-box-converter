import base64
import json as _json

from ..config.outbound import Vmess, Tls, Transport


def parse(uri):
    """Parse a vmess:// URI (v2rayN format) into a Vmess outbound dict."""
    if not uri.startswith("vmess://"):
        raise ValueError(f"Not a VMess URI: {uri}")

    raw = uri[8:]

    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode()
        data = _json.loads(decoded)
    except Exception:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode()
        data = _json.loads(decoded)

    server = data.get("add", "")
    server_port = int(data.get("port", 443))
    uuid = data.get("id", "")
    tag = data.get("ps", "out-vmess") or "out-vmess"

    kwargs = {}

    security = data.get("scy", "auto")
    if security:
        kwargs["security"] = security

    alter_id = int(data.get("aid", 0))
    if alter_id:
        kwargs["alter_id"] = alter_id

    tls_type = data.get("tls", "")
    if tls_type == "tls":
        tls_kwargs = {}
        sni = data.get("sni", "")
        if sni:
            tls_kwargs["server_name"] = sni
        alpn = data.get("alpn", "")
        if alpn:
            tls_kwargs["alpn"] = alpn.split(",")
        fp = data.get("fp", "")
        if fp:
            tls_kwargs["utls"] = {"enabled": True, "fingerprint": fp}
        kwargs["tls"] = Tls(**tls_kwargs)

    net = data.get("net", "tcp")
    if net and net != "tcp":
        transport_kwargs = {}
        if net == "ws":
            transport_kwargs["path"] = data.get("path", "/")
            host = data.get("host", "")
            if host:
                transport_kwargs["headers"] = {"Host": host}
        elif net == "grpc":
            service_name = data.get("path", "")
            if service_name:
                transport_kwargs["service_name"] = service_name
        elif net in ("http", "h2"):
            net = "http"
            transport_kwargs["path"] = data.get("path", "/")
            host = data.get("host", "")
            if host:
                transport_kwargs["host"] = [host]
        elif net == "httpupgrade":
            transport_kwargs["path"] = data.get("path", "/")
            host = data.get("host", "")
            if host:
                transport_kwargs["host"] = host

        kwargs["transport"] = Transport(net, **transport_kwargs)

    return Vmess(
        tag=tag, server=server, server_port=server_port, uuid=uuid, **kwargs
    )
