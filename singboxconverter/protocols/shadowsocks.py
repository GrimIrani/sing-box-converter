import base64
from urllib.parse import unquote

from ..config.outbound import Shadowsocks


def parse(uri):
    """Parse an ss:// URI into a Shadowsocks outbound dict.

    Supports both SIP002 and legacy formats.
    """
    if not uri.startswith("ss://"):
        raise ValueError(f"Not a Shadowsocks URI: {uri}")

    raw = uri[5:]

    tag = "out-ss"
    if "#" in raw:
        raw, fragment = raw.rsplit("#", 1)
        tag = unquote(fragment) or tag

    if "@" in raw:
        userinfo, hostport = raw.rsplit("@", 1)
        if "?" in hostport:
            hostport = hostport.split("?", 1)[0]

        try:
            padded = userinfo + "=" * (-len(userinfo) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode()
            method, password = decoded.split(":", 1)
        except Exception:
            method, password = userinfo.split(":", 1)
            password = unquote(password)

        if ":" not in hostport:
            raise ValueError("Missing port in SS URI")
        server, port_str = hostport.rsplit(":", 1)
        server_port = int(port_str)
    else:
        try:
            padded = raw + "=" * (-len(raw) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode()
        except Exception:
            raise ValueError(f"Cannot decode SS URI")

        method_pass, hostport = decoded.rsplit("@", 1)
        method, password = method_pass.split(":", 1)
        server, port_str = hostport.rsplit(":", 1)
        server_port = int(port_str)

    return Shadowsocks(
        tag=tag,
        server=server,
        server_port=server_port,
        method=method,
        password=password,
    )
