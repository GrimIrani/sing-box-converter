from . import vless, shadowsocks, vmess

_PARSERS = {
    "vless": vless.parse,
    "ss": shadowsocks.parse,
    "vmess": vmess.parse,
}


def parse_outbound_uri(uri):
    """Parse a proxy URI and return the appropriate outbound dict."""
    scheme = uri.split("://", 1)[0].lower()
    parser = _PARSERS.get(scheme)
    if parser is None:
        raise ValueError(f"Unsupported protocol: {scheme!r}")
    return parser(uri)
