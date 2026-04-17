class Direct:
    """Direct with no-proxy"""

    def __init__(self, tag="out-internal"):
        return {
            "type": "direct",
            "tag": tag,
        }


class Block:
    """Block anything"""
    
    def __init__(self, tag="out-internal"):
        return {
            "type": "block",
            "tag": tag,
        }

class Http:
    pass


class Socks:
    pass


class Shadowsocks:
    pass


class Vmess:
    pass


class Trojan:
    pass


class Wiregaurd:
    pass


class Naive:
    pass


class Shadowtls:
    pass


class Tuic:
    pass


class Vless:
    pass


class Tor:
    pass


class Anytls:
    pass


class Hysteria:
    pass


class Hysteria2:
    pass


class Ssh:
    pass


class Selector:
    pass


class Urltest:
    pass
