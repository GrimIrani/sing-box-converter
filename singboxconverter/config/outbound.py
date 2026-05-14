"""
config/outbound.py — sing-box outbound configuration builders.

Every class is a ``dict`` subclass, so instances can be passed directly
wherever a plain dict is expected (e.g. ``json.dumps(outbound)``).

``__init__`` validates all inputs and raises:
  - ``ValueError``  — missing required field or out-of-range value
  - ``TypeError``   — wrong Python type for a field

Shared sub-objects
------------------
  Tls        — TLS block reused by Http, Vmess, Trojan, Vless, …
  Transport  — V2Ray transport block reused by Vmess, Trojan, Vless

Simple outbounds
----------------
  Direct, Block

Proxy outbounds
---------------
  Http, Socks, Shadowsocks, Vmess, Trojan, Wireguard,
  Naive, Shadowtls, Tuic, Vless, Tor, Anytls,
  Hysteria, Hysteria2, Ssh

Group outbounds
---------------
  Selector, Urltest

Usage example
-------------
    from config.outbound import Shadowsocks, Selector, Tls

    proxy = Shadowsocks(
        tag="ss-hk",
        server="1.2.3.4",
        server_port=8388,
        method="aes-256-gcm",
        password="s3cr3t",
    )

    group = Selector(
        tag="proxy",
        outbounds=["ss-hk"],
        default="ss-hk",
    )

    import json
    print(json.dumps([proxy, group], indent=2))
"""

from __future__ import annotations

from typing import Optional

__all__ = [
    # helpers
    "Tls",
    "Transport",
    # simple
    "Direct",
    "Block",
    # proxy
    "Http",
    "Socks",
    "Shadowsocks",
    "Vmess",
    "Trojan",
    "Wireguard",
    "Naive",
    "Shadowtls",
    "Tuic",
    "Vless",
    "Tor",
    "Anytls",
    "Hysteria",
    "Hysteria2",
    "Ssh",
    # group
    "Selector",
    "Urltest",
]


# ── internal validators ────────────────────────────────────────────────────


def _req_str(name: str, value) -> str:
    if value is None:
        raise ValueError(f"'{name}' is required")
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"'{name}' must be a non-empty string, got {value!r}")
    return value


def _req_int(name: str, value, lo: Optional[int] = None, hi: Optional[int] = None) -> int:
    if value is None:
        raise ValueError(f"'{name}' is required")
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"'{name}' must be an int, got {value!r}")
    if lo is not None and value < lo:
        raise ValueError(f"'{name}' must be >= {lo}, got {value}")
    if hi is not None and value > hi:
        raise ValueError(f"'{name}' must be <= {hi}, got {value}")
    return value


def _req_list(name: str, value) -> list:
    if value is None:
        raise ValueError(f"'{name}' is required")
    if not isinstance(value, list) or not value:
        raise TypeError(f"'{name}' must be a non-empty list, got {value!r}")
    return value


def _req_one_of(name: str, value, choices: set):
    if value not in choices:
        raise ValueError(f"'{name}' must be one of {sorted(choices)}, got {value!r}")
    return value


def _port(name: str, value: int) -> int:
    return _req_int(name, value, lo=1, hi=65535)


# ── shared sub-objects ─────────────────────────────────────────────────────


class Tls(dict):
    """
    TLS configuration block, shared across many outbound types.

    https://sing-box.sagernet.org/configuration/shared/tls/
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        server_name: Optional[str] = None,
        insecure: bool = False,
        alpn: Optional[list[str]] = None,
        min_version: Optional[str] = None,
        max_version: Optional[str] = None,
        cipher_suites: Optional[list[str]] = None,
        certificate_path: Optional[str] = None,
        certificate: Optional[str] = None,
        utls: Optional[dict] = None,
        reality: Optional[dict] = None,
        ech: Optional[dict] = None,
    ):
        data: dict = {"enabled": bool(enabled)}
        if server_name is not None:
            data["server_name"] = _req_str("server_name", server_name)
        if insecure:
            data["insecure"] = True
        if alpn is not None:
            data["alpn"] = _req_list("alpn", alpn)
        if min_version is not None:
            data["min_version"] = min_version
        if max_version is not None:
            data["max_version"] = max_version
        if cipher_suites is not None:
            data["cipher_suites"] = cipher_suites
        if certificate_path is not None:
            data["certificate_path"] = certificate_path
        if certificate is not None:
            data["certificate"] = certificate
        if utls is not None:
            data["utls"] = utls
        if reality is not None:
            data["reality"] = reality
        if ech is not None:
            data["ech"] = ech
        super().__init__(data)


class Transport(dict):
    """
    V2Ray transport configuration block, shared across Vmess / Trojan / Vless.

    https://sing-box.sagernet.org/configuration/shared/v2ray-transport/
    """

    TYPES = {"http", "ws", "grpc", "httpupgrade", "quic"}

    def __init__(self, type: str, **kwargs):
        _req_one_of("type", type, self.TYPES)
        super().__init__(type=type, **kwargs)


# ── abstract base classes ──────────────────────────────────────────────────


class _Outbound(dict):
    """Base for all sing-box outbound types. Do not instantiate directly."""

    _TYPE: str = ""

    def __init__(self, tag: str):
        _req_str("tag", tag)
        super().__init__(type=self._TYPE, tag=tag)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({dict.__repr__(self)})"


class _ServerOutbound(_Outbound):
    """Base for outbounds that connect to a remote server."""

    def __init__(self, tag: str, server: str, server_port: int):
        super().__init__(tag)
        self["server"] = _req_str("server", server)
        self["server_port"] = _port("server_port", server_port)


# ── simple outbounds ───────────────────────────────────────────────────────


class Direct(_Outbound):
    """
    Direct outbound — no proxy.

    https://sing-box.sagernet.org/configuration/outbound/direct/
    """

    _TYPE = "direct"

    def __init__(
        self,
        tag: str = "out-direct",
        *,
        override_address: Optional[str] = None,
        override_port: Optional[int] = None,
        proxy_protocol: Optional[int] = None,
    ):
        super().__init__(tag)
        if override_address is not None:
            self["override_address"] = _req_str("override_address", override_address)
        if override_port is not None:
            self["override_port"] = _port("override_port", override_port)
        if proxy_protocol is not None:
            _req_one_of("proxy_protocol", proxy_protocol, {1, 2})
            self["proxy_protocol"] = proxy_protocol


class Block(_Outbound):
    """
    Block outbound — drops all matching traffic silently.

    https://sing-box.sagernet.org/configuration/outbound/block/
    """

    _TYPE = "block"

    def __init__(self, tag: str = "out-block"):
        super().__init__(tag)


# ── proxy outbounds ────────────────────────────────────────────────────────


class Http(_ServerOutbound):
    """
    HTTP CONNECT proxy outbound.

    https://sing-box.sagernet.org/configuration/outbound/http/
    """

    _TYPE = "http"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tls: Optional[Tls] = None,
        path: Optional[str] = None,
        headers: Optional[dict] = None,
    ):
        super().__init__(tag, server, server_port)
        if username is not None:
            self["username"] = _req_str("username", username)
        if password is not None:
            self["password"] = _req_str("password", password)
        if tls is not None:
            if not isinstance(tls, Tls):
                raise TypeError("'tls' must be a Tls instance")
            self["tls"] = tls
        if path is not None:
            self["path"] = path
        if headers is not None:
            self["headers"] = headers


class Socks(_ServerOutbound):
    """
    SOCKS4 / 4a / 5 proxy outbound.

    https://sing-box.sagernet.org/configuration/outbound/socks/
    """

    _TYPE = "socks"
    _VERSIONS = {"4", "4a", "5"}

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        *,
        version: str = "5",
        username: Optional[str] = None,
        password: Optional[str] = None,
        network: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        _req_one_of("version", version, self._VERSIONS)
        self["version"] = version
        if username is not None:
            self["username"] = _req_str("username", username)
        if password is not None:
            self["password"] = _req_str("password", password)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Shadowsocks(_ServerOutbound):
    """
    Shadowsocks proxy outbound.

    https://sing-box.sagernet.org/configuration/outbound/shadowsocks/
    """

    _TYPE = "shadowsocks"
    _METHODS = {
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "rc4-md5", "chacha20-ietf", "xchacha20",
        "none", "plain",
    }

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        method: str,
        password: str,
        *,
        plugin: Optional[str] = None,
        plugin_opts: Optional[str] = None,
        network: Optional[str] = None,
        udp_over_tcp: bool = False,
        multiplex: Optional[dict] = None,
    ):
        super().__init__(tag, server, server_port)
        _req_one_of("method", method, self._METHODS)
        self["method"] = method
        self["password"] = _req_str("password", password)
        if plugin is not None:
            self["plugin"] = plugin
            if plugin_opts is not None:
                self["plugin_opts"] = plugin_opts
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network
        if udp_over_tcp:
            self["udp_over_tcp"] = True
        if multiplex is not None:
            self["multiplex"] = multiplex


class Vmess(_ServerOutbound):
    """
    VMess proxy outbound.

    https://sing-box.sagernet.org/configuration/outbound/vmess/
    """

    _TYPE = "vmess"
    _SECURITY = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        uuid: str,
        *,
        security: str = "auto",
        alter_id: int = 0,
        global_padding: bool = False,
        authenticated_length: bool = True,
        tls: Optional[Tls] = None,
        transport: Optional[Transport] = None,
        multiplex: Optional[dict] = None,
        network: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        self["uuid"] = _req_str("uuid", uuid)
        _req_one_of("security", security, self._SECURITY)
        self["security"] = security
        self["alter_id"] = _req_int("alter_id", alter_id, lo=0)
        if global_padding:
            self["global_padding"] = True
        if not authenticated_length:
            self["authenticated_length"] = False
        if tls is not None:
            if not isinstance(tls, Tls):
                raise TypeError("'tls' must be a Tls instance")
            self["tls"] = tls
        if transport is not None:
            if not isinstance(transport, Transport):
                raise TypeError("'transport' must be a Transport instance")
            self["transport"] = transport
        if multiplex is not None:
            self["multiplex"] = multiplex
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Trojan(_ServerOutbound):
    """
    Trojan proxy outbound.

    https://sing-box.sagernet.org/configuration/outbound/trojan/
    """

    _TYPE = "trojan"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        password: str,
        *,
        tls: Optional[Tls] = None,
        transport: Optional[Transport] = None,
        multiplex: Optional[dict] = None,
        network: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        self["password"] = _req_str("password", password)
        if tls is not None:
            if not isinstance(tls, Tls):
                raise TypeError("'tls' must be a Tls instance")
            self["tls"] = tls
        if transport is not None:
            if not isinstance(transport, Transport):
                raise TypeError("'transport' must be a Transport instance")
            self["transport"] = transport
        if multiplex is not None:
            self["multiplex"] = multiplex
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Wireguard(_Outbound):
    """
    WireGuard outbound.

    https://sing-box.sagernet.org/configuration/outbound/wireguard/
    """

    _TYPE = "wireguard"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        private_key: str,
        peer_public_key: str,
        local_address: list[str],
        *,
        pre_shared_key: Optional[str] = None,
        reserved: Optional[list[int]] = None,
        mtu: int = 1408,
        network: Optional[str] = None,
    ):
        super().__init__(tag)
        self["server"] = _req_str("server", server)
        self["server_port"] = _port("server_port", server_port)
        self["private_key"] = _req_str("private_key", private_key)
        self["peer_public_key"] = _req_str("peer_public_key", peer_public_key)
        self["local_address"] = _req_list("local_address", local_address)
        if pre_shared_key is not None:
            self["pre_shared_key"] = pre_shared_key
        if reserved is not None:
            if not isinstance(reserved, list) or len(reserved) != 3:
                raise ValueError("'reserved' must be a list of exactly 3 ints")
            self["reserved"] = reserved
        self["mtu"] = _req_int("mtu", mtu, lo=1280, hi=9000)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Naive(_ServerOutbound):
    """
    NaïveProxy outbound.

    https://sing-box.sagernet.org/configuration/outbound/naive/
    """

    _TYPE = "naive"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        username: str,
        password: str,
        *,
        network: Optional[str] = None,
        tls: Optional[Tls] = None,
    ):
        super().__init__(tag, server, server_port)
        self["username"] = _req_str("username", username)
        self["password"] = _req_str("password", password)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network
        if tls is not None:
            if not isinstance(tls, Tls):
                raise TypeError("'tls' must be a Tls instance")
            self["tls"] = tls


class Shadowtls(_ServerOutbound):
    """
    ShadowTLS outbound.

    https://sing-box.sagernet.org/configuration/outbound/shadowtls/
    """

    _TYPE = "shadowtls"
    _VERSIONS = {1, 2, 3}

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        version: int,
        tls: Tls,
        *,
        password: Optional[str] = None,
        handshake: Optional[dict] = None,
    ):
        super().__init__(tag, server, server_port)
        _req_one_of("version", version, self._VERSIONS)
        self["version"] = version
        if version >= 2 and password is None:
            raise ValueError("'password' is required for ShadowTLS v2/v3")
        if password is not None:
            self["password"] = _req_str("password", password)
        if not isinstance(tls, Tls):
            raise TypeError("'tls' must be a Tls instance")
        self["tls"] = tls
        if handshake is not None:
            self["handshake"] = handshake


class Tuic(_ServerOutbound):
    """
    TUIC v5 outbound.

    https://sing-box.sagernet.org/configuration/outbound/tuic/
    """

    _TYPE = "tuic"
    _CONGESTION = {"cubic", "new_reno", "bbr"}

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        uuid: str,
        password: str,
        tls: Tls,
        *,
        congestion_control: str = "cubic",
        udp_relay_mode: Optional[str] = None,
        zero_rtt_handshake: bool = False,
        heartbeat: Optional[str] = None,
        network: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        self["uuid"] = _req_str("uuid", uuid)
        self["password"] = _req_str("password", password)
        if not isinstance(tls, Tls):
            raise TypeError("'tls' must be a Tls instance")
        self["tls"] = tls
        _req_one_of("congestion_control", congestion_control, self._CONGESTION)
        self["congestion_control"] = congestion_control
        if udp_relay_mode is not None:
            _req_one_of("udp_relay_mode", udp_relay_mode, {"native", "quic"})
            self["udp_relay_mode"] = udp_relay_mode
        if zero_rtt_handshake:
            self["zero_rtt_handshake"] = True
        if heartbeat is not None:
            self["heartbeat"] = heartbeat
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Vless(_ServerOutbound):
    """
    VLESS outbound.

    https://sing-box.sagernet.org/configuration/outbound/vless/
    """

    _TYPE = "vless"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        uuid: str,
        *,
        flow: Optional[str] = None,
        tls: Optional[Tls] = None,
        transport: Optional[Transport] = None,
        multiplex: Optional[dict] = None,
        network: Optional[str] = None,
        packet_encoding: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        self["uuid"] = _req_str("uuid", uuid)
        if flow is not None:
            self["flow"] = _req_str("flow", flow)
        if tls is not None:
            if not isinstance(tls, Tls):
                raise TypeError("'tls' must be a Tls instance")
            self["tls"] = tls
        if transport is not None:
            if not isinstance(transport, Transport):
                raise TypeError("'transport' must be a Transport instance")
            self["transport"] = transport
        if multiplex is not None:
            self["multiplex"] = multiplex
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network
        if packet_encoding is not None:
            self["packet_encoding"] = packet_encoding


class Tor(_Outbound):
    """
    Tor outbound.

    https://sing-box.sagernet.org/configuration/outbound/tor/
    """

    _TYPE = "tor"

    def __init__(
        self,
        tag: str = "out-tor",
        *,
        executable_path: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
        data_directory: Optional[str] = None,
        options: Optional[dict] = None,
    ):
        super().__init__(tag)
        if executable_path is not None:
            self["executable_path"] = executable_path
        if extra_args is not None:
            self["extra_args"] = extra_args
        if data_directory is not None:
            self["data_directory"] = data_directory
        if options is not None:
            self["options"] = options


class Anytls(_ServerOutbound):
    """
    AnyTLS outbound.

    https://sing-box.sagernet.org/configuration/outbound/anytls/
    """

    _TYPE = "anytls"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        password: str,
        *,
        idle_session_check_interval: Optional[str] = None,
        idle_session_timeout: Optional[str] = None,
        min_idle_session: Optional[int] = None,
        tls: Optional[Tls] = None,
    ):
        super().__init__(tag, server, server_port)
        self["password"] = _req_str("password", password)
        if idle_session_check_interval is not None:
            self["idle_session_check_interval"] = idle_session_check_interval
        if idle_session_timeout is not None:
            self["idle_session_timeout"] = idle_session_timeout
        if min_idle_session is not None:
            self["min_idle_session"] = _req_int("min_idle_session", min_idle_session, lo=0)
        if tls is not None:
            if not isinstance(tls, Tls):
                raise TypeError("'tls' must be a Tls instance")
            self["tls"] = tls


class Hysteria(_ServerOutbound):
    """
    Hysteria v1 outbound.

    https://sing-box.sagernet.org/configuration/outbound/hysteria/
    """

    _TYPE = "hysteria"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        tls: Tls,
        *,
        up_mbps: Optional[int] = None,
        down_mbps: Optional[int] = None,
        obfs: Optional[str] = None,
        auth: Optional[bytes] = None,
        auth_str: Optional[str] = None,
        recv_window_conn: Optional[int] = None,
        recv_window: Optional[int] = None,
        disable_mtu_discovery: bool = False,
        network: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        if not isinstance(tls, Tls):
            raise TypeError("'tls' must be a Tls instance")
        self["tls"] = tls
        if up_mbps is not None:
            self["up_mbps"] = _req_int("up_mbps", up_mbps, lo=1)
        if down_mbps is not None:
            self["down_mbps"] = _req_int("down_mbps", down_mbps, lo=1)
        if obfs is not None:
            self["obfs"] = obfs
        if auth is not None and auth_str is not None:
            raise ValueError("use either 'auth' or 'auth_str', not both")
        if auth is not None:
            self["auth"] = auth
        if auth_str is not None:
            self["auth_str"] = auth_str
        if recv_window_conn is not None:
            self["recv_window_conn"] = recv_window_conn
        if recv_window is not None:
            self["recv_window"] = recv_window
        if disable_mtu_discovery:
            self["disable_mtu_discovery"] = True
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Hysteria2(_ServerOutbound):
    """
    Hysteria2 outbound.

    https://sing-box.sagernet.org/configuration/outbound/hysteria2/
    """

    _TYPE = "hysteria2"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int,
        password: str,
        tls: Tls,
        *,
        up_mbps: Optional[int] = None,
        down_mbps: Optional[int] = None,
        obfs: Optional[dict] = None,
        brutal_debug: bool = False,
        network: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        self["password"] = _req_str("password", password)
        if not isinstance(tls, Tls):
            raise TypeError("'tls' must be a Tls instance")
        self["tls"] = tls
        if up_mbps is not None:
            self["up_mbps"] = _req_int("up_mbps", up_mbps, lo=1)
        if down_mbps is not None:
            self["down_mbps"] = _req_int("down_mbps", down_mbps, lo=1)
        if obfs is not None:
            self["obfs"] = obfs
        if brutal_debug:
            self["brutal_debug"] = True
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Ssh(_ServerOutbound):
    """
    SSH outbound.

    https://sing-box.sagernet.org/configuration/outbound/ssh/
    """

    _TYPE = "ssh"

    def __init__(
        self,
        tag: str,
        server: str,
        server_port: int = 22,
        *,
        user: Optional[str] = None,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_path: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        host_key: Optional[list[str]] = None,
        host_key_algorithms: Optional[list[str]] = None,
        client_version: Optional[str] = None,
    ):
        super().__init__(tag, server, server_port)
        if user is not None:
            self["user"] = user
        if password is not None:
            self["password"] = password
        if private_key is not None and private_key_path is not None:
            raise ValueError("use either 'private_key' or 'private_key_path', not both")
        if private_key is not None:
            self["private_key"] = private_key
        if private_key_path is not None:
            self["private_key_path"] = private_key_path
        if private_key_passphrase is not None:
            self["private_key_passphrase"] = private_key_passphrase
        if host_key is not None:
            self["host_key"] = host_key
        if host_key_algorithms is not None:
            self["host_key_algorithms"] = host_key_algorithms
        if client_version is not None:
            self["client_version"] = client_version


# ── group outbounds ────────────────────────────────────────────────────────


class Selector(_Outbound):
    """
    Manual-select group outbound.

    https://sing-box.sagernet.org/configuration/outbound/selector/
    """

    _TYPE = "selector"

    def __init__(
        self,
        tag: str,
        outbounds: list[str],
        *,
        default: Optional[str] = None,
        interrupt_exist_connections: bool = False,
    ):
        super().__init__(tag)
        self["outbounds"] = _req_list("outbounds", outbounds)
        if default is not None:
            if default not in outbounds:
                raise ValueError(f"'default' ({default!r}) must be present in 'outbounds'")
            self["default"] = default
        if interrupt_exist_connections:
            self["interrupt_exist_connections"] = True


class Urltest(_Outbound):
    """
    Latency-based automatic-select group outbound.

    https://sing-box.sagernet.org/configuration/outbound/urltest/
    """

    _TYPE = "urltest"

    def __init__(
        self,
        tag: str,
        outbounds: list[str],
        *,
        url: str = "https://www.gstatic.com/generate_204",
        interval: Optional[str] = None,
        tolerance: Optional[int] = None,
        idle_timeout: Optional[str] = None,
        interrupt_exist_connections: bool = False,
    ):
        super().__init__(tag)
        self["outbounds"] = _req_list("outbounds", outbounds)
        self["url"] = _req_str("url", url)
        if interval is not None:
            self["interval"] = interval
        if tolerance is not None:
            self["tolerance"] = _req_int("tolerance", tolerance, lo=0)
        if idle_timeout is not None:
            self["idle_timeout"] = idle_timeout
        if interrupt_exist_connections:
            self["interrupt_exist_connections"] = True


# ── backward-compat alias (typo in original) ───────────────────────────────

Wiregaurd = Wireguard