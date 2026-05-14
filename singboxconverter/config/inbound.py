"""
config/inbound.py — sing-box inbound configuration builders.

Every class is a ``dict`` subclass, so instances can be passed directly
wherever a plain dict is expected (e.g. ``json.dumps(inbound)``).

``__init__`` validates all inputs and raises:
  - ``ValueError``  — missing required field or out-of-range value
  - ``TypeError``   — wrong Python type for a field

NOTE — shared types
-------------------
  ``Tls`` and ``Transport`` are imported from ``config.outbound`` for now.
  When the project grows, move them to ``config/shared.py`` and update
  both modules to import from there.

Listener inbounds (have listen / listen_port)
---------------------------------------------
  Direct, Mixed, Http, Socks, Shadowsocks, Vmess, Trojan,
  Naive, Shadowtls, Tuic, Vless, Anytls, Hysteria, Hysteria2,
  Redirect, Tproxy

Special inbounds
----------------
  Tun         — virtual network interface, no listen address
  Cloudflared — WIP, only in documentation (placeholder)

Usage example
-------------
    from config.inbound import Mixed, Tun, Hysteria2
    from config.outbound import Tls

    listener = Mixed(
        tag="in-mixed",
        listen="127.0.0.1",
        listen_port=7890,
        users=[{"username": "alice", "password": "s3cr3t"}],
    )

    tun = Tun(
        tag="in-tun",
        address=["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        auto_route=True,
    )

    import json
    print(json.dumps([listener, tun], indent=2))
"""

from __future__ import annotations

from typing import Optional

# Tls and Transport are shared between inbound and outbound.
# TODO: move to config/shared.py once the project grows.
from .outbound import Tls, Transport  # noqa: F401  (re-exported for convenience)

__all__ = [
    # listener
    "Direct",
    "Mixed",
    "Http",
    "Socks",
    "Shadowsocks",
    "Vmess",
    "Trojan",
    "Naive",
    "Shadowtls",
    "Tuic",
    "Vless",
    "Anytls",
    "Hysteria",
    "Hysteria2",
    "Redirect",
    "Tproxy",
    # special
    "Tun",
    "Cloudflared",
]


# ── internal validators (mirrors config/outbound.py) ──────────────────────


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


def _tls(value) -> Tls:
    if not isinstance(value, Tls):
        raise TypeError("'tls' must be a Tls instance")
    return value


def _transport(value) -> Transport:
    if not isinstance(value, Transport):
        raise TypeError("'transport' must be a Transport instance")
    return value


# ── abstract base classes ──────────────────────────────────────────────────


class _Inbound(dict):
    """
    Base for all sing-box inbound types.
    Do not instantiate directly.
    """

    _TYPE: str = ""

    def __init__(self, tag: str):
        _req_str("tag", tag)
        super().__init__(type=self._TYPE, tag=tag)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({dict.__repr__(self)})"


_DOMAIN_STRATEGIES = {
    "prefer_ipv4", "prefer_ipv6",
    "ipv4_only", "ipv6_only",
    "",  # empty string = default / unset
}


class _ListenInbound(_Inbound):
    """
    Base for inbounds that bind to a local address and port.

    All parameters beyond ``tag`` are keyword-only so subclasses can add
    positional arguments without breaking the MRO signature.

    Common sing-box listener fields
    --------------------------------
    listen                    — bind IP (default "0.0.0.0")
    listen_port               — bind port (required for most types)
    sniff                     — enable traffic sniffing
    sniff_override_destination — replace destination with sniffed one
    sniff_timeout             — duration string, e.g. "300ms"
    domain_strategy           — DNS resolution strategy for sniffed domains
    udp_timeout               — duration string for UDP session timeout
    proxy_protocol            — accept PROXY protocol header
    detour                    — forward accepted traffic to this outbound tag
    tcp_fast_open             — enable TCP Fast Open
    tcp_multi_path            — enable TCP multi-path
    udp_fragment              — enable UDP fragmentation
    """

    def __init__(
        self,
        tag: str,
        *,
        listen: str = "0.0.0.0",
        listen_port: Optional[int] = None,
        sniff: bool = False,
        sniff_override_destination: bool = False,
        sniff_timeout: Optional[str] = None,
        domain_strategy: Optional[str] = None,
        udp_timeout: Optional[str] = None,
        proxy_protocol: bool = False,
        detour: Optional[str] = None,
        tcp_fast_open: bool = False,
        tcp_multi_path: bool = False,
        udp_fragment: bool = False,
    ):
        super().__init__(tag)
        self["listen"] = _req_str("listen", listen)
        if listen_port is not None:
            self["listen_port"] = _port("listen_port", listen_port)
        if sniff:
            self["sniff"] = True
        if sniff_override_destination:
            self["sniff_override_destination"] = True
        if sniff_timeout is not None:
            self["sniff_timeout"] = sniff_timeout
        if domain_strategy is not None:
            _req_one_of("domain_strategy", domain_strategy, _DOMAIN_STRATEGIES)
            self["domain_strategy"] = domain_strategy
        if udp_timeout is not None:
            self["udp_timeout"] = udp_timeout
        if proxy_protocol:
            self["proxy_protocol"] = True
        if detour is not None:
            self["detour"] = _req_str("detour", detour)
        if tcp_fast_open:
            self["tcp_fast_open"] = True
        if tcp_multi_path:
            self["tcp_multi_path"] = True
        if udp_fragment:
            self["udp_fragment"] = True


# ── listener inbounds ──────────────────────────────────────────────────────


class Direct(_ListenInbound):
    """
    Transparent direct inbound — accepts raw TCP/UDP and forwards it.

    https://sing-box.sagernet.org/configuration/inbound/direct/
    """

    _TYPE = "direct"

    def __init__(
        self,
        tag: str = "in-direct",
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        override_address: Optional[str] = None,
        override_port: Optional[int] = None,
        network: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        if override_address is not None:
            self["override_address"] = _req_str("override_address", override_address)
        if override_port is not None:
            self["override_port"] = _port("override_port", override_port)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Mixed(_ListenInbound):
    """
    Mixed SOCKS5 + HTTP inbound on a single port.

    https://sing-box.sagernet.org/configuration/inbound/mixed/
    """

    _TYPE = "mixed"

    def __init__(
        self,
        tag: str = "in-mixed",
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        users: Optional[list[dict]] = None,
        set_system_proxy: bool = False,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        if users is not None:
            self["users"] = _req_list("users", users)
        if set_system_proxy:
            self["set_system_proxy"] = True


class Http(_ListenInbound):
    """
    HTTP proxy inbound.

    https://sing-box.sagernet.org/configuration/inbound/http/
    """

    _TYPE = "http"

    def __init__(
        self,
        tag: str = "in-http",
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        users: Optional[list[dict]] = None,
        tls: Optional[Tls] = None,
        set_system_proxy: bool = False,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        if users is not None:
            self["users"] = _req_list("users", users)
        if tls is not None:
            self["tls"] = _tls(tls)
        if set_system_proxy:
            self["set_system_proxy"] = True


class Socks(_ListenInbound):
    """
    SOCKS5 proxy inbound.

    https://sing-box.sagernet.org/configuration/inbound/socks/
    """

    _TYPE = "socks"

    def __init__(
        self,
        tag: str = "in-socks",
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        users: Optional[list[dict]] = None,
        set_system_proxy: bool = False,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        if users is not None:
            self["users"] = _req_list("users", users)
        if set_system_proxy:
            self["set_system_proxy"] = True


class Shadowsocks(_ListenInbound):
    """
    Shadowsocks inbound.

    https://sing-box.sagernet.org/configuration/inbound/shadowsocks/
    """

    _TYPE = "shadowsocks"
    _METHODS = {
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "none", "plain",
    }

    def __init__(
        self,
        tag: str,
        *,
        listen_port: int,
        method: str,
        password: str,
        listen: str = "0.0.0.0",
        users: Optional[list[dict]] = None,
        network: Optional[str] = None,
        multiplex: Optional[dict] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        _req_one_of("method", method, self._METHODS)
        self["method"] = method
        self["password"] = _req_str("password", password)
        # multi-user mode: users override the single password above
        if users is not None:
            self["users"] = _req_list("users", users)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network
        if multiplex is not None:
            self["multiplex"] = multiplex


class Vmess(_ListenInbound):
    """
    VMess inbound.

    https://sing-box.sagernet.org/configuration/inbound/vmess/
    """

    _TYPE = "vmess"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        tls: Optional[Tls] = None,
        transport: Optional[Transport] = None,
        multiplex: Optional[dict] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        if tls is not None:
            self["tls"] = _tls(tls)
        if transport is not None:
            self["transport"] = _transport(transport)
        if multiplex is not None:
            self["multiplex"] = multiplex


class Trojan(_ListenInbound):
    """
    Trojan inbound.

    https://sing-box.sagernet.org/configuration/inbound/trojan/
    """

    _TYPE = "trojan"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        tls: Optional[Tls] = None,
        transport: Optional[Transport] = None,
        multiplex: Optional[dict] = None,
        fallback: Optional[dict] = None,
        fallback_for_alpn: Optional[dict] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        if tls is not None:
            self["tls"] = _tls(tls)
        if transport is not None:
            self["transport"] = _transport(transport)
        if multiplex is not None:
            self["multiplex"] = multiplex
        if fallback is not None:
            self["fallback"] = fallback
        if fallback_for_alpn is not None:
            self["fallback_for_alpn"] = fallback_for_alpn


class Naive(_ListenInbound):
    """
    NaïveProxy inbound. Requires TLS.

    https://sing-box.sagernet.org/configuration/inbound/naive/
    """

    _TYPE = "naive"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        tls: Tls,
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        network: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        self["tls"] = _tls(tls)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


class Shadowtls(_ListenInbound):
    """
    ShadowTLS inbound. Requires TLS.

    https://sing-box.sagernet.org/configuration/inbound/shadowtls/
    """

    _TYPE = "shadowtls"
    _VERSIONS = {1, 2, 3}

    def __init__(
        self,
        tag: str,
        version: int,
        handshake: dict,
        tls: Tls,
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        password: Optional[str] = None,
        users: Optional[list[dict]] = None,
        handshake_for_server_name: Optional[dict] = None,
        strict_mode: bool = False,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        _req_one_of("version", version, self._VERSIONS)
        self["version"] = version
        if not isinstance(handshake, dict):
            raise TypeError("'handshake' must be a dict")
        self["handshake"] = handshake
        self["tls"] = _tls(tls)
        # v1 uses a single password; v2/v3 use per-user passwords
        if version == 1:
            if password is None:
                raise ValueError("'password' is required for ShadowTLS v1")
            self["password"] = _req_str("password", password)
        else:
            if users is None:
                raise ValueError("'users' is required for ShadowTLS v2/v3")
            self["users"] = _req_list("users", users)
        if handshake_for_server_name is not None:
            self["handshake_for_server_name"] = handshake_for_server_name
        if strict_mode:
            self["strict_mode"] = True


class Tuic(_ListenInbound):
    """
    TUIC v5 inbound. Requires TLS.

    https://sing-box.sagernet.org/configuration/inbound/tuic/
    """

    _TYPE = "tuic"
    _CONGESTION = {"cubic", "new_reno", "bbr"}

    def __init__(
        self,
        tag: str,
        users: list[dict],
        tls: Tls,
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        congestion_control: str = "cubic",
        auth_timeout: Optional[str] = None,
        zero_rtt_handshake: bool = False,
        heartbeat: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        self["tls"] = _tls(tls)
        _req_one_of("congestion_control", congestion_control, self._CONGESTION)
        self["congestion_control"] = congestion_control
        if auth_timeout is not None:
            self["auth_timeout"] = auth_timeout
        if zero_rtt_handshake:
            self["zero_rtt_handshake"] = True
        if heartbeat is not None:
            self["heartbeat"] = heartbeat


class Vless(_ListenInbound):
    """
    VLESS inbound.

    https://sing-box.sagernet.org/configuration/inbound/vless/
    """

    _TYPE = "vless"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        tls: Optional[Tls] = None,
        transport: Optional[Transport] = None,
        multiplex: Optional[dict] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        if tls is not None:
            self["tls"] = _tls(tls)
        if transport is not None:
            self["transport"] = _transport(transport)
        if multiplex is not None:
            self["multiplex"] = multiplex


class Anytls(_ListenInbound):
    """
    AnyTLS inbound.

    https://sing-box.sagernet.org/configuration/inbound/anytls/
    """

    _TYPE = "anytls"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        tls: Optional[Tls] = None,
        padding_scheme: Optional[str] = None,
        idle_session_check_interval: Optional[str] = None,
        idle_session_timeout: Optional[str] = None,
        min_idle_session: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        if tls is not None:
            self["tls"] = _tls(tls)
        if padding_scheme is not None:
            self["padding_scheme"] = padding_scheme
        if idle_session_check_interval is not None:
            self["idle_session_check_interval"] = idle_session_check_interval
        if idle_session_timeout is not None:
            self["idle_session_timeout"] = idle_session_timeout
        if min_idle_session is not None:
            self["min_idle_session"] = _req_int("min_idle_session", min_idle_session, lo=0)


class Hysteria(_ListenInbound):
    """
    Hysteria v1 inbound. Requires TLS.

    https://sing-box.sagernet.org/configuration/inbound/hysteria/
    """

    _TYPE = "hysteria"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        tls: Tls,
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        up_mbps: Optional[int] = None,
        down_mbps: Optional[int] = None,
        obfs: Optional[str] = None,
        recv_window_conn: Optional[int] = None,
        recv_window_client: Optional[int] = None,
        max_conn_client: Optional[int] = None,
        disable_mtu_discovery: bool = False,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        self["tls"] = _tls(tls)
        if up_mbps is not None:
            self["up_mbps"] = _req_int("up_mbps", up_mbps, lo=1)
        if down_mbps is not None:
            self["down_mbps"] = _req_int("down_mbps", down_mbps, lo=1)
        if obfs is not None:
            self["obfs"] = obfs
        if recv_window_conn is not None:
            self["recv_window_conn"] = recv_window_conn
        if recv_window_client is not None:
            self["recv_window_client"] = recv_window_client
        if max_conn_client is not None:
            self["max_conn_client"] = _req_int("max_conn_client", max_conn_client, lo=1)
        if disable_mtu_discovery:
            self["disable_mtu_discovery"] = True


class Hysteria2(_ListenInbound):
    """
    Hysteria2 inbound. Requires TLS.

    https://sing-box.sagernet.org/configuration/inbound/hysteria2/
    """

    _TYPE = "hysteria2"

    def __init__(
        self,
        tag: str,
        users: list[dict],
        tls: Tls,
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        up_mbps: Optional[int] = None,
        down_mbps: Optional[int] = None,
        obfs: Optional[dict] = None,
        ignore_client_bandwidth: bool = False,
        masquerade: Optional[str] = None,
        brutal_debug: bool = False,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        self["users"] = _req_list("users", users)
        self["tls"] = _tls(tls)
        if up_mbps is not None:
            self["up_mbps"] = _req_int("up_mbps", up_mbps, lo=1)
        if down_mbps is not None:
            self["down_mbps"] = _req_int("down_mbps", down_mbps, lo=1)
        if obfs is not None:
            self["obfs"] = obfs
        if ignore_client_bandwidth:
            self["ignore_client_bandwidth"] = True
        if masquerade is not None:
            self["masquerade"] = masquerade
        if brutal_debug:
            self["brutal_debug"] = True


class Redirect(_ListenInbound):
    """
    Redirect (iptables REDIRECT) transparent proxy inbound. Linux only.

    https://sing-box.sagernet.org/configuration/inbound/redirect/
    """

    _TYPE = "redirect"

    def __init__(
        self,
        tag: str = "in-redirect",
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)


class Tproxy(_ListenInbound):
    """
    TProxy transparent proxy inbound. Linux only.

    https://sing-box.sagernet.org/configuration/inbound/tproxy/
    """

    _TYPE = "tproxy"

    def __init__(
        self,
        tag: str = "in-tproxy",
        *,
        listen_port: int,
        listen: str = "0.0.0.0",
        network: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(tag, listen=listen, listen_port=listen_port, **kwargs)
        if network is not None:
            _req_one_of("network", network, {"tcp", "udp"})
            self["network"] = network


# ── special inbounds ───────────────────────────────────────────────────────


_TUN_STACKS = {"system", "gvisor", "mixed"}


class Tun(_Inbound):
    """
    TUN virtual network interface inbound.
    Does not bind to a port — operates at the network layer.

    https://sing-box.sagernet.org/configuration/inbound/tun/
    """

    _TYPE = "tun"

    def __init__(
        self,
        tag: str = "in-tun",
        *,
        address: list[str],
        interface_name: Optional[str] = None,
        mtu: int = 9000,
        auto_route: bool = False,
        strict_route: bool = False,
        stack: str = "mixed",
        route_address: Optional[list[str]] = None,
        route_exclude_address: Optional[list[str]] = None,
        route_address_set: Optional[list[str]] = None,
        route_exclude_address_set: Optional[list[str]] = None,
        endpoint_independent_nat: bool = False,
        include_interface: Optional[list[str]] = None,
        exclude_interface: Optional[list[str]] = None,
        include_uid: Optional[list[int]] = None,
        exclude_uid: Optional[list[int]] = None,
        include_uid_range: Optional[list[str]] = None,
        exclude_uid_range: Optional[list[str]] = None,
        include_android_user: Optional[list[int]] = None,
        exclude_android_user: Optional[list[int]] = None,
        include_package: Optional[list[str]] = None,
        exclude_package: Optional[list[str]] = None,
        platform: Optional[dict] = None,
        sniff: bool = False,
        sniff_override_destination: bool = False,
        sniff_timeout: Optional[str] = None,
        domain_strategy: Optional[str] = None,
        udp_timeout: Optional[str] = None,
    ):
        super().__init__(tag)
        self["address"] = _req_list("address", address)
        if interface_name is not None:
            self["interface_name"] = _req_str("interface_name", interface_name)
        self["mtu"] = _req_int("mtu", mtu, lo=1280, hi=65535)
        _req_one_of("stack", stack, _TUN_STACKS)
        self["stack"] = stack
        if auto_route:
            self["auto_route"] = True
        if strict_route:
            self["strict_route"] = True
        if route_address is not None:
            self["route_address"] = route_address
        if route_exclude_address is not None:
            self["route_exclude_address"] = route_exclude_address
        if route_address_set is not None:
            self["route_address_set"] = route_address_set
        if route_exclude_address_set is not None:
            self["route_exclude_address_set"] = route_exclude_address_set
        if endpoint_independent_nat:
            self["endpoint_independent_nat"] = True
        # interface / uid / package filters (all optional)
        for key, val in (
            ("include_interface", include_interface),
            ("exclude_interface", exclude_interface),
            ("include_uid", include_uid),
            ("exclude_uid", exclude_uid),
            ("include_uid_range", include_uid_range),
            ("exclude_uid_range", exclude_uid_range),
            ("include_android_user", include_android_user),
            ("exclude_android_user", exclude_android_user),
            ("include_package", include_package),
            ("exclude_package", exclude_package),
        ):
            if val is not None:
                self[key] = val
        if platform is not None:
            self["platform"] = platform
        # sniffing fields (mirrors _ListenInbound but Tun doesn't inherit it)
        if sniff:
            self["sniff"] = True
        if sniff_override_destination:
            self["sniff_override_destination"] = True
        if sniff_timeout is not None:
            self["sniff_timeout"] = sniff_timeout
        if domain_strategy is not None:
            _req_one_of("domain_strategy", domain_strategy, _DOMAIN_STRATEGIES)
            self["domain_strategy"] = domain_strategy
        if udp_timeout is not None:
            self["udp_timeout"] = udp_timeout


class Cloudflared(_Inbound):
    """
    Cloudflare Tunnel inbound.

    ⚠  WIP — documented but not yet available in stable sing-box releases.
    Fields may change without notice; kept as a placeholder.

    https://sing-box.sagernet.org/configuration/inbound/cloudflare/
    """

    _TYPE = "cloudflared"

    def __init__(
        self,
        tag: str = "in-cloudflared",
        *,
        token: Optional[str] = None,
        tunnel_id: Optional[str] = None,
        secret: Optional[str] = None,
    ):
        super().__init__(tag)
        if token is not None:
            self["token"] = _req_str("token", token)
        if tunnel_id is not None:
            self["tunnel_id"] = _req_str("tunnel_id", tunnel_id)
        if secret is not None:
            self["secret"] = _req_str("secret", secret)