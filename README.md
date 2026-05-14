# sing-box-converter

A Python library for converting proxy URIs into [sing-box](https://sing-box.sagernet.org/) JSON configuration.

Paste a `vless://`, `ss://`, or `vmess://` URI and get a ready-to-use sing-box config.

> **Work in progress** -- core config building works, CLI and GUI are coming.

## Install

```bash
git clone https://github.com/GrimIrani/sing-box-converter.git
cd sing-box-converter
```

No external dependencies -- pure Python 3.10+.

## Usage

### As a library

```python
import singboxconverter as sbc

config = sbc.Config()
config.inbound("127.0.0.1", 1080)
config.outbound("vless://uuid@server:443?security=tls&sni=example.com#my-proxy")
config.block("geosite:nsfw")
config.proxy("geoip:us")
config.direct("geoip:private")
config.default("direct")
config.export("config.json")
```

Fluent chaining works too:

```python
config = (
    sbc.Config()
    .inbound("socks5://127.0.0.1:1080")
    .outbound("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#my-ss")
    .block("geosite:malware")
    .default("proxy")
    .export("config.json")
)
```

### Inbound formats

| Format | Example | Creates |
|---|---|---|
| Address + port | `config.inbound("127.0.0.1", 1080)` | Mixed (SOCKS5 + HTTP) |
| SOCKS5 URI | `config.inbound("socks5://127.0.0.1:1080")` | SOCKS5 |
| HTTP URI | `config.inbound("http://0.0.0.0:8080")` | HTTP proxy |

### Outbound formats

| Format | Example |
|---|---|
| Direct | `config.outbound("direct")` |
| VLESS | `config.outbound("vless://uuid@host:port?...")` |
| Shadowsocks | `config.outbound("ss://...")` |
| VMess | `config.outbound("vmess://...")` |

### Routing rules

```python
config.block("geosite:nsfw")         # block by geosite category
config.block("geosite:malware")      # block malware domains
config.direct("geoip:private")       # direct for private IPs
config.proxy("geoip:us")             # proxy US traffic
config.direct("https://google.com")  # direct for specific domain
config.default("direct")             # default: direct / proxy / block
```

### CLI (coming soon)

```bash
sing-box-converter "vless://..." > config.json
```

## How it works

Three routing modes:
- **direct** -- bypass the proxy
- **block** -- drop the traffic
- **proxy** -- send through the proxy server

The library auto-adds `direct` and `block` outbounds if you don't specify them, and `proxy` rules automatically point to your first proxy outbound.

## Supported protocols

| Protocol | URI parsing | Outbound | Inbound |
|---|---|---|---|
| VLESS | yes | yes | yes |
| Shadowsocks | yes | yes | yes |
| VMess | yes | yes | yes |
| Trojan | -- | yes | yes |
| Hysteria / Hysteria2 | -- | yes | yes |
| WireGuard | -- | yes | -- |
| TUIC | -- | yes | yes |
| ShadowTLS | -- | yes | yes |
| Tor | -- | yes | -- |
| SSH | -- | yes | -- |
| HTTP / SOCKS | -- | yes | yes |
| TUN | -- | -- | yes |

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

[GPL-3.0](LICENSE)
