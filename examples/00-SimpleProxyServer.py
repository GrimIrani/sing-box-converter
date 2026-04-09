"""
This is a simple example for writing a mixed proxy(both http/socks5) as outbound.
which is meant to be a simple socks5 server.
"""

import singboxconverter as sbc

config = sbc.Config()

config.inbound("127.0.0.1", "1080")
config.outbound("direct")

config.block("geosite:nsfw")
config.proxy("geoip:us")
config.direct("https://google.com")

config.default("direct")

config.export("config.json")
# or: config.connect() / config.tun() / config.system_proxy()
