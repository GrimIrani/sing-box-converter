"""
This is a simple example for writing a mixed proxy(both http/socks5) as outbound.
which is meant to be a simple socks5 server.
"""

import singboxconverter as sbc

sbc.addProxy("127.0.0.1", "1080")

# sbc.block("geosite:nsfw")
# sbc.proxy("geoip:us")
# sbc.direct("https://google.com")

# For make all the connections direct/proxy/block:
# sbc.default("direct")

sbc.export("config.json")
# or: sbc.connect()
