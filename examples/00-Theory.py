import singboxconverter as sbc

sbc.in.addProxy("socks5://127.0.0.1:1080")
sbc.out.addProxy("vless://...")

# For make all the connections direct/proxy/block:
sbc.rule.default("direct")

sbc.rule.block("geosite:nsfw")
sbc.rule.proxy("geoip:us")
sbc.rule.direct("https://google.com")
print("Here Comes the rules:", sbc.rules)

sbc.export("config.json")
# or: sbc.connect()
# or: sbc.tun()
# or: sbc.system_proxy()
