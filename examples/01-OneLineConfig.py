import singboxconverter as sbc

config = (
    sbc.Config()
    .inbound("socks5://127.0.0.1:1080")
    .outbound("vless://...")
    .default("direct")
    .block("geosite:nsfw")
    .proxy("geoip:us")
    .direct("geoip:private")
)

config.export("config.json")
