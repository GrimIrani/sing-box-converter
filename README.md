> WORK-IN-PROCESS!
# sing-box-converter

it's a lib(+GUI) tool to convert any proxy to sing-box.

## Quick:
this is a quick knowledge good for know:
we have 3 kind of passing connection:
- direct: Which means DO NOT USE the proxy.
- block: Which means BLOCK THEM.
- proxy: Which means TO BE proxified.


### Usage(CLI):
```
$sing-box-converter "ss://..." --dns 1.1.1.1 -- 
{
    ...
}

$sing-box-converter "vless://..." > config.json
```

### Usage(lib):
```python
import singboxconverter as sbc

config = sbc.Config()

config.inbound("127.0.0.1", "1080")
config.outbound("direct")

config.block("geosite:nsfw")
config.proxy("geoip:us")
config.direct("https://google.com")

config.export("config.json")
# or: config.connect() / config.tun() / config.system_proxy()
```

### Usage(GUI):
> TODO: Picture...

## Contributing

Contributions are always welcome! If you find a bug or have an idea for an improvement, feel free to create an issue or submit a pull request.
