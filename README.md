# sing-box converter

it's a lib(+GUI) tool to convert any proxy to sing-box.

## Quick:
this is a quick knowledge good for know:
we have 3 kind of passing connection:
- direct: Which means DO NOT USE the proxy.
- block: Which means BLOCK THEM.
- proxy: Which means TO BE proxified.


### Usage(CLI):
```
$sing-box-converter "ss://..."
{
    ...
}

$sing-box-converter "vless://..." > config.json
```

### Usage(lib):
```python
import singboxconverter as sbc

proxy = "vless://..."

sbc.add(proxy)

sbc.export("config.json")
# or: sbc.connect(tun=True)
```

### Usage(GUI):
> TODO: Picture...

## Contributing

Contributions are always welcome! If you find a bug or have an idea for an improvement, feel free to create an issue or submit a pull request.
