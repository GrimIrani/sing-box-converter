import re
from urllib.parse import urlparse

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")


def parse_rule(rule_str):
    """Parse a rule string into a partial sing-box route rule dict.

    The caller must add the "outbound" field.

    Supported formats:
        geosite:category  -> {"geosite": ["category"]}
        geoip:code        -> {"geoip": ["code"]}
        1.2.3.4           -> {"ip_cidr": ["1.2.3.4/32"]}
        1.2.3.0/24        -> {"ip_cidr": ["1.2.3.0/24"]}
        https://host/...  -> {"domain": ["host"]}
        example.com       -> {"domain_suffix": [".example.com"]}
    """
    if rule_str.startswith("geosite:"):
        value = rule_str.split(":", 1)[1]
        return {"geosite": [value]}

    if rule_str.startswith("geoip:"):
        value = rule_str.split(":", 1)[1]
        return {"geoip": [value]}

    if rule_str.startswith("http://") or rule_str.startswith("https://"):
        parsed = urlparse(rule_str)
        return {"domain": [parsed.hostname]}

    if _IP_RE.match(rule_str):
        if "/" not in rule_str:
            rule_str += "/32"
        return {"ip_cidr": [rule_str]}

    if "." in rule_str:
        domain = rule_str.lstrip(".")
        return {"domain_suffix": ["." + domain]}

    raise ValueError(
        f"Cannot parse rule: {rule_str!r}. "
        "Expected geosite:X, geoip:X, IP, URL, or domain."
    )
