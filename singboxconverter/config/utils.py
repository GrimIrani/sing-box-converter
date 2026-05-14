import re
from urllib.parse import urlparse

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")

GEOSITE_URL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
GEOIP_URL = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"


def parse_rule(rule_str):
    """Parse a rule string into a partial sing-box route rule dict.

    The caller must add the "outbound" field.

    Supported formats:
        geosite:category  -> {"rule_set": ["geosite-category"]}
        geoip:code        -> {"rule_set": ["geoip-code"]}
        1.2.3.4           -> {"ip_cidr": ["1.2.3.4/32"]}
        1.2.3.0/24        -> {"ip_cidr": ["1.2.3.0/24"]}
        https://host/...  -> {"domain": ["host"]}
        example.com       -> {"domain_suffix": [".example.com"]}
    """
    if rule_str.startswith("geosite:"):
        value = rule_str.split(":", 1)[1]
        return {"rule_set": [f"geosite-{value}"]}

    if rule_str.startswith("geoip:"):
        value = rule_str.split(":", 1)[1]
        return {"rule_set": [f"geoip-{value}"]}

    if rule_str.startswith("http://") or rule_str.startswith("https://"):
        parsed = urlparse(rule_str)
        return {"domain": [parsed.hostname]}

    if _IP_RE.match(rule_str):
        if "/" not in rule_str:
            rule_str += "/32"
        return {"ip_cidr": [rule_str]}

    if "." in rule_str:
        domain = rule_str.lstrip(".")
        return {"domain_suffix": [domain]}

    raise ValueError(
        f"Cannot parse rule: {rule_str!r}. "
        "Expected geosite:X, geoip:X, IP, URL, or domain."
    )


def build_rule_sets(rules):
    """Collect rule_set tags from rules and build remote rule_set definitions."""
    tags = set()
    for rule in rules:
        for tag in rule.get("rule_set", []):
            tags.add(tag)

    if not tags:
        return []

    rule_sets = []
    for tag in sorted(tags):
        if tag.startswith("geosite-"):
            url = f"{GEOSITE_URL}/{tag}.srs"
        elif tag.startswith("geoip-"):
            url = f"{GEOIP_URL}/{tag}.srs"
        else:
            continue
        rule_sets.append({
            "tag": tag,
            "type": "remote",
            "format": "binary",
            "url": url,
            "download_detour": "out-direct",
        })
    return rule_sets
