PRESETS = {
    "google": "tls://8.8.8.8",
    "google-doh": "https://dns.google/dns-query",
    "cloudflare": "tls://1.1.1.1",
    "cloudflare-doh": "https://cloudflare-dns.com/dns-query",
    "quad9": "tls://9.9.9.9",
    "adguard": "tls://dns.adguard-dns.com",
    "adguard-doh": "https://dns.adguard-dns.com/dns-query",
}


def build(servers):
    """Build a sing-box DNS config block from a list of server addresses.

    Server addresses can be preset names (e.g. "google", "cloudflare")
    or raw addresses (e.g. "tls://8.8.8.8", "https://1.1.1.1/dns-query", "8.8.8.8").
    """
    if not servers:
        return {}
    entries = []
    for i, addr in enumerate(servers):
        resolved = PRESETS.get(addr, addr)
        entries.append({"tag": f"dns-{i}", "address": resolved})
    return {"servers": entries, "final": "dns-0"}
