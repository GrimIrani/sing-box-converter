def rule2json(rule):
    """return json
    ip: 1.1.1.1
    domain: example.com
    sufix: example.com
    geoip: geoip:ir
    geosite: geosite:nsfw
    """
    match rule:
        case url if rule.startwith("http"):
            return {"url": url}
        case ip if rule.startwith():  # TODO: regex need
            pass
        case geoip if rule.startwith("geoip"):
            return geoip
        case geosite if rule.startwith("geosite"):
            pass

        case _:  # INVALID INPUT
            raise ValueError(
                "Input should be one of these: 'http://domain.com'/1.1.1.1/geoip:us/geosite:nsfe"
            )
