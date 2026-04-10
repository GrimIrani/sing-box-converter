class block:
    def __init__(self, cross):
        match cross:
            case url if cross.startwith("http"):
                return {"url": url}
            case ip if cross.startwith():  # TODO: regex need
                pass
            case geoip if cross.startwith("geoip"):
                return geoip
            case geosite if cross.startwith("geosite"):
                pass

            case _:  # INVALID INPUT
                raise ValueError(
                    "Input should be one of these: 'http://domain.com'/1.1.1.1/geoip:us/geosite:nsfe"
                )
