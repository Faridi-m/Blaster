from ipwhois import IPWhois


class ASNLookup:
    def __init__(self, ip):
        self.ip = ip

    def lookup(self):
        try:
            obj = IPWhois(self.ip)
            result = obj.lookup_rdap()

            return {
                "ip": self.ip,
                "asn": result.get("asn"),
                "org": result.get("network", {}).get("name"),
                "country": result.get("network", {}).get("country")
            }

        except Exception as e:
            return {
                "ip": self.ip,
                "error": str(e)
            }