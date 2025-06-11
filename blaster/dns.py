import dns.resolver
import socket
from colorama import Fore, Style

class DNSLookup:
    def __init__(self, domain):
        self.domain = domain
    
    def lookup(self):
        records = {
            'A': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'ips': []
        }

        try:
            # A records
            a_answers = dns.resolver.resolve(self.domain, 'A')
            records['A'] = [str(r) for r in a_answers]
        except:
            records['A'] = ["No A records found"]

        try:
            # MX records
            mx_answers = dns.resolver.resolve(self.domain, 'MX')
            records['MX'] = [str(r.exchange) for r in mx_answers]
        except:
            records['MX'] = ["No MX records found"]

        try:
            # TXT records
            txt_answers = dns.resolver.resolve(self.domain, 'TXT')
            records['TXT'] = [r.to_text().strip('"') for r in txt_answers]
        except:
            records['TXT'] = ["No TXT records found"]

        try:
            # NS records
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            records['NS'] = [str(r.target) for r in ns_answers]
        except:
            records['NS'] = ["No NS records found"]

        # Extra: get IPs for common subdomains
        for sub in ["www", "mail", "ftp"]:
            try:
                ips = socket.gethostbyname_ex(f"{sub}.{self.domain}")[2]
                records['ips'].extend(ips)
            except:
                pass

        # Remove duplicates
        records['ips'] = list(set(records['ips']))
        return records
