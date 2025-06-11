import requests
import socket
from colorama import Fore, Style
import re
import json

class WhoisLookup:
    def __init__(self, domain):
        self.domain = domain
        self.server = "whois.verisign-grs.com"  # For .com/.net TLDs

    def lookup(self):
        try:
            print(f"Connecting to {self.server} for domain {self.domain}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.server, 43))
                s.send((self.domain + "\r\n").encode())

                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data

            decoded = response.decode(errors="ignore")
            print(decoded)  # ✅ Raw WHOIS output
            return {
                'domain': self.domain,
                'raw_data': decoded[:500] + "..."  # Preview only
            }

        except Exception as e:
            return {
                'error': str(e),
                'solution': "Firewall or WHOIS blocked. Try a VPN.",
                'alternative': f"https://who.is/whois/{self.domain}"
            }