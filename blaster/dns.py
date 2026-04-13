import dns.resolver
import socket
from colorama import Fore, Style

# ============================================================
#                      DNS LOOKUP MODULE
#
#   PRESERVED:
#     - Class name: DNSLookup
#     - Method name: lookup()
#     - Return structure: dict with record type keys
#     - A, MX, TXT, NS records
#     - Extra IPs from common subdomains (www, mail, ftp)
#
#   ADDITIONS:
#     - CNAME records  (alias chains, reveals CDN/hosting)
#     - AAAA records   (IPv6 addresses)
#     - SOA records    (zone authority, serial, admin email)
#     - CAA records    (which CAs can issue SSL certs)
#     - TTL values     (caching behavior per record)
#     - Specific exception handling (no more bare except:)
#     - DNSSEC detection (is the domain DNSSEC signed?)
# ============================================================

class DNSLookup:
    def __init__(self, domain):
        self.domain = domain

    def lookup(self):
        records = {
            # --- PRESERVED RECORD TYPES ---
            'A': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'ips': [],

            # --- ADDED RECORD TYPES ---
            'AAAA': [],     # IPv6 addresses
            'CNAME': [],    # Canonical name aliases
            'SOA': [],      # Start of Authority
            'CAA': [],      # Certificate Authority Authorization
            'TTL': {},      # TTL per record type
            'DNSSEC': False # DNSSEC signing status
        }

        # ----------------------------------------------------
        #   A RECORDS (IPv4)
        #   PRESERVED — same logic, fixed bare except
        # ----------------------------------------------------
        try:
            a_answers = dns.resolver.resolve(self.domain, 'A')
            records['A'] = [str(r) for r in a_answers]
            records['TTL']['A'] = a_answers.rrset.ttl
        except dns.resolver.NXDOMAIN:
            records['A'] = ["Domain does not exist"]
        except dns.resolver.NoAnswer:
            records['A'] = ["No A records found"]
        except dns.resolver.Timeout:
            records['A'] = ["DNS query timed out"]
        except Exception as e:
            records['A'] = [f"Error: {str(e)}"]

        # ----------------------------------------------------
        #   MX RECORDS (Mail Servers)
        #   PRESERVED — same logic, fixed bare except
        # ----------------------------------------------------
        try:
            mx_answers = dns.resolver.resolve(self.domain, 'MX')
            records['MX'] = [str(r.exchange) for r in mx_answers]
            records['TTL']['MX'] = mx_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['MX'] = ["No MX records found"]
        except dns.resolver.Timeout:
            records['MX'] = ["DNS query timed out"]
        except Exception as e:
            records['MX'] = [f"Error: {str(e)}"]

        # ----------------------------------------------------
        #   TXT RECORDS (SPF, DKIM, DMARC, verification)
        #   PRESERVED — same logic, fixed bare except
        # ----------------------------------------------------
        try:
            txt_answers = dns.resolver.resolve(self.domain, 'TXT')
            records['TXT'] = [r.to_text().strip('"') for r in txt_answers]
            records['TTL']['TXT'] = txt_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['TXT'] = ["No TXT records found"]
        except dns.resolver.Timeout:
            records['TXT'] = ["DNS query timed out"]
        except Exception as e:
            records['TXT'] = [f"Error: {str(e)}"]

        # ----------------------------------------------------
        #   NS RECORDS (Name Servers)
        #   PRESERVED — same logic, fixed bare except
        # ----------------------------------------------------
        try:
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            records['NS'] = [str(r.target) for r in ns_answers]
            records['TTL']['NS'] = ns_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['NS'] = ["No NS records found"]
        except dns.resolver.Timeout:
            records['NS'] = ["DNS query timed out"]
        except Exception as e:
            records['NS'] = [f"Error: {str(e)}"]

        # ----------------------------------------------------
        #   AAAA RECORDS — ADDED
        #   IPv6 addresses for the domain
        #   Useful to know if target is IPv6 reachable
        # ----------------------------------------------------
        try:
            aaaa_answers = dns.resolver.resolve(self.domain, 'AAAA')
            records['AAAA'] = [str(r) for r in aaaa_answers]
            records['TTL']['AAAA'] = aaaa_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['AAAA'] = ["No AAAA records found"]
        except dns.resolver.Timeout:
            records['AAAA'] = ["DNS query timed out"]
        except Exception as e:
            records['AAAA'] = [f"Error: {str(e)}"]

        # ----------------------------------------------------
        #   CNAME RECORDS — ADDED
        #   Alias records — reveals CDN providers, hosting
        #   e.g. www → target.cloudfront.net reveals AWS CDN
        # ----------------------------------------------------
        try:
            cname_answers = dns.resolver.resolve(self.domain, 'CNAME')
            records['CNAME'] = [str(r.target) for r in cname_answers]
            records['TTL']['CNAME'] = cname_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['CNAME'] = ["No CNAME records found"]
        except dns.resolver.NoNameservers:
            records['CNAME'] = ["No CNAME records found"]
        except dns.resolver.Timeout:
            records['CNAME'] = ["DNS query timed out"]
        except Exception as e:
            records['CNAME'] = [f"Error: {str(e)}"]

        # ----------------------------------------------------
        #   SOA RECORD — ADDED
        #   Start of Authority — zone admin email, serial
        #   number, refresh intervals. Useful for identifying
        #   the primary nameserver and admin contact
        # ----------------------------------------------------
        try:
            soa_answers = dns.resolver.resolve(self.domain, 'SOA')
            for r in soa_answers:
                records['SOA'].append({
                    'mname':   str(r.mname),    # Primary nameserver
                    'rname':   str(r.rname),    # Admin email (@ = .)
                    'serial':  int(r.serial),   # Zone version number
                    'refresh': int(r.refresh),  # Refresh interval
                    'retry':   int(r.retry),    # Retry interval
                    'expire':  int(r.expire),   # Expiry interval
                })
            records['TTL']['SOA'] = soa_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['SOA'] = []
        except dns.resolver.Timeout:
            records['SOA'] = []
        except Exception:
            records['SOA'] = []

        # ----------------------------------------------------
        #   CAA RECORDS — ADDED
        #   Certificate Authority Authorization
        #   Shows which CAs are allowed to issue SSL certs
        #   e.g. "letsencrypt.org" or "digicert.com"
        #   Missing CAA = any CA can issue certs (risky)
        # ----------------------------------------------------
        try:
            caa_answers = dns.resolver.resolve(self.domain, 'CAA')
            records['CAA'] = [r.to_text() for r in caa_answers]
            records['TTL']['CAA'] = caa_answers.rrset.ttl
        except dns.resolver.NoAnswer:
            records['CAA'] = ["No CAA records (any CA can issue certs)"]
        except dns.resolver.Timeout:
            records['CAA'] = ["DNS query timed out"]
        except Exception:
            records['CAA'] = ["No CAA records (any CA can issue certs)"]

        # ----------------------------------------------------
        #   DNSSEC DETECTION — ADDED
        #   Checks if the domain has DNSSEC signatures (RRSIG)
        #   DNSSEC protects against DNS spoofing/cache poisoning
        #   True = signed, False = unsigned (vulnerable)
        # ----------------------------------------------------
        try:
            dns.resolver.resolve(self.domain, 'RRSIG')
            records['DNSSEC'] = True
        except Exception:
            records['DNSSEC'] = False

        # ----------------------------------------------------
        #   EXTRA IPs FROM COMMON SUBDOMAINS
        #   PRESERVED — exactly as original
        # ----------------------------------------------------
        for sub in ["www", "mail", "ftp"]:
            try:
                ips = socket.gethostbyname_ex(f"{sub}.{self.domain}")[2]
                records['ips'].extend(ips)
            except Exception:
                pass

        records['ips'] = list(set(records['ips']))
        return records