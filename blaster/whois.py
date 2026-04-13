import socket
import re
from colorama import Fore, Style

# ============================================================
#                     WHOIS LOOKUP MODULE
#
#   PRESERVED:
#     - Class name: WhoisLookup
#     - Method name: lookup()
#     - Raw WHOIS data in return dict
#     - Error return structure with solution/alternative
#
#   ADDITIONS:
#     - TLD detection + correct WHOIS server routing
#       (was hardcoded to Verisign — only worked for .com/.net)
#     - Parsed key fields: registrar, creation, expiry,
#       updated date, registrant, name servers, status
#     - Removed print(decoded) from inside the class
#       (display belongs in blaster.py, not the module)
#     - Referral WHOIS follow-through
#       (Verisign often refers to registrar's WHOIS server,
#        now we follow that referral for full data)
#     - Cleaner timeout and error handling
# ============================================================

class WhoisLookup:
    def __init__(self, domain):
        self.domain = domain

        # ----------------------------------------------------
        #   TLD → WHOIS SERVER MAP — ADDED
        #   Covers all common TLDs so tool works globally
        #   Previously hardcoded to Verisign (.com/.net only)
        # ----------------------------------------------------
        self.whois_servers = {
            # Generic TLDs
            'com':      'whois.verisign-grs.com',
            'net':      'whois.verisign-grs.com',
            'org':      'whois.pir.org',
            'info':     'whois.afilias.net',
            'biz':      'whois.biz',
            'io':       'whois.nic.io',
            'co':       'whois.nic.co',
            'app':      'whois.nic.google',
            'dev':      'whois.nic.google',
            'ai':       'whois.nic.ai',
            'me':       'whois.nic.me',
            'tv':       'whois.nic.tv',
            'cc':       'whois.nic.cc',
            'mobi':     'whois.dotmobiregistry.net',
            'name':     'whois.nic.name',
            'pro':      'whois.registrypro.pro',
            'tel':      'whois.nic.tel',
            'travel':   'whois.nic.travel',
            'museum':   'whois.museum',
            'coop':     'whois.nic.coop',
            'aero':     'whois.aero',
            'jobs':     'jobswhois.verisign.com',
            'cat':      'whois.cat',
            'post':     'whois.dotpostregistry.net',
            'xxx':      'whois.nic.xxx',

            # Country TLDs
            'us':       'whois.nic.us',
            'uk':       'whois.nic.uk',
            'ca':       'whois.cira.ca',
            'au':       'whois.auda.org.au',
            'de':       'whois.denic.de',
            'fr':       'whois.afnic.fr',
            'jp':       'whois.jprs.jp',
            'cn':       'whois.cnnic.cn',
            'in':       'whois.registry.in',
            'pk':       'whois.pknic.net.pk',
            'ru':       'whois.tcinet.ru',
            'br':       'whois.registro.br',
            'nl':       'whois.domain-registry.nl',
            'eu':       'whois.eu',
            'es':       'whois.nic.es',
            'it':       'whois.nic.it',
            'pl':       'whois.dns.pl',
            'se':       'whois.iis.se',
            'no':       'whois.norid.no',
            'dk':       'whois.dk-hostmaster.dk',
            'fi':       'whois.fi',
            'ch':       'whois.nic.ch',
            'at':       'whois.nic.at',
            'be':       'whois.dns.be',
            'nz':       'whois.srs.net.nz',
            'za':       'whois.registry.net.za',
            'mx':       'whois.mx',
            'ar':       'whois.nic.ar',
            'sg':       'whois.sgnic.sg',
            'hk':       'whois.hkirc.hk',
            'tw':       'whois.twnic.net.tw',
            'kr':       'whois.kr',
            'tr':       'whois.nic.tr',
            'id':       'whois.id',
            'my':       'whois.mynic.my',
            'th':       'whois.thnic.co.th',
            'ph':       'whois.dot.ph',
            'vn':       'whois.vnnic.vn',
            'ae':       'whois.aeda.net.ae',
            'sa':       'whois.nic.net.sa',
        }

    # --------------------------------------------------------
    #   TLD DETECTION — ADDED
    #   Extracts TLD from domain and returns correct server
    #   Falls back to whois.iana.org for unknown TLDs
    # --------------------------------------------------------
    def _get_whois_server(self):
        parts = self.domain.split('.')
        tld = parts[-1].lower()

        # Handle second-level TLDs like .co.uk, .com.pk
        if len(parts) >= 3:
            second_level_tld = f"{parts[-2]}.{parts[-1]}".lower()
            if second_level_tld in self.whois_servers:
                return self.whois_servers[second_level_tld]

        return self.whois_servers.get(tld, 'whois.iana.org')

    # --------------------------------------------------------
    #   RAW WHOIS QUERY — PRESERVED CORE LOGIC
    #   Same socket approach, now uses dynamic server
    # --------------------------------------------------------
    def _raw_query(self, server, domain):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        return response.decode(errors="ignore")

    # --------------------------------------------------------
    #   REFERRAL FOLLOW-THROUGH — ADDED
    #   Verisign often replies with a refer: line pointing
    #   to the registrar's WHOIS server for full details.
    #   We follow that referral automatically.
    # --------------------------------------------------------
    def _follow_referral(self, raw_text):
        match = re.search(r'refer:\s*(\S+)', raw_text, re.IGNORECASE)
        if match:
            referral_server = match.group(1).strip()
            try:
                return self._raw_query(referral_server, self.domain)
            except Exception:
                pass
        return None

    # --------------------------------------------------------
    #   PARSE KEY FIELDS — ADDED
    #   Extracts structured data from raw WHOIS text
    #   Returns clean dict instead of just raw blob
    # --------------------------------------------------------
    def _parse(self, raw_text):
        def extract(patterns, text):
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            return "N/A"

        def extract_all(pattern, text):
            return list(set(re.findall(pattern, text, re.IGNORECASE)))

        parsed = {
            'registrar':      extract([
                                r'Registrar:\s*(.+)',
                                r'registrar:\s*(.+)'
                              ], raw_text),

            'creation_date':  extract([
                                r'Creation Date:\s*(.+)',
                                r'created:\s*(.+)',
                                r'Registered on:\s*(.+)',
                                r'domain_dateregistered:\s*(.+)'
                              ], raw_text),

            'expiry_date':    extract([
                                r'Registry Expiry Date:\s*(.+)',
                                r'Expir\w+ Date:\s*(.+)',
                                r'paid-till:\s*(.+)',
                                r'domain_datexpires:\s*(.+)'
                              ], raw_text),

            'updated_date':   extract([
                                r'Updated Date:\s*(.+)',
                                r'last-update:\s*(.+)',
                                r'last_updated:\s*(.+)'
                              ], raw_text),

            'registrant':     extract([
                                r'Registrant Organization:\s*(.+)',
                                r'Registrant Name:\s*(.+)',
                                r'org:\s*(.+)'
                              ], raw_text),

            'registrant_country': extract([
                                r'Registrant Country:\s*(.+)',
                                r'country:\s*(.+)'
                              ], raw_text),

            'name_servers':   extract_all(
                                r'Name Server:\s*(\S+)', raw_text
                              ),

            'status':         extract_all(
                                r'Domain Status:\s*(\S+)', raw_text
                              ),

            'dnssec':         extract([
                                r'DNSSEC:\s*(.+)'
                              ], raw_text),
        }

        return parsed

    # --------------------------------------------------------
    #   LOOKUP — MAIN METHOD
    #   Preserved method signature and return contract
    # --------------------------------------------------------
    def lookup(self):
        try:
            server = self._get_whois_server()

            # Query primary WHOIS server
            raw = self._raw_query(server, self.domain)

            # Follow referral if present (e.g. Verisign → registrar)
            referral_raw = self._follow_referral(raw)
            full_raw = referral_raw if referral_raw else raw

            # Parse structured fields
            parsed = self._parse(full_raw)

            return {
                'domain':   self.domain,
                'server':   server,
                'parsed':   parsed,
                'raw_data': full_raw[:1000] + "..."  # Preview preserved
            }

        except Exception as e:
            return {
                'error':       str(e),
                'solution':    "Firewall or WHOIS blocked. Try a VPN.",
                'alternative': f"https://who.is/whois/{self.domain}"
            }