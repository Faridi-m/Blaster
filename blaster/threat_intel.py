import socket
import requests
import json
from colorama import Fore, Style

# ============================================================
#                 THREAT INTELLIGENCE MODULE
#
#   Three sources — all free, no API key required:
#
#   Source 1: DNSBL (DNS Blackhole Lists)
#     - Checks IP against Spamhaus, SpamCop, SORBS
#     - Pure DNS queries — no HTTP, no rate limits
#     - Industry standard used by mail servers globally
#
#   Source 2: ThreatFox (abuse.ch)
#     - Checks domain + IP against malware/IOC database
#     - Detects C2 servers, botnets, phishing domains
#     - Run by abuse.ch — trusted security organization
#
#   Source 3: Shodan InternetDB
#     - Passive recon — what Shodan sees on the IP
#     - Open ports, known CVEs, tags, hostnames
#     - No API key needed for basic queries
#
#   Flow:
#     domain → resolve IP → run all 3 checks → return results
#     User inputs domain only, IP resolved automatically
# ============================================================

class ThreatIntel:
    def __init__(self, domain):
        self.domain  = domain
        self.ip      = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })

        # ----------------------------------------------------
        #   DNSBL BLACKLISTS
        #   Format: (blacklist_host, friendly_name)
        #   Query: reversed_ip.blacklist_host
        #   Response: NXDOMAIN = clean, any A record = listed
        # ----------------------------------------------------
        self.dnsbl_lists = [
            ('zen.spamhaus.org',      'Spamhaus ZEN'),
            ('bl.spamcop.net',        'SpamCop'),
            ('dnsbl.sorbs.net',       'SORBS'),
            ('b.barracudacentral.org','Barracuda Reputation'),
            ('dnsbl-1.uceprotect.net','UCEPROTECT Level 1'),
        ]


    # --------------------------------------------------------
    #   RESOLVE DOMAIN TO IP
    #   Done once, reused by all three sources
    # --------------------------------------------------------
    def _resolve_ip(self):
        try:
            self.ip = socket.gethostbyname(self.domain)
            return True
        except socket.gaierror:
            return False


    # --------------------------------------------------------
    #   SOURCE 1: DNSBL CHECK
    #   Reverses IP and queries each blacklist via DNS
    #   Pure DNS — no HTTP requests, no rate limits ever
    # --------------------------------------------------------
    def _check_dnsbl(self):
        results = {
            'listed':  [],   # blacklists that flagged this IP
            'clean':   [],   # blacklists that gave it clean
            'errors':  [],   # blacklists that failed to respond
        }

        # Reverse the IP for DNSBL query format
        # e.g. 1.2.3.4 → 4.3.2.1
        reversed_ip = '.'.join(self.ip.split('.')[::-1])

        for bl_host, bl_name in self.dnsbl_lists:
            query = f"{reversed_ip}.{bl_host}"
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(query)
                # If resolved → IP is LISTED on this blacklist
                results['listed'].append(bl_name)
            except socket.gaierror as e:
                if 'NXDOMAIN' in str(e) or '11001' in str(e) or 'Name or service not known' in str(e):
                    # NXDOMAIN = not listed = clean
                    results['clean'].append(bl_name)
                else:
                    results['errors'].append(bl_name)
            except Exception:
                results['errors'].append(bl_name)

        return results


    # --------------------------------------------------------
    #   SOURCE 2: THREATFOX (abuse.ch)
    #   Checks domain AND IP against IOC database
    #   Free JSON API — no key needed for basic queries
    # --------------------------------------------------------
    def _check_threatfox(self):
        results = {
            'domain_hits': [],
            'ip_hits':     [],
        }

        url = "https://threatfox-api.abuse.ch/api/v1/"

        # --- Check domain ---
        try:
            response = self.session.post(
                url,
                json={"query": "search_ioc", "search_term": self.domain},
                timeout=10
            )
            data = response.json()

            if data.get('query_status') == 'ok':
                for ioc in data.get('data', []):
                    results['domain_hits'].append({
                        'ioc_type':    ioc.get('ioc_type', 'N/A'),
                        'malware':     ioc.get('malware_printable', 'N/A'),
                        'threat_type': ioc.get('threat_type', 'N/A'),
                        'confidence':  ioc.get('confidence_level', 'N/A'),
                        'first_seen':  ioc.get('first_seen', 'N/A'),
                        'last_seen':   ioc.get('last_seen', 'N/A'),
                        'reporter':    ioc.get('reporter', 'N/A'),
                    })
        except Exception:
            pass

        # --- Check IP ---
        try:
            response = self.session.post(
                url,
                json={"query": "search_ioc", "search_term": self.ip},
                timeout=10
            )
            data = response.json()

            if data.get('query_status') == 'ok':
                for ioc in data.get('data', []):
                    results['ip_hits'].append({
                        'ioc_type':    ioc.get('ioc_type', 'N/A'),
                        'malware':     ioc.get('malware_printable', 'N/A'),
                        'threat_type': ioc.get('threat_type', 'N/A'),
                        'confidence':  ioc.get('confidence_level', 'N/A'),
                        'first_seen':  ioc.get('first_seen', 'N/A'),
                        'last_seen':   ioc.get('last_seen', 'N/A'),
                        'reporter':    ioc.get('reporter', 'N/A'),
                    })
        except Exception:
            pass

        return results


    # --------------------------------------------------------
    #   SOURCE 3: SHODAN INTERNETDB
    #   Passive recon — ports, CVEs, tags Shodan has seen
    #   Free endpoint, no key needed
    #   Endpoint: https://internetdb.shodan.io/{ip}
    # --------------------------------------------------------
    def _check_shodan_internetdb(self):
        results = {
            'ports':     [],
            'cves':      [],
            'tags':      [],
            'hostnames': [],
        }

        try:
            response = self.session.get(
                f"https://internetdb.shodan.io/{self.ip}",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                results['ports']     = data.get('ports', [])
                results['cves']      = data.get('vulns', [])
                results['tags']      = data.get('tags', [])
                results['hostnames'] = data.get('hostnames', [])

            elif response.status_code == 404:
                # Shodan has no data for this IP — not necessarily bad
                results['no_data'] = True

        except requests.exceptions.Timeout:
            results['error'] = 'Shodan InternetDB timed out'
        except Exception as e:
            results['error'] = str(e)

        return results


    # --------------------------------------------------------
    #   ANALYZE — MAIN METHOD
    #   Resolves IP, runs all 3 sources, returns full results
    # --------------------------------------------------------
    def analyze(self):
        # Step 1 — Resolve domain to IP
        if not self._resolve_ip():
            return {
                'success': False,
                'error':   f"Could not resolve IP for {self.domain}"
            }

        # Step 2 — Run all three sources
        # Each fails independently — one down doesn't stop others
        dnsbl_results   = {}
        threatfox_results = {}
        shodan_results  = {}

        try:
            dnsbl_results = self._check_dnsbl()
        except Exception as e:
            dnsbl_results = {'error': str(e)}

        try:
            threatfox_results = self._check_threatfox()
        except Exception as e:
            threatfox_results = {'error': str(e)}

        try:
            shodan_results = self._check_shodan_internetdb()
        except Exception as e:
            shodan_results = {'error': str(e)}

        return {
            'success':   True,
            'domain':    self.domain,
            'ip':        self.ip,
            'dnsbl':     dnsbl_results,
            'threatfox': threatfox_results,
            'shodan':    shodan_results,
        }