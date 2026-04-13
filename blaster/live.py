import socket
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
#                 LIVE SUBDOMAIN CHECKER MODULE
#
#   Takes the subdomain list from SubdomainFinder and
#   checks which ones are actually alive and responding.
#
#   Two-step check per subdomain:
#     Step 1 — DNS resolve  (fast, filters dead ones)
#     Step 2 — HTTP probe   (confirms web service is live)
#
#   Returns for each live subdomain:
#     - subdomain name
#     - resolved IP
#     - HTTP status code
#     - redirect URL (if redirected)
#     - page title (if detectable)
#     - protocol (http or https)
#
#   No new packages — uses requests + socket (already installed)
#   Threaded — all subdomains checked in parallel
# ============================================================

class LiveSubdomainChecker:
    def __init__(self, subdomains, timeout=3):
        self.subdomains = subdomains
        self.timeout    = timeout
        self.session    = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })


    # --------------------------------------------------------
    #   STEP 1: DNS RESOLVE
    #   Quickly filters out subdomains that don't resolve
    #   Much faster than making HTTP requests to dead hosts
    # --------------------------------------------------------
    def _resolve(self, subdomain):
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(subdomain)
            return ip
        except Exception:
            return None


    # --------------------------------------------------------
    #   STEP 2: HTTP PROBE
    #   Tries HTTPS first, falls back to HTTP
    #   Captures status, redirect, title
    # --------------------------------------------------------
    def _probe(self, subdomain, ip):
        result = {
            'subdomain': subdomain,
            'ip':        ip,
            'status':    None,
            'protocol':  None,
            'url':       None,
            'title':     None,
            'redirect':  None,
        }

        # Try HTTPS first, then HTTP
        for protocol in ('https', 'http'):
            url = f"{protocol}://{subdomain}"
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

                result['status']   = response.status_code
                result['protocol'] = protocol
                result['url']      = response.url

                # Detect redirect
                if response.url != url:
                    result['redirect'] = response.url

                # Extract page title from HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    import re
                    title_match = re.search(
                        r'<title[^>]*>([^<]+)</title>',
                        response.text[:2000],
                        re.IGNORECASE
                    )
                    if title_match:
                        result['title'] = title_match.group(1).strip()[:80]

                return result

            except requests.exceptions.SSLError:
                # HTTPS failed — loop will try HTTP next
                continue
            except Exception:
                continue

        # Both protocols failed — not live
        return None


    # --------------------------------------------------------
    #   CHECK SINGLE SUBDOMAIN
    #   Combines DNS resolve + HTTP probe
    # --------------------------------------------------------
    def _check(self, subdomain):
        # Step 1 — DNS resolve
        ip = self._resolve(subdomain)
        if not ip:
            return None

        # Step 2 — HTTP probe
        return self._probe(subdomain, ip)


    # --------------------------------------------------------
    #   CHECK ALL — MAIN METHOD
    #   Runs all checks in parallel, returns live results
    # --------------------------------------------------------
    def check(self):
        live      = []
        total     = len(self.subdomains)
        checked   = 0

        print(f"\n{Fore.CYAN}[*] Checking {total} subdomains for live hosts...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {
                executor.submit(self._check, sub): sub
                for sub in self.subdomains
            }
            for future in as_completed(futures):
                result   = future.result()
                checked += 1

                # Progress counter — updates in place on same line
                print(
                    f"  {Fore.YELLOW}[{checked}/{total}]{Style.RESET_ALL} "
                    f"{Fore.LIGHTBLACK_EX}checking...{Style.RESET_ALL}",
                    end='\r'
                )

                if result:
                    live.append(result)

        # Clear the progress line before printing final result
        print(' ' * 60, end='\r')

        # Sort by subdomain name
        live.sort(key=lambda x: x['subdomain'])

        print(f"{Fore.GREEN}[✓] Live subdomains found: {len(live)} / {total}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")

        return live