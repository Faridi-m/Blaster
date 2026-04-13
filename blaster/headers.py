import requests
import urllib3
from colorama import Fore, Style

# Suppress SSL warnings — we want to connect even to bad certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
#                  HTTP HEADERS AUDIT MODULE
#
#   Checks:
#     - Security headers (present/missing with severity)
#         HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
#         Referrer-Policy, Permissions-Policy, X-XSS-Protection
#     - Information disclosure headers
#         Server, X-Powered-By, X-AspNet-Version
#     - Cookie security flags
#         Secure, HttpOnly, SameSite
#     - Overall security grade (A / B / C / F)
#
#   No new packages — uses requests (already in requirements)
# ============================================================

class HeadersAudit:
    def __init__(self, domain):
        self.domain = domain
        self.url    = f"https://{domain}"

        # ----------------------------------------------------
        #   SECURITY HEADERS
        #   Each entry: header_name → (severity, description)
        #   severity: HIGH = serious risk if missing
        #             MEDIUM = recommended but not critical
        #             LOW = best practice
        # ----------------------------------------------------
        self.security_headers = {
            'Strict-Transport-Security': (
                'HIGH',
                'HSTS missing — browsers may connect over HTTP'
            ),
            'Content-Security-Policy': (
                'HIGH',
                'CSP missing — XSS and injection attacks possible'
            ),
            'X-Frame-Options': (
                'HIGH',
                'Clickjacking protection missing'
            ),
            'X-Content-Type-Options': (
                'MEDIUM',
                'MIME sniffing attacks possible'
            ),
            'Referrer-Policy': (
                'MEDIUM',
                'Referrer data may leak to third parties'
            ),
            'Permissions-Policy': (
                'LOW',
                'Browser feature access not restricted'
            ),
            'X-XSS-Protection': (
                'LOW',
                'Legacy XSS filter not configured (older browsers)'
            ),
        }

        # ----------------------------------------------------
        #   INFORMATION DISCLOSURE HEADERS
        #   These reveal tech stack — useful for attackers
        # ----------------------------------------------------
        self.info_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Generator',
            'X-Drupal-Cache',
            'X-WordPress-Cache',
        ]


    # --------------------------------------------------------
    #   FETCH HEADERS
    #   Sends GET request — captures full response headers
    #   including all cookies set by the server
    #   GET used instead of HEAD because HEAD responses
    #   often omit Set-Cookie headers (e.g. GitHub only
    #   sets _octo, logged_in on full GET requests)
    # --------------------------------------------------------
    def _fetch_headers(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }

        try:
            response = requests.get(
                self.url,
                headers=headers,
                timeout=10,
                verify=False,           # Connect even if cert is bad
                allow_redirects=True    # Follow redirects
            )
            return response

        except requests.exceptions.SSLError:
            # Try plain HTTP if HTTPS fails
            self.url = f"http://{self.domain}"
            return requests.get(
                self.url,
                headers=headers,
                timeout=10,
                allow_redirects=True
            )


    # --------------------------------------------------------
    #   CHECK SECURITY HEADERS
    #   Returns lists of present and missing headers
    # --------------------------------------------------------
    def _check_security_headers(self, response_headers):
        present = {}
        missing = {}

        for header, (severity, desc) in self.security_headers.items():
            if header.lower() in [h.lower() for h in response_headers]:
                # Find actual header value (case-insensitive)
                value = next(
                    v for k, v in response_headers.items()
                    if k.lower() == header.lower()
                )
                present[header] = value
            else:
                missing[header] = (severity, desc)

        return present, missing


    # --------------------------------------------------------
    #   CHECK INFORMATION DISCLOSURE
    #   Returns headers that reveal too much about the stack
    # --------------------------------------------------------
    def _check_info_disclosure(self, response_headers):
        disclosed = {}

        for header in self.info_headers:
            if header.lower() in [h.lower() for h in response_headers]:
                value = next(
                    v for k, v in response_headers.items()
                    if k.lower() == header.lower()
                )
                disclosed[header] = value

        return disclosed


    # --------------------------------------------------------
    #   CHECK COOKIE SECURITY
    #   Inspects Set-Cookie headers for security flags
    #   Fixed: uses requests cookie jar instead of manual
    #   comma splitting which broke on date values like
    #   "expires=Mon, 05 Apr 2027" — commas in dates caused
    #   date fragments to be treated as new cookie entries
    # --------------------------------------------------------
    def _check_cookies(self, response_headers):
        cookies = []

        # Pull all Set-Cookie values from raw headers
        # requests stores them as a list in response.raw.headers
        raw_cookie_header = response_headers.get('Set-Cookie', '')
        if not raw_cookie_header:
            return cookies

        # Split on cookie boundaries properly —
        # cookies are separated by newlines in raw headers
        # not commas (commas appear inside cookie values/dates)
        # Use semicolon to split attributes within each cookie
        raw_lines = raw_cookie_header.split('\n') if '\n' in raw_cookie_header else [raw_cookie_header]

        for raw in raw_lines:
            raw = raw.strip()
            if not raw:
                continue

            # Split cookie into parts by semicolon
            parts = [p.strip() for p in raw.split(';')]
            if not parts:
                continue

            # First part is always name=value
            first = parts[0]
            if '=' in first:
                name = first.split('=')[0].strip()
            else:
                name = first.strip()

            # Skip empty names or names that look like date fragments
            # Date fragments start with digits or weekday abbreviations
            if not name:
                continue
            weekdays = ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun')
            if name.lower()[:3] in weekdays or name[0].isdigit():
                continue

            # Check flags from all parts (case-insensitive)
            parts_lower = [p.lower() for p in parts]
            flags = {
                'name':     name,
                'secure':   any(p == 'secure' for p in parts_lower),
                'httponly': any(p == 'httponly' for p in parts_lower),
                'samesite': any(p.startswith('samesite') for p in parts_lower),
            }
            cookies.append(flags)

        return cookies


    # --------------------------------------------------------
    #   CALCULATE GRADE
    #   Based on missing HIGH/MEDIUM security headers
    #   A = all present, F = multiple HIGH missing
    # --------------------------------------------------------
    def _calculate_grade(self, missing):
        high_missing   = sum(1 for s, _ in missing.values() if s == 'HIGH')
        medium_missing = sum(1 for s, _ in missing.values() if s == 'MEDIUM')

        if high_missing == 0 and medium_missing == 0:
            return 'A', Fore.GREEN
        elif high_missing == 0 and medium_missing <= 1:
            return 'B', Fore.CYAN
        elif high_missing == 1:
            return 'C', Fore.YELLOW
        elif high_missing == 2:
            return 'D', Fore.YELLOW
        else:
            return 'F', Fore.RED


    # --------------------------------------------------------
    #   BLOCK DETECTION
    #   Checks status code and returns meaningful message
    #   instead of silently processing a blocked response
    # --------------------------------------------------------
    def _check_if_blocked(self, status_code):
        block_codes = {
            403: 'Forbidden — WAF or server is blocking requests',
            429: 'Rate Limited — too many requests from your IP, wait and retry',
            503: 'Service Unavailable — WAF challenge page or server overloaded',
            407: 'Proxy Authentication Required — target is behind a proxy',
            999: 'Blocked — custom block code (common on LinkedIn)',
        }
        if status_code in block_codes:
            return block_codes[status_code]
        return None

    # --------------------------------------------------------
    #   AUDIT — MAIN METHOD
    #   Returns structured dict or error dict
    # --------------------------------------------------------
    def audit(self):
        try:
            response     = self._fetch_headers()
            resp_headers = response.headers
            status_code  = response.status_code

            # --- Check if blocked before processing ---
            block_reason = self._check_if_blocked(status_code)
            if block_reason:
                return {
                    'success':  False,
                    'blocked':  True,
                    'status':   status_code,
                    'error':    f"HTTP {status_code} — {block_reason}",
                    'tip':      'Try again later or use a VPN'
                }

            present, missing   = self._check_security_headers(resp_headers)
            disclosed          = self._check_info_disclosure(resp_headers)
            cookies            = self._check_cookies(resp_headers)
            grade, grade_color = self._calculate_grade(missing)

            return {
                'success':     True,
                'url':         self.url,
                'status':      status_code,
                'present':     present,
                'missing':     missing,
                'disclosed':   disclosed,
                'cookies':     cookies,
                'grade':       grade,
                'grade_color': grade_color,
            }

        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error':   'Request timed out'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error':   f'Could not connect to {self.domain}'
            }
        except Exception as e:
            return {
                'success': False,
                'error':   f'Unexpected error: {str(e)}'
            }