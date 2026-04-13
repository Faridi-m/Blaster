import requests
import re
import urllib3
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
#              TECHNOLOGY FINGERPRINTING MODULE
#
#   Detects from HTTP headers + HTML body (lightweight GET):
#     - Web server (Apache, Nginx, IIS, Cloudflare etc.)
#     - Programming language / framework
#       (PHP, Python, Django, Rails, ASP.NET etc.)
#     - CMS (WordPress, Drupal, Joomla, Shopify etc.)
#     - CDN / Hosting provider
#       (Cloudflare, CloudFront, Fastly, Akamai etc.)
#     - WAF / Security layer
#       (Cloudflare WAF, AWS WAF, Sucuri, Imperva etc.)
#     - JavaScript frameworks
#       (React, Vue, Angular, Next.js, jQuery etc.)
#
#   Two-pass detection:
#     Pass 1 — Headers only  (fast, always done)
#     Pass 2 — HTML body     (lightweight, reveals CMS/JS)
#
#   No new packages — uses requests (already installed)
# ============================================================

class TechDetector:
    def __init__(self, domain):
        self.domain  = domain
        self.url     = f"https://{domain}"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }

        # ----------------------------------------------------
        #   WEB SERVER SIGNATURES
        #   Matched against Server header
        # ----------------------------------------------------
        self.server_signatures = {
            'apache':      'Apache',
            'nginx':       'Nginx',
            'iis':         'Microsoft IIS',
            'cloudflare':  'Cloudflare',
            'cloudfront':  'AWS CloudFront',
            'litespeed':   'LiteSpeed',
            'openresty':   'OpenResty (Nginx+Lua)',
            'caddy':       'Caddy',
            'gunicorn':    'Gunicorn (Python)',
            'uvicorn':     'Uvicorn (Python)',
            'jetty':       'Jetty (Java)',
            'tomcat':      'Apache Tomcat (Java)',
            'kestrel':     'Kestrel (.NET)',
            'cowboy':      'Cowboy (Erlang)',
            'werkzeug':    'Werkzeug (Python/Flask)',
            'vercel':      'Vercel',
            'awselb':      'AWS Elastic Load Balancer',
            'akamai':      'Akamai',
        }

        # ----------------------------------------------------
        #   FRAMEWORK / LANGUAGE SIGNATURES
        #   Matched against multiple headers
        # ----------------------------------------------------
        self.framework_signatures = {
            # Headers → framework
            'x-powered-by': {
                'php':            'PHP',
                'asp.net':        'ASP.NET',
                'express':        'Express.js (Node.js)',
                'next.js':        'Next.js (Node.js)',
                'ruby':           'Ruby',
                'python':         'Python',
                'java':           'Java',
                'perl':           'Perl',
                'mono':           'Mono (.NET)',
            },
            'x-aspnet-version': {
                '':               'ASP.NET'  # presence alone confirms it
            },
            'x-aspnetmvc-version': {
                '':               'ASP.NET MVC'
            },
        }

        # ----------------------------------------------------
        #   CDN SIGNATURES
        #   Matched against response headers
        #   X-Cache now parsed for value hints, not generic
        # ----------------------------------------------------
        self.cdn_signatures = [
            ('CF-Ray',              'Cloudflare'),
            ('X-Served-By',         'Fastly'),
            ('X-Amz-Cf-Id',         'AWS CloudFront'),
            ('X-Amz-Cf-Pop',        'AWS CloudFront'),
            ('X-Azure-Ref',         'Azure CDN'),
            ('X-MSEdge-Ref',        'Azure CDN'),
            ('X-Akamai-Transformed','Akamai'),
            ('Akamai-Cache-Status', 'Akamai'),
            ('X-Fastly-Request-Id', 'Fastly'),
            ('X-Varnish',           'Varnish Cache'),
            ('X-Sucuri-ID',         'Sucuri CDN'),
            ('X-Proxy-Cache',       'Proxy Cache'),
            ('Via',                 None),   # parsed separately
            ('X-Cache',             None),   # parsed separately — value checked
        ]

        # ----------------------------------------------------
        #   WAF SIGNATURES
        #   Matched against headers and response body
        # ----------------------------------------------------
        self.waf_signatures = [
            ('CF-Ray',                  'Cloudflare WAF'),
            ('X-Sucuri-ID',             'Sucuri WAF'),
            ('X-Sucuri-Cache',          'Sucuri WAF'),
            ('X-Denied-Reason',         'Imperva WAF'),
            ('X-Iinfo',                 'Imperva Incapsula'),
            ('X-CDN',                   'CDN WAF'),
            ('X-Fw-Hash',               'Fortinet WAF'),
            ('X-AWS-WAF',               'AWS WAF'),
            ('X-Barracuda-Connect',     'Barracuda WAF'),
        ]

        # ----------------------------------------------------
        #   CMS SIGNATURES
        #   Matched against HTML body and headers/cookies
        # ----------------------------------------------------
        self.cms_signatures = {
            # Body patterns — tightened to avoid false positives
            # Using specific unique strings per CMS
            'body': {
                'wp-content/themes':      'WordPress',
                'wp-content/plugins':     'WordPress',
                'wp-includes/js':         'WordPress',
                '/sites/default/files':   'Drupal',
                'drupal.settings':        'Drupal',
                'joomla!':                'Joomla',
                'option=com_':            'Joomla',
                'ghost-url':              'Ghost CMS',
                'shopify.com/s/files':    'Shopify',
                'cdn.shopify.com':        'Shopify',
                'bigcommerce.com':        'BigCommerce',
                'squarespace.com':        'Squarespace',
                'static.squarespace.com': 'Squarespace',
                'wixsite.com':            'Wix',
                'static.wixstatic.com':   'Wix',
                'data-wf-page':           'Webflow',
                'data-wf-site':           'Webflow',
                'typo3conf':              'TYPO3',
                'prestashop':             'PrestaShop',
                'mage/cookies':           'Magento',
                'magento':                'Magento',
                'next-head-count':        'Next.js',
                '__nuxt':                 'Nuxt.js',
                'gatsby-focus-wrapper':   'Gatsby',
            },
            # Header patterns
            'headers': {
                'x-drupal-cache':         'Drupal',
                'x-drupal-dynamic-cache': 'Drupal',
                'x-wordpress-cache':      'WordPress',
                'x-generator':            None,  # parsed separately
                'x-shopify-stage':        'Shopify',
            },
            # Cookie name patterns
            'cookies': {
                'wordpress_':             'WordPress',
                'wp-settings-':           'WordPress',
                'drupal':                 'Drupal',
                'joomla':                 'Joomla',
                'shopify':                'Shopify',
            }
        }

        # ----------------------------------------------------
        #   JAVASCRIPT FRAMEWORK SIGNATURES
        #   Matched against HTML body
        # ----------------------------------------------------
        self.js_signatures = {
            # React — specific attributes/globals
            '__reactfiber':           'React',
            '__reactprop':            'React',
            'data-reactroot':         'React',
            'react.production.min':   'React',
            'react-dom':              'React',

            # Vue — specific globals/patterns
            '__vue_app__':            'Vue.js',
            'vue.runtime':            'Vue.js',
            'vue.min.js':             'Vue.js',
            'createapp':              'Vue.js',

            # Angular — specific attributes
            'ng-version':             'Angular',
            'ng-reflect':             'Angular',
            'angular.min.js':         'Angular',

            # jQuery — specific file patterns
            'jquery.min.js':          'jQuery',
            'jquery-':                'jQuery',
            '/jquery/':               'jQuery',

            # Backbone
            'backbone.min.js':        'Backbone.js',
            'backbone-min.js':        'Backbone.js',

            # Ember — specific patterns
            'ember.min.js':           'Ember.js',
            'ember-source':           'Ember.js',
            'emberjs.com':            'Ember.js',

            # Svelte
            '__svelte':               'Svelte',
            'svelte/internal':        'Svelte',

            # Next.js
            '__next':                 'Next.js',
            'next/dist':              'Next.js',
            '_next/static':           'Next.js',

            # Nuxt
            '__nuxt':                 'Nuxt.js',
            '_nuxt/':                 'Nuxt.js',

            # Gatsby
            'gatsby-focus-wrapper':   'Gatsby',
            '___gatsby':              'Gatsby',

            # Alpine.js
            'x-data=':               'Alpine.js',
            'alpinejs':               'Alpine.js',

            # HTMX
            'htmx.org':               'HTMX',
            'hx-get':                 'HTMX',

            # Turbolinks / Hotwire
            'turbolinks':             'Turbolinks (Rails)',
            'turbo-frame':            'Hotwire Turbo (Rails)',

            # Livewire
            'livewire:init':          'Laravel Livewire',
            'wire:id':                'Laravel Livewire',
        }


    # --------------------------------------------------------
    #   PASS 1: DETECT FROM HEADERS
    # --------------------------------------------------------
    def _detect_from_headers(self, resp_headers):
        detected = {
            'server':     None,
            'framework':  None,
            'cdn':        [],
            'waf':        [],
        }

        headers_lower = {k.lower(): v for k, v in resp_headers.items()}

        # --- Web Server ---
        server_val = headers_lower.get('server', '').lower()
        for sig, name in self.server_signatures.items():
            if sig in server_val:
                detected['server'] = f"{name} ({headers_lower.get('server', '')})"
                break
        if not detected['server'] and server_val:
            # Server header exists but didn't match any known signature
            # Could be intentional obfuscation (e.g. github.com, ECS, ECAcc)
            # Show raw value but label it clearly
            raw = headers_lower.get('server', '')
            detected['server'] = f"{raw} (unrecognized)"

        # --- Framework / Language ---
        for header, patterns in self.framework_signatures.items():
            if header in headers_lower:
                val = headers_lower[header].lower()
                for sig, name in patterns.items():
                    if sig == '' or sig in val:
                        detected['framework'] = f"{name} ({headers_lower[header]})"
                        break

        # --- CDN ---
        found_cdns = set()
        for header, cdn_name in self.cdn_signatures:
            if header.lower() in headers_lower:
                val = headers_lower[header.lower()].lower()
                if cdn_name:
                    found_cdns.add(cdn_name)
                elif header.lower() == 'via':
                    # Parse Via value for hints
                    found_cdns.add(f"Via proxy: {headers_lower['via']}")
                elif header.lower() == 'x-cache':
                    # Parse X-Cache value to identify CDN
                    if 'cloudfront' in val:
                        found_cdns.add('AWS CloudFront')
                    elif 'varnish' in val:
                        found_cdns.add('Varnish Cache')
                    elif 'hit' in val or 'miss' in val:
                        found_cdns.add('CDN Cache')
        detected['cdn'] = list(found_cdns)

        # --- WAF ---
        found_wafs = set()
        for header, waf_name in self.waf_signatures:
            if header.lower() in headers_lower:
                found_wafs.add(waf_name)
        detected['waf'] = list(found_wafs)

        return detected


    # --------------------------------------------------------
    #   PASS 2: DETECT FROM HTML BODY
    # --------------------------------------------------------
    def _detect_from_body(self, body, resp_headers):
        detected = {
            'cms':        None,
            'js_frameworks': [],
        }

        body_lower = body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in resp_headers.items()}

        # --- CMS from body ---
        for sig, name in self.cms_signatures['body'].items():
            if re.search(sig, body_lower):
                detected['cms'] = name
                break

        # --- CMS from headers ---
        if not detected['cms']:
            for header, name in self.cms_signatures['headers'].items():
                if header in headers_lower:
                    if name:
                        detected['cms'] = name
                    elif header == 'x-generator':
                        detected['cms'] = f"Generator: {resp_headers.get('X-Generator', '')}"
                    break

        # --- CMS from cookies ---
        if not detected['cms']:
            cookie_header = headers_lower.get('set-cookie', '')
            for sig, name in self.cms_signatures['cookies'].items():
                if sig in cookie_header:
                    detected['cms'] = name
                    break

        # --- JavaScript Frameworks ---
        found_js = set()
        for sig, name in self.js_signatures.items():
            if sig in body_lower:
                found_js.add(name)
        detected['js_frameworks'] = list(found_js)

        return detected


    # --------------------------------------------------------
    #   BLOCK DETECTION
    #   Checks status code and returns meaningful message
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
    #   DETECT — MAIN METHOD
    # --------------------------------------------------------
    def detect(self):
        try:
            # GET — need body for CMS/JS detection
            response = requests.get(
                self.url,
                headers=self.headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )

            status_code  = response.status_code
            resp_headers = response.headers
            body         = response.text

            # --- Check if blocked before processing ---
            block_reason = self._check_if_blocked(status_code)
            if block_reason:
                return {
                    'success': False,
                    'blocked': True,
                    'status':  status_code,
                    'error':   f"HTTP {status_code} — {block_reason}",
                    'tip':     'Try again later or use a VPN'
                }

            # Pass 1 — headers
            header_data = self._detect_from_headers(resp_headers)

            # Pass 2 — body
            body_data = self._detect_from_body(body, resp_headers)

            return {
                'success':       True,
                'url':           self.url,
                'status':        status_code,
                'server':        header_data['server'],
                'framework':     header_data['framework'],
                'cdn':           header_data['cdn'],
                'waf':           header_data['waf'],
                'cms':           body_data['cms'],
                'js_frameworks': body_data['js_frameworks'],
            }

        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timed out'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': f'Could not connect to {self.domain}'}
        except Exception as e:
            return {'success': False, 'error': f'Unexpected error: {str(e)}'}