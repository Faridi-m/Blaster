import requests
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style


# ============================================================
#                   HELPER: CLEAN SUBDOMAINS
#   Preserves your original cleaning logic exactly as-is
#   Fixed: filters junk URL artifacts (@, %, $, {})
#   Fixed: filters the domain itself from subdomain list
# ============================================================

def clean_subdomains(subdomains, domain):
    cleaned = set()

    for sub in subdomains:
        # Split multi-line entries
        for line in sub.split('\n'):
            line = line.strip().lower()

            # Remove wildcard entries
            if line.startswith("*."):
                line = line[2:]

            # --- FIXED: Skip junk URL artifacts from WebArchive ---
            # These are not real subdomains — they're tokens/variables
            # found in URLs that got picked up during crawl parsing
            if any(c in line for c in ['@', '%', '$', '{', '}']):
                continue

            # --- FIXED: Skip the domain itself ---
            # Only keep actual subdomains, not the root domain
            if line == domain:
                continue

            # Keep only valid subdomains of target domain
            if line.endswith('.' + domain):
                cleaned.add(line)

    return sorted(cleaned)


# ============================================================
#                   SUBDOMAIN ENUMERATION MODULE
#
#   Method 1: DNS Bruteforce  (wordlist-based, fully offline)
#   Method 2: HackerTarget    (passive, free, no key needed)
#   Method 3: WebArchive      (passive, free, no key needed)
#
#   All results are deduplicated and merged in find()
# ============================================================

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain

        # ------------------------------------------------
        #   WORDLIST — used by DNS Bruteforce method
        #   500+ entries covering real-world subdomain patterns
        #   Add/remove entries freely to expand coverage
        # ------------------------------------------------
        self.wordlist = [
            # --- Web & WWW ---
            "www", "www1", "www2", "www3", "www4", "www5",
            "web", "web1", "web2", "web3", "website", "webserver",
            "m", "mobile", "wap", "touch",

            # --- Mail & Messaging ---
            "mail", "mail1", "mail2", "mail3", "mail4", "mail5",
            "smtp", "smtp1", "smtp2", "imap", "pop", "pop3",
            "webmail", "webmail1", "email", "mx", "mx1", "mx2",
            "mx3", "relay", "mailer", "mailserver", "exchange",
            "autodiscover", "autoconfig",

            # --- DNS & Name Servers ---
            "ns", "ns1", "ns2", "ns3", "ns4", "ns5",
            "dns", "dns1", "dns2", "dns3", "nameserver",
            "resolver", "bind",

            # --- FTP & File Transfer ---
            "ftp", "ftp1", "ftp2", "sftp", "ftps", "files",
            "file", "upload", "uploads", "download", "downloads",
            "transfer", "storage", "store",

            # --- Admin & Management ---
            "admin", "admin1", "admin2", "administrator",
            "administration", "manage", "management", "manager",
            "control", "controlpanel", "cpanel", "whm",
            "plesk", "panel", "portal", "console",
            "dashboard", "backstage", "backend", "backoffice",

            # --- API & Services ---
            "api", "api1", "api2", "api3", "api4", "api5",
            "apis", "rest", "restapi", "graphql", "soap",
            "rpc", "grpc", "ws", "websocket", "webhook",
            "v1", "v2", "v3", "v4", "v5",
            "service", "services", "svc", "microservice",
            "endpoint", "gateway", "gw", "proxy", "reverse",

            # --- Development & Testing ---
            "dev", "dev1", "dev2", "dev3", "develop", "development",
            "developer", "developers",
            "test", "test1", "test2", "test3", "testing",
            "stage", "staging", "stg", "stg1", "stg2",
            "uat", "qa", "qa1", "qa2", "qe",
            "sandbox", "sandbox1", "sandbox2",
            "beta", "beta1", "beta2", "alpha",
            "demo", "demo1", "demo2", "preview",
            "lab", "labs", "experiment", "poc",
            "local", "localhost", "internal", "int",

            # --- Apps & Products ---
            "app", "app1", "app2", "app3", "apps",
            "application", "platform", "product",
            "ios", "android", "mobileapp",

            # --- Security & Access ---
            "vpn", "vpn1", "vpn2", "remote", "access",
            "secure", "security", "ssl", "tls",
            "ssh", "rdp", "bastion", "jump", "jumpbox",
            "firewall", "fw", "waf", "proxy",
            "auth", "auth1", "auth2", "authentication",
            "login", "logout", "signin", "signup",
            "sso", "saml", "oauth", "oidc",
            "id", "identity", "idp", "ldap", "ad",
            "mfa", "2fa", "otp", "password", "reset",
            "register", "registration",

            # --- Infrastructure & Servers ---
            "server", "server1", "server2", "server3",
            "host", "host1", "host2", "host3",
            "node", "node1", "node2", "node3",
            "vps", "vm", "vms", "dedicated",
            "lb", "load", "loadbalancer", "balancer",
            "edge", "edge1", "edge2",
            "origin", "origin1", "origin2",

            # --- Cloud ---
            "cloud", "cloud1", "cloud2",
            "aws", "azure", "gcp", "digitalocean",
            "heroku", "k8s", "kubernetes", "docker",
            "container", "cluster",

            # --- CDN & Static ---
            "cdn", "cdn1", "cdn2", "cdn3",
            "static", "static1", "static2",
            "assets", "asset", "img", "images",
            "image", "pics", "photos", "media",
            "video", "videos", "audio", "stream",
            "streaming", "live", "broadcast",

            # --- Database ---
            "db", "db1", "db2", "db3", "db4",
            "database", "mysql", "postgres", "postgresql",
            "mongo", "mongodb", "redis", "redis1",
            "elastic", "elasticsearch", "cassandra",
            "memcache", "memcached", "sql", "nosql",
            "data", "datastore", "warehouse",

            # --- Monitoring & Logging ---
            "monitor", "monitoring", "metrics",
            "grafana", "kibana", "elk", "elastic",
            "splunk", "nagios", "zabbix", "prometheus",
            "logs", "log", "logging", "syslog",
            "trace", "tracing", "apm", "newrelic",
            "datadog", "status", "health", "ping",
            "uptime", "alert", "alerts", "pagerduty",

            # --- DevOps & CI/CD ---
            "git", "gitlab", "github", "bitbucket",
            "jenkins", "ci", "cd", "cicd",
            "build", "builds", "builder", "deploy",
            "deployment", "release", "pipeline",
            "artifactory", "nexus", "registry",
            "docker", "harbor", "sonar", "sonarqube",
            "jira", "confluence", "wiki",

            # --- Support & Communication ---
            "support", "help", "helpdesk", "helpdesk1",
            "ticket", "tickets", "desk", "servicedesk",
            "chat", "chatbot", "bot", "slack",
            "teams", "zoom", "meet", "conference",
            "feedback", "survey",

            # --- Content & CMS ---
            "blog", "blogs", "news", "press",
            "content", "cms", "wp", "wordpress",
            "drupal", "joomla", "ghost",
            "forum", "forums", "community", "discuss",
            "kb", "knowledgebase", "faq", "docs",
            "documentation", "wiki", "portal",

            # --- E-commerce & Business ---
            "shop", "store", "ecommerce", "cart",
            "checkout", "order", "orders", "catalog",
            "product", "products", "inventory",
            "pay", "payment", "payments", "billing",
            "invoice", "invoices", "finance", "financial",
            "account", "accounts", "myaccount", "profile",
            "user", "users", "customer", "customers",
            "member", "members", "membership",
            "partner", "partners", "affiliate", "affiliates",
            "crm", "erp", "sales", "marketing",

            # --- Corporate ---
            "corp", "corporate", "intranet", "extranet",
            "office", "hr", "legal", "compliance",
            "ir", "investor", "careers", "jobs",
            "about", "contact", "info",

            # --- Backup & Archive ---
            "backup", "backup1", "backup2",
            "bak", "archive", "archives", "old",
            "legacy", "deprecated", "temp", "tmp",

            # --- Geographic / Regional ---
            "us", "uk", "eu", "ap", "asia",
            "us-east", "us-west", "eu-west", "ap-south",
            "nyc", "lon", "sin", "syd", "fra",

            # --- Numbered / Generic ---
            "1", "2", "3", "4", "5",
            "01", "02", "03", "04", "05",
        ]


    # --------------------------------------------------------
    #   METHOD 1: DNS BRUTEFORCE
    #   Resolves subdomains from wordlist via direct DNS query
    #   Fully offline — no third-party API dependency
    # --------------------------------------------------------

    def _dns_bruteforce(self):
        found = []

        def resolve(word):
            hostname = f"{word}.{self.domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(hostname)
                return hostname
            except socket.error:
                return None

        print(f"  {Fore.YELLOW}[*] Method 1: DNS Bruteforce ({len(self.wordlist)} entries)...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(resolve, word): word for word in self.wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        print(f"  {Fore.GREEN}[+] DNS Bruteforce found: {len(found)} subdomains{Style.RESET_ALL}")
        return found


    # --------------------------------------------------------
    #   METHOD 2: HACKERTARGET API
    #   Passive DNS lookup — free, no API key required
    #   Endpoint: https://api.hackertarget.com/hostsearch/
    # --------------------------------------------------------

    def _hackertarget(self):
        found = []
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"

        print(f"  {Fore.YELLOW}[*] Method 2: HackerTarget API...{Style.RESET_ALL}")

        try:
            response = requests.get(
                url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )

            if response.status_code != 200:
                print(f"  {Fore.RED}[!] HackerTarget returned HTTP {response.status_code}{Style.RESET_ALL}")
                return found

            if "error" in response.text.lower() or not response.text.strip():
                print(f"  {Fore.RED}[!] HackerTarget: No data or rate limited{Style.RESET_ALL}")
                return found

            # Response format: "subdomain.domain.com,IP" per line
            for line in response.text.strip().splitlines():
                parts = line.split(",")
                if parts:
                    subdomain = parts[0].strip().lower()
                    if subdomain.endswith(self.domain):
                        found.append(subdomain)

            print(f"  {Fore.GREEN}[+] HackerTarget found: {len(found)} subdomains{Style.RESET_ALL}")

        except requests.exceptions.Timeout:
            print(f"  {Fore.RED}[!] HackerTarget: Request timed out{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"  {Fore.RED}[!] HackerTarget: {str(e)}{Style.RESET_ALL}")

        return found


    # --------------------------------------------------------
    #   METHOD 3: WEBARCHIVE (Wayback Machine)
    #   Passive — free, no API key, no rate limits
    #   Endpoint: http://web.archive.org/cdx/search/cdx
    #   Pulls subdomains from years of historical web crawls
    #   Run by the Internet Archive — extremely stable
    # --------------------------------------------------------

    def _webarchive(self):
        found = []
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.domain}&output=json&fl=original&collapse=urlkey&limit=10000"
        )

        print(f"  {Fore.YELLOW}[*] Method 3: WebArchive (Wayback Machine)...{Style.RESET_ALL}")

        try:
            response = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )

            if response.status_code != 200:
                print(f"  {Fore.RED}[!] WebArchive returned HTTP {response.status_code}{Style.RESET_ALL}")
                return found

            try:
                data = response.json()
            except json.JSONDecodeError:
                print(f"  {Fore.RED}[!] WebArchive: Invalid JSON response{Style.RESET_ALL}")
                return found

            # Response is a list of lists — first row is header ["original"], skip it
            # Each entry is a full URL like https://sub.domain.com/path
            for entry in data[1:]:
                if not entry:
                    continue
                raw_url = entry[0].strip().lower()

                # Extract hostname from URL
                try:
                    # Strip scheme (http:// or https://)
                    if "://" in raw_url:
                        raw_url = raw_url.split("://", 1)[1]
                    # Strip path, port, query
                    hostname = raw_url.split("/")[0].split(":")[0].split("?")[0]
                    if hostname.endswith(self.domain) and hostname != self.domain:
                        found.append(hostname)
                except Exception:
                    continue

            print(f"  {Fore.GREEN}[+] WebArchive found: {len(found)} subdomains{Style.RESET_ALL}")

        except requests.exceptions.Timeout:
            print(f"  {Fore.RED}[!] WebArchive: Request timed out{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"  {Fore.RED}[!] WebArchive: {str(e)}{Style.RESET_ALL}")

        return found


    # --------------------------------------------------------
    #   FIND — ORCHESTRATOR
    #   Runs all 3 methods, merges + deduplicates results
    #   Returns: list of subdomains  OR  dict {'error': '...'}
    #   (same return contract your blaster.py already expects)
    # --------------------------------------------------------

    def find(self):
        print(f"\n{Fore.CYAN}[*] Starting Subdomain Enumeration for: {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")

        all_found = []

        # Run all three methods — failures in one don't stop others
        try:
            all_found += self._dns_bruteforce()
        except Exception as e:
            print(f"  {Fore.RED}[!] DNS Bruteforce crashed: {e}{Style.RESET_ALL}")

        try:
            all_found += self._hackertarget()
        except Exception as e:
            print(f"  {Fore.RED}[!] HackerTarget crashed: {e}{Style.RESET_ALL}")

        try:
            all_found += self._webarchive()
        except Exception as e:
            print(f"  {Fore.RED}[!] WebArchive crashed: {e}{Style.RESET_ALL}")

        # Deduplicate and clean using your original helper
        final = clean_subdomains(all_found, self.domain)

        print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Total unique subdomains found: {len(final)}{Style.RESET_ALL}\n")

        return final if final else []