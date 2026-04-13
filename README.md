# Blaster — Domain Recon Made Brutal

> **Developed by Usman Faridi**
> A powerful domain reconnaissance tool built for speed, clarity, and brutal simplicity.

---

## 🚀 Features

### Phase 1 — Foundation
- **DNS Lookup** — A, MX, TXT, NS, AAAA, CNAME, SOA, CAA records + TTL values + DNSSEC detection
- **WHOIS Lookup** — Raw socket query with TLD-aware server routing (50+ TLDs supported)
- **Subdomain Enumeration** — Three-method approach: DNS Bruteforce (500+ wordlist) + HackerTarget API + WebArchive
- **Live Subdomain Checker** — HTTP/HTTPS probe each subdomain, shows status code, IP, title, redirects
- **Port Scanning** — 65+ ports, threaded, nmap-style output with service names and version info
- **ASN Lookup** — Autonomous System Number, organization, and country for discovered IPs

### Phase 2 — Active Recon
- **SSL/TLS Analysis** — Certificate details, expiry warning, self-signed detection, SANs, cipher suite, TLS version
- **HTTP Headers Audit** — Security headers check, grade (A–F), cookie security flags, info disclosure
- **Technology Fingerprinting** — Web server, framework, CMS, CDN, WAF, JavaScript frameworks

### Phase 3 — Threat Intelligence
- **DNSBL Check** — IP against Spamhaus, SpamCop, SORBS, Barracuda, UCEPROTECT (no API key needed)
- **ThreatFox IOC Check** — Domain + IP against abuse.ch malware/botnet database (no API key needed)
- **Shodan InternetDB** — Passive open ports, CVEs, tags, hostnames (no API key needed)

### Phase 4 — Reporting
- **JSON Report** — Structured machine-readable output
- **HTML Report** — Dark-themed styled report, opens in any browser
- **TXT Report** — Clean plain text, universal

---

## 📦 Installation

```bash
git clone https://github.com/Faridi-m/blaster.git
cd blaster
python3 -m venv venv
source venv/bin/activate       # Linux/Mac
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

---

## ⚙️ Requirements

```
requests
colorama
dnspython
urllib3
```

---

## 🧠 Usage

```bash
python blaster.py <domain> -h, --help
```

### Available Flags

| Flag | Description |
|------|-------------|
| `--dns` | DNS lookup (A, MX, TXT, NS, AAAA, CNAME, SOA, CAA, DNSSEC) |
| `--whois` | WHOIS lookup with parsed fields |
| `--subdomains` | Subdomain enumeration (3 methods) |
| `--live` | Check which subdomains are live (use with `--subdomains`) |
| `--ports` | Port scan with service detection and banner grabbing |
| `--ssl` | SSL/TLS certificate analysis |
| `--headers` | HTTP security headers audit |
| `--tech` | Technology fingerprinting |
| `--threat` | Threat intelligence (DNSBL + ThreatFox + Shodan) |
| `--full` | Run all modules at once |
| `--output` | Save report to file (`.json`, `.html`, `.txt`) |
| `-v`, `--verbose` | Enable verbose output |

---

## 📖 Examples

**Run a specific module:**
```bash
python blaster.py example.com --dns
python blaster.py example.com --ports
python blaster.py example.com --ssl
python blaster.py example.com --threat
```

**Combine modules:**
```bash
python blaster.py example.com --dns --whois --ports -v
python blaster.py example.com --subdomains --live
```

**Full scan:**
```bash
python blaster.py example.com --full
python blaster.py example.com --full -v
```

**Save report:**
```bash
python blaster.py example.com --full --output report.html
python blaster.py example.com --dns --ssl --output report.json
python blaster.py example.com --dns --ports --output report.txt
```

---

## 🖥️ Output Example

```
[*] Starting Subdomain Enumeration for: example.com
──────────────────────────────────────────────────
  [*] Method 1: DNS Bruteforce (477 entries)...
  [+] DNS Bruteforce found: 1 subdomains
  [*] Method 2: HackerTarget API...
  [+] HackerTarget found: 2 subdomains
──────────────────────────────────────────────────
[✓] Total unique subdomains found: 1

[+] Live Subdomains:
  SUBDOMAIN                                     STATUS   IP               TITLE
  www.example.com                               200      172.66.147.243   Example Domain
    ↳ https://www.example.com/

──────────────────────────────────────────────────
[+] DNS Records:
──────────────────────────────────────────────────
A Records: (TTL: 298s)
  • 104.20.23.154
  • 172.66.147.243
NS Records: (TTL: 86400s)
  • elliott.ns.cloudflare.com.
  • hera.ns.cloudflare.com.
DNSSEC: ✘ Not signed (vulnerable to spoofing)

──────────────────────────────────────────────────────────────────────
[+] Open Ports:
──────────────────────────────────────────────────────────────────────
  PORT       STATE    SERVICE                VERSION/INFO
  ──────────────────────────────────────────────────────────────────
  80/tcp     open     HTTP                   HTTP/1.1 200 OK | cloudflare
  443/tcp    open     HTTPS                  HTTP/1.1 200 OK | cloudflare
  8080/tcp   open     HTTP-Alt
  8443/tcp   open     HTTPS-Alt

──────────────────────────────────────────────────
[+] SSL/TLS Analysis:
──────────────────────────────────────────────────
  Subject CN    : example.com
  Issuer CN     : Cloudflare TLS Issuing ECC CA 1
  Valid To      : 2026-07-01  [✔ 79 days remaining]
  TLS Version   : TLSv1.3
  Cipher Suite  : TLS_AES_256_GCM_SHA384 (256 bits)
  SANs (2 found):
    • example.com
    • *.example.com

──────────────────────────────────────────────────
[+] HTTP Headers Audit:
──────────────────────────────────────────────────
  URL           : https://example.com
  Status        : 200
  Security Grade: F
  [✘] Missing Security Headers:
    • [HIGH] Strict-Transport-Security
    • [HIGH] Content-Security-Policy
    • [HIGH] X-Frame-Options

──────────────────────────────────────────────────
[+] Technology Fingerprint:
──────────────────────────────────────────────────
  Web Server    : Cloudflare (cloudflare)
  CDN           : Cloudflare
  WAF           : Cloudflare WAF

──────────────────────────────────────────────────
[+] Threat Intelligence:
──────────────────────────────────────────────────
  Domain        : example.com
  Resolved IP   : 104.20.23.154

  [ DNSBL Blacklist Check ]
  [✔] Not listed on any blacklist
  [✔] Clean on: Spamhaus ZEN, SpamCop, UCEPROTECT Level 1

  [ ThreatFox IOC Check ]
  [✔] No IOC matches found

  [ Shodan InternetDB ]
  Open Ports    : 80, 443, 8080, 8443
  [✔] No CVEs recorded by Shodan
  Tags          : cdn
```

---

## 🌐 Supported TLDs

Blaster works on **any domain and TLD** — `.com`, `.org`, `.net`, `.io`, `.pk`, `.gov`, `.edu`, `.co.uk`, `.de`, `.fr` and hundreds more. All modules are TLD-agnostic except WHOIS which has explicit routing for 50+ TLDs with automatic fallback for the rest.

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
Always obtain proper authorization before scanning any domain or system you do not own.
Unauthorized use is strictly prohibited and may be illegal.

---

## ✨ Credits

Built with ❤️ by Usman Faridi