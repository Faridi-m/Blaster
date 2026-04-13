import argparse
import sys
from colorama import init, Fore, Style
init()  # Must be before any color usage

BANNER = f"""
{Fore.LIGHTMAGENTA_EX}  ____  _           _            {Style.RESET_ALL}
{Fore.MAGENTA} | __ )| | __ _ ___| |_ ___ _ __ {Style.RESET_ALL}
{Fore.LIGHTMAGENTA_EX} |  _ \\| |/ _` / __| __/ _ \\ '__|{Style.RESET_ALL}
{Fore.MAGENTA} | |_) | | (_| \\__ \\ ||  __/ |   {Style.RESET_ALL}
{Fore.LIGHTMAGENTA_EX} |____/|_|\\__,_|___/\\__\\___|_|   {Style.RESET_ALL}

{Fore.LIGHTCYAN_EX}      Domain Recon Made Brutal{Style.RESET_ALL}
{Fore.LIGHTBLUE_EX}        Developed by Usman Faridi{Style.RESET_ALL}
"""

def show_banner():
    print(BANNER)

from blaster.dns import DNSLookup
from blaster.asn import ASNLookup
from blaster.whois import WhoisLookup
from blaster.subdomains import SubdomainFinder
from blaster.nmap import PortScanner
from blaster.ssl_tls import SSLAnalyzer
from blaster.headers import HeadersAudit
from blaster.tech_detect import TechDetector
from blaster.threat_intel import ThreatIntel
from blaster.report import Reporter
from blaster.live import LiveSubdomainChecker
import re

init(autoreset=True)

def is_ip_address(text):
    """Check if text is an IP address"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.match(ip_pattern, text) is not None

def main():
    show_banner()
    parser = argparse.ArgumentParser(description=f"{Fore.CYAN}Blaster - Domain Recon Tool{Style.RESET_ALL}")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--dns", action="store_true", help="Perform DNS lookup")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--subdomains", action="store_true", help="Find subdomains")
    parser.add_argument("--live",       action="store_true", help="Check live subdomains (use after --subdomains)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--ports", action="store_true", help="Perform port scanning")
    parser.add_argument("--ssl",     action="store_true", help="Perform SSL/TLS analysis")
    parser.add_argument("--headers", action="store_true", help="Perform HTTP headers audit")
    parser.add_argument("--tech",    action="store_true", help="Perform technology fingerprinting")
    parser.add_argument("--threat",  action="store_true", help="Perform threat intelligence lookup")
    parser.add_argument("--full",    action="store_true", help="Run all modules")
    parser.add_argument("--output",  type=str,            help="Save report to file (.json, .html, .txt)")

    args = parser.parse_args()

    # --full enables all modules at once
    if args.full:
        args.dns        = True
        args.whois      = True
        args.subdomains = True
        args.live       = True
        args.ports      = True
        args.ssl        = True
        args.headers    = True
        args.tech       = True
        args.threat     = True

    if not any([args.dns, args.whois, args.subdomains, args.live, args.ports, args.ssl, args.headers, args.tech, args.threat]):
        print(f"{Fore.RED}[!] Please specify at least one module (--dns, --whois, --subdomains, or --ports){Style.RESET_ALL}")

    results = {
        'dns':        None,
        'whois':      None,
        'subdomains': None,
        'live':       None,
        'ports':      None,
        'ssl':        None,
        'headers':    None,
        'tech':       None,
        'threat':     None,
    }

    try:
        if args.dns:
            if args.verbose:
                print(f"{Fore.YELLOW}[*] Running DNS lookup for {args.domain}{Style.RESET_ALL}")
            results['dns'] = DNSLookup(args.domain).lookup()

        if args.whois:
            if args.verbose:
                print(f"{Fore.YELLOW}[*] Running WHOIS lookup for {args.domain}{Style.RESET_ALL}")
            results['whois'] = WhoisLookup(args.domain).lookup()

        if args.subdomains:
            if args.verbose:
                print(f"{Fore.YELLOW}[*] Searching subdomains for {args.domain}{Style.RESET_ALL}")
            results['subdomains'] = SubdomainFinder(args.domain).find()
            print(f"\n{Fore.GREEN}[+] Subdomains found:{Style.RESET_ALL}")
            if isinstance(results['subdomains'], list):
                for subdomain in results['subdomains']:
                    print(f"  {Fore.CYAN}• {subdomain}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] {results['subdomains']}{Style.RESET_ALL}")

        # ================================================================
        #   LIVE SUBDOMAIN CHECK
        #   Command: python blaster.py example.com --subdomains --live
        #   Runs automatically after --subdomains if --live is set
        # ================================================================
        if args.live:
            subs = results.get('subdomains', [])
            if not subs or not isinstance(subs, list):
                print(f"{Fore.RED}[!] No subdomains to check — run --subdomains first{Style.RESET_ALL}")
            else:
                if args.verbose:
                    print(f"{Fore.YELLOW}[*] Checking live subdomains...{Style.RESET_ALL}")
                live_results = LiveSubdomainChecker(subs).check()
                results['live'] = live_results

                print(f"\n{Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Live Subdomains:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}")

                if not live_results:
                    print(f"  {Fore.RED}No live subdomains found{Style.RESET_ALL}")
                else:
                    # nmap-style table header
                    print(f"  {Fore.CYAN}{'SUBDOMAIN':<45} {'STATUS':<8} {'IP':<16} {'TITLE'}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}{'─' * 66}{Style.RESET_ALL}")

                    for item in live_results:
                        subdomain = item['subdomain']
                        status    = item.get('status') or '—'
                        ip        = item.get('ip') or '—'
                        title     = item.get('title') or '—'
                        redirect  = item.get('redirect')

                        # Color by status code
                        if str(status).startswith('2'):
                            status_color = Fore.GREEN
                        elif str(status).startswith('3'):
                            status_color = Fore.YELLOW
                        elif str(status).startswith('4'):
                            status_color = Fore.RED
                        else:
                            status_color = Fore.WHITE

                        print(
                            f"  {Fore.CYAN}{subdomain:<45}{Style.RESET_ALL}"
                            f" {status_color}{str(status):<8}{Style.RESET_ALL}"
                            f" {Fore.MAGENTA}{ip:<16}{Style.RESET_ALL}"
                            f" {Fore.LIGHTBLACK_EX}{title}{Style.RESET_ALL}"
                        )

                        # Show redirect on next line if present — truncated for display
                        if redirect and redirect != f"https://{subdomain}" and redirect != f"http://{subdomain}":
                            display_redirect = redirect[:80] + '...' if len(redirect) > 80 else redirect
                            print(f"    {Fore.YELLOW}↳ {display_redirect}{Style.RESET_ALL}")

                print(f"  {Fore.YELLOW}{'─' * 68}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error occurred: {e}{Style.RESET_ALL}")

    # ================================================================
    #   DNS DISPLAY — UPDATED
    #   Preserved: A, MX, TXT, NS, extra IPs, ASN lookup
    #   Added display for: AAAA, CNAME, SOA, CAA, DNSSEC, TTL values
    # ================================================================
    if 'dns' in results:
        print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] DNS Records:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
    dns_data = results['dns']

    if dns_data:
        try:
            # --- PRESERVED: A, MX, TXT, NS records ---
            for record_type in ['A', 'MX', 'TXT', 'NS']:
                if record_type in dns_data and dns_data[record_type]:
                    ttl     = dns_data.get('TTL', {}).get(record_type, '')
                    ttl_str = f" {Fore.LIGHTBLACK_EX}(TTL: {ttl}s){Style.RESET_ALL}" if ttl else ""
                    print(f"{Fore.CYAN}{record_type} Records:{Style.RESET_ALL}{ttl_str}")
                    for value in dns_data[record_type]:
                        print(f"  {Fore.GREEN}• {value}{Style.RESET_ALL}")

            # --- ADDED: AAAA records (IPv6) ---
            if dns_data.get('AAAA') and dns_data['AAAA'] != ["No AAAA records found"]:
                ttl     = dns_data.get('TTL', {}).get('AAAA', '')
                ttl_str = f" {Fore.LIGHTBLACK_EX}(TTL: {ttl}s){Style.RESET_ALL}" if ttl else ""
                print(f"{Fore.CYAN}AAAA Records (IPv6):{Style.RESET_ALL}{ttl_str}")
                for value in dns_data['AAAA']:
                    print(f"  {Fore.GREEN}• {value}{Style.RESET_ALL}")

            # --- ADDED: CNAME records ---
            if dns_data.get('CNAME') and dns_data['CNAME'] != ["No CNAME records found"]:
                print(f"{Fore.CYAN}CNAME Records:{Style.RESET_ALL}")
                for value in dns_data['CNAME']:
                    print(f"  {Fore.GREEN}• {value}{Style.RESET_ALL}")

            # --- ADDED: SOA record ---
            if dns_data.get('SOA'):
                print(f"{Fore.CYAN}SOA Record:{Style.RESET_ALL}")
                for soa in dns_data['SOA']:
                    print(f"  {Fore.GREEN}• Primary NS : {soa['mname']}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}• Admin Email: {soa['rname']}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}• Serial     : {soa['serial']}{Style.RESET_ALL}")

            # --- ADDED: CAA records ---
            if dns_data.get('CAA'):
                print(f"{Fore.CYAN}CAA Records:{Style.RESET_ALL}")
                for value in dns_data['CAA']:
                    print(f"  {Fore.GREEN}• {value}{Style.RESET_ALL}")

            # --- ADDED: DNSSEC status ---
            dnssec = dns_data.get('DNSSEC', False)
            if dnssec:
                print(f"{Fore.CYAN}DNSSEC:{Style.RESET_ALL} {Fore.GREEN}✔ Signed{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}DNSSEC:{Style.RESET_ALL} {Fore.RED}✘ Not signed (vulnerable to spoofing){Style.RESET_ALL}")

            # --- PRESERVED: Extra IPs + ASN lookup ---
            if 'ips' in dns_data and dns_data['ips']:
                print(f"\n{Fore.YELLOW}Extra IPs found from subdomains:{Style.RESET_ALL}")
                for ip in dns_data['ips']:
                    print(f"  {Fore.MAGENTA}• {ip}{Style.RESET_ALL}")
                    asn_info = ASNLookup(ip).lookup()
                    if "error" not in asn_info:
                        print(f"    {Fore.CYAN}ASN:{Style.RESET_ALL} AS{asn_info['asn']}")
                        print(f"    {Fore.CYAN}Org:{Style.RESET_ALL} {asn_info['org']}")
                        print(f"    {Fore.CYAN}Country:{Style.RESET_ALL} {asn_info['country'] or 'Unknown'}")
                    else:
                        print(f"    {Fore.RED}ASN lookup failed{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error displaying DNS results: {str(e)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] No DNS data returned.{Style.RESET_ALL}")

    # ================================================================
    #   WHOIS DISPLAY — UPDATED
    #   Preserved: error handling with solution/alternative
    #   Added display for: parsed fields (registrar, dates,
    #   registrant, name servers, status, DNSSEC)
    # ================================================================
    if args.whois and results.get('whois'):
        whois_data = results['whois']
        print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}WHOIS Results:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")

        if 'error' in whois_data:
            # PRESERVED error structure
            print(f"{Fore.RED}[!] WHOIS Error: {whois_data['error']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] {whois_data.get('solution', '')}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Try: {whois_data.get('alternative', '')}{Style.RESET_ALL}")
        else:
            # ADDED: show parsed fields cleanly
            parsed = whois_data.get('parsed', {})
            server = whois_data.get('server', '')

            print(f"  {Fore.CYAN}WHOIS Server  :{Style.RESET_ALL} {server}")
            print(f"  {Fore.CYAN}Registrar     :{Style.RESET_ALL} {parsed.get('registrar', 'N/A')}")
            print(f"  {Fore.CYAN}Registrant    :{Style.RESET_ALL} {parsed.get('registrant', 'N/A')}")
            print(f"  {Fore.CYAN}Country       :{Style.RESET_ALL} {parsed.get('registrant_country', 'N/A')}")
            print(f"  {Fore.CYAN}Created       :{Style.RESET_ALL} {parsed.get('creation_date', 'N/A')}")
            print(f"  {Fore.CYAN}Expires       :{Style.RESET_ALL} {parsed.get('expiry_date', 'N/A')}")
            print(f"  {Fore.CYAN}Updated       :{Style.RESET_ALL} {parsed.get('updated_date', 'N/A')}")
            print(f"  {Fore.CYAN}DNSSEC        :{Style.RESET_ALL} {parsed.get('dnssec', 'N/A')}")

            if parsed.get('name_servers'):
                print(f"  {Fore.CYAN}Name Servers  :{Style.RESET_ALL}")
                for ns in parsed['name_servers']:
                    print(f"    {Fore.GREEN}• {ns}{Style.RESET_ALL}")

            if parsed.get('status'):
                print(f"  {Fore.CYAN}Status        :{Style.RESET_ALL}")
                for st in parsed['status']:
                    print(f"    {Fore.GREEN}• {st}{Style.RESET_ALL}")

    # ================================================================
    #   PORT SCAN DISPLAY — UPDATED
    #   Preserved: port number, banner display
    #   Added display for: service name, risk warning
    # ================================================================
    if args.ports:
        if args.verbose:
            print(f"{Fore.YELLOW}[*] Scanning ports on {args.domain}{Style.RESET_ALL}")
        try:
            scanner    = PortScanner(args.domain)
            ports_info = scanner.scan()
            results['ports'] = ports_info
            print(f"\n{Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Open Ports:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}")

            if not ports_info:
                print(f"  {Fore.RED}No open ports found{Style.RESET_ALL}")
            else:
                # --- nmap-style table header ---
                print(f"  {Fore.CYAN}{'PORT':<10} {'STATE':<8} {'SERVICE':<22} {'VERSION/INFO'}{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}{'─' * 66}{Style.RESET_ALL}")

                for item in ports_info:
                    port    = f"{item['port']}/tcp"
                    state   = 'open'
                    service = item.get('service', 'unknown')
                    version = item.get('version', '')
                    risk    = item.get('risk', False)

                    # Color code by risk
                    port_color    = Fore.RED    if risk else Fore.CYAN
                    service_color = Fore.RED    if risk else Fore.GREEN
                    version_color = Fore.WHITE

                    # Risk tag appended to version
                    risk_tag = f"  {Fore.RED}[⚠ HIGH RISK]{Style.RESET_ALL}" if risk else ""

                    print(
                        f"  {port_color}{port:<10}{Style.RESET_ALL}"
                        f" {Fore.GREEN}{state:<8}{Style.RESET_ALL}"
                        f" {service_color}{service:<22}{Style.RESET_ALL}"
                        f" {version_color}{version}{Style.RESET_ALL}"
                        f"{risk_tag}"
                    )

            print(f"  {Fore.YELLOW}{'─' * 66}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error during port scan: {e}{Style.RESET_ALL}")

    # ================================================================
    #   SSL/TLS DISPLAY
    #   Command: python blaster.py example.com --ssl
    # ================================================================
    if args.ssl:
        if args.verbose:
            print(f"{Fore.YELLOW}[*] Analyzing SSL/TLS for {args.domain}{Style.RESET_ALL}")
        try:
            ssl_result = SSLAnalyzer(args.domain).analyze()
            results['ssl'] = ssl_result
            print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] SSL/TLS Analysis:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")

            if not ssl_result.get('success'):
                print(f"  {Fore.RED}[!] {ssl_result.get('error')}{Style.RESET_ALL}")
            else:
                d = ssl_result['data']

                # --- Certificate Identity ---
                print(f"  {Fore.CYAN}Subject CN    :{Style.RESET_ALL} {d['subject_cn']}")
                print(f"  {Fore.CYAN}Subject Org   :{Style.RESET_ALL} {d['subject_org']}")
                print(f"  {Fore.CYAN}Issuer CN     :{Style.RESET_ALL} {d['issuer_cn']}")
                print(f"  {Fore.CYAN}Issuer Org    :{Style.RESET_ALL} {d['issuer_org']}")
                print(f"  {Fore.CYAN}Serial        :{Style.RESET_ALL} {d['serial']}")

                # --- Validity ---
                print(f"  {Fore.CYAN}Valid From    :{Style.RESET_ALL} {d['valid_from']}")
                print(f"  {Fore.CYAN}Valid To      :{Style.RESET_ALL} {d['valid_to']}", end="")

                if d['is_expired']:
                    print(f"  {Fore.RED}[✘ EXPIRED]{Style.RESET_ALL}")
                elif d['expiry_warn']:
                    print(f"  {Fore.YELLOW}[⚠ EXPIRES IN {d['days_left']} DAYS]{Style.RESET_ALL}")
                elif d['days_left'] is not None:
                    print(f"  {Fore.GREEN}[✔ {d['days_left']} days remaining]{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}[? Expiry date unavailable]{Style.RESET_ALL}")

                # --- Self-Signed Warning ---
                if d['self_signed']:
                    print(f"  {Fore.RED}[⚠ SELF-SIGNED CERTIFICATE — Not trusted by browsers]{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}Self-Signed   :{Style.RESET_ALL} {Fore.GREEN}No{Style.RESET_ALL}")

                # --- TLS Version & Cipher ---
                tls_color = Fore.RED if d['weak_protocol'] else Fore.GREEN
                tls_warn  = " [⚠ WEAK — Deprecated protocol]" if d['weak_protocol'] else ""
                print(f"  {Fore.CYAN}TLS Version   :{Style.RESET_ALL} {tls_color}{d['tls_version']}{tls_warn}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Cipher Suite  :{Style.RESET_ALL} {d['cipher_name']} ({d['cipher_bits']} bits)")

                # --- SANs ---
                if d['sans']:
                    print(f"  {Fore.CYAN}SANs ({len(d['sans'])} found):{Style.RESET_ALL}")
                    for san in d['sans']:
                        print(f"    {Fore.GREEN}• {san}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}SANs          :{Style.RESET_ALL} None found")

        except Exception as e:
            print(f"{Fore.RED}[!] Error during SSL analysis: {e}{Style.RESET_ALL}")

    # ================================================================
    #   HTTP HEADERS AUDIT DISPLAY
    #   Command: python blaster.py example.com --headers
    # ================================================================
    if args.headers:
        if args.verbose:
            print(f"{Fore.YELLOW}[*] Auditing HTTP headers for {args.domain}{Style.RESET_ALL}")
        try:
            audit_result = HeadersAudit(args.domain).audit()
            results['headers'] = audit_result
            print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] HTTP Headers Audit:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")

            if not audit_result.get('success'):
                print(f"  {Fore.RED}[!] {audit_result.get('error')}{Style.RESET_ALL}")
                if audit_result.get('blocked'):
                    print(f"  {Fore.YELLOW}[*] Tip: {audit_result.get('tip')}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}[*] Status Code: {audit_result.get('status')}{Style.RESET_ALL}")
            else:
                # --- Grade ---
                grade       = audit_result['grade']
                grade_color = audit_result['grade_color']
                print(f"  {Fore.CYAN}URL           :{Style.RESET_ALL} {audit_result['url']}")
                print(f"  {Fore.CYAN}Status        :{Style.RESET_ALL} {audit_result['status']}")
                print(f"  {Fore.CYAN}Security Grade:{Style.RESET_ALL} {grade_color}{grade}{Style.RESET_ALL}")

                # --- Present Security Headers ---
                present = audit_result['present']
                if present:
                    print(f"\n  {Fore.GREEN}[✔] Security Headers Present:{Style.RESET_ALL}")
                    for header, value in present.items():
                        # Truncate long values for clean display
                        display_val = value[:80] + '...' if len(value) > 80 else value
                        print(f"    {Fore.GREEN}• {header}{Style.RESET_ALL}")
                        print(f"      {Fore.LIGHTBLACK_EX}{display_val}{Style.RESET_ALL}")

                # --- Missing Security Headers ---
                missing = audit_result['missing']
                if missing:
                    print(f"\n  {Fore.RED}[✘] Missing Security Headers:{Style.RESET_ALL}")
                    for header, (severity, desc) in missing.items():
                        sev_color = (
                            Fore.RED    if severity == 'HIGH'   else
                            Fore.YELLOW if severity == 'MEDIUM' else
                            Fore.CYAN
                        )
                        print(f"    {sev_color}• [{severity}] {header}{Style.RESET_ALL}")
                        print(f"      {Fore.LIGHTBLACK_EX}{desc}{Style.RESET_ALL}")

                # --- Information Disclosure ---
                disclosed = audit_result['disclosed']
                if disclosed:
                    print(f"\n  {Fore.YELLOW}[⚠] Information Disclosure:{Style.RESET_ALL}")
                    for header, value in disclosed.items():
                        print(f"    {Fore.YELLOW}• {header}: {value}{Style.RESET_ALL}")
                else:
                    print(f"\n  {Fore.GREEN}[✔] No sensitive headers disclosed{Style.RESET_ALL}")

                # --- Cookie Security ---
                cookies = audit_result['cookies']
                if cookies:
                    print(f"\n  {Fore.CYAN}[~] Cookie Security:{Style.RESET_ALL}")
                    for cookie in cookies:
                        name     = cookie['name']
                        secure   = f"{Fore.GREEN}Secure✔{Style.RESET_ALL}"   if cookie['secure']   else f"{Fore.RED}Secure✘{Style.RESET_ALL}"
                        httponly = f"{Fore.GREEN}HttpOnly✔{Style.RESET_ALL}" if cookie['httponly'] else f"{Fore.RED}HttpOnly✘{Style.RESET_ALL}"
                        samesite = f"{Fore.GREEN}SameSite✔{Style.RESET_ALL}" if cookie['samesite'] else f"{Fore.RED}SameSite✘{Style.RESET_ALL}"
                        print(f"    {Fore.CYAN}• {name}{Style.RESET_ALL}  {secure}  {httponly}  {samesite}")
                else:
                    print(f"\n  {Fore.LIGHTBLACK_EX}[~] No cookies set{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error during headers audit: {e}{Style.RESET_ALL}")

    # ================================================================
    #   TECHNOLOGY FINGERPRINTING DISPLAY
    #   Command: python blaster.py example.com --tech
    # ================================================================
    if args.tech:
        if args.verbose:
            print(f"{Fore.YELLOW}[*] Fingerprinting technologies for {args.domain}{Style.RESET_ALL}")
        try:
            tech_result = TechDetector(args.domain).detect()
            results['tech'] = tech_result
            print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Technology Fingerprint:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")

            if not tech_result.get('success'):
                print(f"  {Fore.RED}[!] {tech_result.get('error')}{Style.RESET_ALL}")
                if tech_result.get('blocked'):
                    print(f"  {Fore.YELLOW}[*] Tip: {tech_result.get('tip')}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}[*] Status Code: {tech_result.get('status')}{Style.RESET_ALL}")
            else:
                # --- Web Server ---
                server = tech_result.get('server')
                if server:
                    print(f"  {Fore.CYAN}Web Server    :{Style.RESET_ALL} {Fore.GREEN}{server}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}Web Server    :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Not detected{Style.RESET_ALL}")

                # --- Framework / Language ---
                framework = tech_result.get('framework')
                if framework:
                    print(f"  {Fore.CYAN}Framework     :{Style.RESET_ALL} {Fore.GREEN}{framework}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}Framework     :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Not detected{Style.RESET_ALL}")

                # --- CMS ---
                cms = tech_result.get('cms')
                if cms:
                    print(f"  {Fore.CYAN}CMS           :{Style.RESET_ALL} {Fore.GREEN}{cms}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}CMS           :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Not detected{Style.RESET_ALL}")

                # --- CDN ---
                cdns = tech_result.get('cdn', [])
                if cdns:
                    print(f"  {Fore.CYAN}CDN           :{Style.RESET_ALL}")
                    for cdn in cdns:
                        print(f"    {Fore.GREEN}• {cdn}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}CDN           :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Not detected{Style.RESET_ALL}")

                # --- WAF ---
                wafs = tech_result.get('waf', [])
                if wafs:
                    print(f"  {Fore.CYAN}WAF           :{Style.RESET_ALL}")
                    for waf in wafs:
                        print(f"    {Fore.YELLOW}• {waf}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}WAF           :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Not detected{Style.RESET_ALL}")

                # --- JavaScript Frameworks ---
                js_frameworks = tech_result.get('js_frameworks', [])
                if js_frameworks:
                    print(f"  {Fore.CYAN}JS Frameworks :{Style.RESET_ALL}")
                    for js in js_frameworks:
                        print(f"    {Fore.GREEN}• {js}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}JS Frameworks :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Not detected{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error during tech detection: {e}{Style.RESET_ALL}")

    # ================================================================
    #   THREAT INTELLIGENCE DISPLAY
    #   Command: python blaster.py example.com --threat
    # ================================================================
    if args.threat:
        if args.verbose:
            print(f"{Fore.YELLOW}[*] Running threat intelligence for {args.domain}{Style.RESET_ALL}")
        try:
            threat_result = ThreatIntel(args.domain).analyze()
            results['threat'] = threat_result
            print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Threat Intelligence:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")

            if not threat_result.get('success'):
                print(f"  {Fore.RED}[!] {threat_result.get('error')}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.CYAN}Domain        :{Style.RESET_ALL} {threat_result['domain']}")
                print(f"  {Fore.CYAN}Resolved IP   :{Style.RESET_ALL} {threat_result['ip']}")

                # ------------------------------------------------
                #   DNSBL RESULTS
                # ------------------------------------------------
                dnsbl = threat_result.get('dnsbl', {})
                print(f"\n  {Fore.CYAN}[ DNSBL Blacklist Check ]{Style.RESET_ALL}")

                if 'error' in dnsbl:
                    print(f"  {Fore.RED}[!] DNSBL error: {dnsbl['error']}{Style.RESET_ALL}")
                else:
                    listed = dnsbl.get('listed', [])
                    clean  = dnsbl.get('clean', [])

                    if listed:
                        print(f"  {Fore.RED}[✘] Listed on {len(listed)} blacklist(s):{Style.RESET_ALL}")
                        for bl in listed:
                            print(f"    {Fore.RED}• {bl}{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.GREEN}[✔] Not listed on any blacklist{Style.RESET_ALL}")

                    if clean:
                        print(f"  {Fore.GREEN}[✔] Clean on: {', '.join(clean)}{Style.RESET_ALL}")

                # ------------------------------------------------
                #   THREATFOX RESULTS
                # ------------------------------------------------
                threatfox = threat_result.get('threatfox', {})
                print(f"\n  {Fore.CYAN}[ ThreatFox IOC Check ]{Style.RESET_ALL}")

                if 'error' in threatfox:
                    print(f"  {Fore.RED}[!] ThreatFox error: {threatfox['error']}{Style.RESET_ALL}")
                else:
                    domain_hits = threatfox.get('domain_hits', [])
                    ip_hits     = threatfox.get('ip_hits', [])

                    if not domain_hits and not ip_hits:
                        print(f"  {Fore.GREEN}[✔] No IOC matches found{Style.RESET_ALL}")
                    else:
                        if domain_hits:
                            print(f"  {Fore.RED}[✘] Domain flagged — {len(domain_hits)} IOC match(es):{Style.RESET_ALL}")
                            for hit in domain_hits[:3]:  # Show max 3
                                print(f"    {Fore.RED}• Malware     : {hit['malware']}{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}Threat Type : {hit['threat_type']}{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}Confidence  : {hit['confidence']}%{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}First Seen  : {hit['first_seen']}{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}Reporter    : {hit['reporter']}{Style.RESET_ALL}")

                        if ip_hits:
                            print(f"  {Fore.RED}[✘] IP flagged — {len(ip_hits)} IOC match(es):{Style.RESET_ALL}")
                            for hit in ip_hits[:3]:  # Show max 3
                                print(f"    {Fore.RED}• Malware     : {hit['malware']}{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}Threat Type : {hit['threat_type']}{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}Confidence  : {hit['confidence']}%{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}First Seen  : {hit['first_seen']}{Style.RESET_ALL}")
                                print(f"      {Fore.YELLOW}Reporter    : {hit['reporter']}{Style.RESET_ALL}")

                # ------------------------------------------------
                #   SHODAN INTERNETDB RESULTS
                # ------------------------------------------------
                shodan = threat_result.get('shodan', {})
                print(f"\n  {Fore.CYAN}[ Shodan InternetDB ]{Style.RESET_ALL}")

                if 'error' in shodan:
                    print(f"  {Fore.RED}[!] Shodan error: {shodan['error']}{Style.RESET_ALL}")
                elif shodan.get('no_data'):
                    print(f"  {Fore.LIGHTBLACK_EX}[~] No Shodan data for this IP{Style.RESET_ALL}")
                else:
                    # Open ports
                    ports = shodan.get('ports', [])
                    if ports:
                        print(f"  {Fore.CYAN}Open Ports    :{Style.RESET_ALL} {', '.join(str(p) for p in ports)}")
                    else:
                        print(f"  {Fore.LIGHTBLACK_EX}Open Ports    : None recorded{Style.RESET_ALL}")

                    # CVEs — most critical info
                    cves = shodan.get('cves', [])
                    if cves:
                        print(f"  {Fore.RED}[✘] CVEs found ({len(cves)}):{Style.RESET_ALL}")
                        for cve in cves:
                            print(f"    {Fore.RED}• {cve}{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.GREEN}[✔] No CVEs recorded by Shodan{Style.RESET_ALL}")

                    # Tags
                    tags = shodan.get('tags', [])
                    if tags:
                        print(f"  {Fore.YELLOW}Tags          : {', '.join(tags)}{Style.RESET_ALL}")

                    # Hostnames
                    hostnames = shodan.get('hostnames', [])
                    if hostnames:
                        print(f"  {Fore.CYAN}Hostnames     :{Style.RESET_ALL}")
                        for h in hostnames[:5]:  # Show max 5
                            print(f"    {Fore.GREEN}• {h}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error during threat intelligence: {e}{Style.RESET_ALL}")

    # ================================================================
    #   REPORT GENERATION
    #   Triggered by --output flag
    #   Format auto-detected from file extension
    # ================================================================
    if args.output:
        try:
            reporter = Reporter(args.domain, results, args)
            path, fmt = reporter.save(args.output)
            print(f"\n{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[✔] Report saved:{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}File  :{Style.RESET_ALL} {path}")
            print(f"  {Fore.CYAN}Format:{Style.RESET_ALL} {fmt.upper()}")
            print(f"{Fore.YELLOW}{'─' * 50}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving report: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()