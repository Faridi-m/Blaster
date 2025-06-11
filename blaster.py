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
from blaster.whois import WhoisLookup
from blaster.subdomains import SubdomainFinder
from blaster.nmap import PortScanner
import re

# Initialize colors
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--ports", action="store_true", help="Perform port scanning")
    
    args = parser.parse_args()
    
    if not any([args.dns, args.whois, args.subdomains, args.ports]):  # ← Added args.ports
        print(f"{Fore.RED}[!] Please specify at least one module (--dns, --whois, --subdomains, or --ports){Style.RESET_ALL}")
    results = {'dns': None, 'whois': None, 'subdomains': None}  # Initialize results dictionary
    
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
            for subdomain in results['subdomains']:
                print(f"  {Fore.CYAN}• {subdomain}{Style.RESET_ALL}")
            
    except Exception as e:  # Add proper exception handling
        print(f"{Fore.RED}[!] Error occurred: {e}{Style.RESET_ALL}")
        
        
    if 'subdomains' in results:
            if isinstance(results['subdomains'], list):
                print(f"{Fore.YELLOW}Subdomains found:{Style.RESET_ALL}")
                for entry in results['subdomains']:
                    for line in str(entry).split('\n'):
                        line = line.strip()
                        if line:
                            if is_ip_address(line):
                                print(f"  {Fore.MAGENTA}• {line}{Style.RESET_ALL}")
                            else:
                                print(f"  {Fore.CYAN}• {line}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Error:{Style.RESET_ALL} {results['subdomains']}")
        
    # Only process DNS/IP data if --dns was used AND data exists
    # Handle DNS results (only if --dns was used)
    if 'dns' in results:
        print(f"\n{Fore.YELLOW}DNS Records:{Style.RESET_ALL}")
    dns_data = results['dns']
    
    if dns_data:  # ✅ Only proceed if not None
        try:
            for record_type in ['A', 'MX', 'TXT', 'NS']:
                if record_type in dns_data and dns_data[record_type]:
                    print(f"{Fore.CYAN}{record_type} records:{Style.RESET_ALL}")
                    for value in dns_data[record_type]:
                        print(f"  {Fore.GREEN}• {value}{Style.RESET_ALL}")

            if 'ips' in dns_data and dns_data['ips']:
                print(f"\n{Fore.YELLOW}Extra IPs found from subdomains:{Style.RESET_ALL}")
                for ip in dns_data['ips']:
                    print(f"  {Fore.MAGENTA}• {ip}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error displaying DNS results: {str(e)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] No DNS data returned.{Style.RESET_ALL}")

            # PERFORM PORT SCAN IF REQUESTED
    if args.ports:
        if args.verbose:
            print(f"{Fore.YELLOW}[*] Scanning ports on {args.domain}{Style.RESET_ALL}")
        try:
            scanner = PortScanner(args.domain)
            ports_info = scanner.scan()
            print(f"\n{Fore.GREEN}[+] Open Ports:{Style.RESET_ALL}")
            for item in ports_info:
                print(f"  {Fore.CYAN}• Port {item['port']}{Style.RESET_ALL}")
                if item['banner']:
                    print(f"    {Fore.LIGHTBLACK_EX}Banner: {item['banner']}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during port scan: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()