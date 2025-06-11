import requests
from colorama import Fore, Style
import re
import json

def clean_subdomains(subdomains):
    cleaned = set()
    for sub in subdomains:
        # Split multi-line entries and clean each
        for line in sub.split('\n'):
            line = line.strip().lower()
            if line and '\\' not in line and ' ' not in line:
                cleaned.add(line)
    return sorted(cleaned)

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
    
    def find(self):
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=10
            )
            raw_subdomains = {cert['name_value'] for cert in response.json()}
            return clean_subdomains(raw_subdomains)
        except Exception as e:
            return {'error': str(e)}