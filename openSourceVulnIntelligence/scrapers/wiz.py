"""
Wiz vulnerability database scraper.
"""
import requests
import re
import warnings
from bs4 import BeautifulSoup
from typing import Dict, Any, Optional
from .base import BaseScraper
from .registry import register_scraper

# Disable SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


@register_scraper
class WizScraper(BaseScraper):
    """Scraper for Wiz vulnerability database."""
    
    def get_name(self) -> str:
        return "wiz"
    
    def get_priority(self) -> int:
        return 5  # Curated source
    
    def scrape(self, cve_id: str) -> Dict[str, Any]:
        """Scrape Wiz vulnerability database."""
        url = f"https://www.wiz.io/vulnerability-database/cve/{cve_id.lower()}"
        response = requests.get(url, timeout=15, verify=False)
        response.raise_for_status()
        data = response.text
        # soup = BeautifulSoup(data, 'html.parser')
        text = data
        
        return {
            'cve_id': cve_id,
            'cwe': None,
            'cvss': self._extract_cvss(text),
            'epss': self._extract_epss(text),
            'lifecycle': self._extract_lifecycle(text, cve_id),
            'date_published': None,
            'description': self._extract_description(text),
            'affected': {},
            'urls': None,
            'exploit': None
        }
    
    def _extract_cvss(self, text: str) -> Optional[float]:
        try:
            regex = r"CNA Score.*?>([0-9]+\.?[0-9]+)"
            matches = re.findall(regex, text, re.IGNORECASE)
            scores = [float(s) for s in matches if 0.0 <= float(s) <= 10.0]
            return max(scores) if scores else None
        except Exception:
            return None
    
    def _extract_epss(self, text: str) -> Optional[float]:
        try:
            regex = r"Exploitation Probability Percentile \(EPSS\).*?>([0-9]+\.?[0-9]+)"
            matches = re.findall(regex, text, re.IGNORECASE)
            scores = [float(s) for s in matches if 0.0 <= float(s) <= 100.0]
            return max(scores) if scores else None
        except Exception:
            return None
    
    def _extract_lifecycle(self, text: str, cve_id: str) -> Optional[str]:
        lifecycle = "Exploitation Unknown"
        
        disclosure_regex = r".{10}NVD.{10}"
        poc_regex = r"Has Public Exploit.*?(Yes|No)"
        cisa_regex = r"Has CISA KEV Exploit.*?(Yes|No)"
        
        disclosure = re.findall(disclosure_regex, text)
        if len(disclosure) > 0:
            lifecycle = "Disclosure"
            poc = re.findall(poc_regex, text)
            if len(poc) > 0 and poc[0] == "Yes":
                lifecycle = "Exploitation available"
                cisa = re.findall(cisa_regex, text)
                if len(cisa) > 0 and cisa[0] == "Yes":
                    lifecycle = "Added to CISA KEV"
        
        return lifecycle if lifecycle != "Exploitation Unknown" else None

    def _extract_description(self, text: str) -> Optional[str]:
        soup = BeautifulSoup(text, 'html.parser')
        for a in soup.findAll('a'):
            a.replaceWith(f"{a.text} - {a['href']}")
        p = soup.find('p')
        return p.text.strip('<p>').strip('</p>') if p else None       
        try:
            return desc1[1].strip('<p>')[1].strip('</p>')[0]
        except IndexError:
            return None