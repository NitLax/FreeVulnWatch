"""
Vulmon vulnerability database scraper.
"""
import requests
import re
from typing import Dict, Any, Optional, List
from bs4 import BeautifulSoup
from .base import BaseScraper
from .registry import register_scraper
from ..utils import unescape

@register_scraper
class VulmonScraper(BaseScraper):
    """Scraper for Vulmon."""
    
    def get_name(self) -> str:
        return "vulmon"
    
    def get_priority(self) -> int:
        return 5  # Curated source
    
    def scrape(self, cve_id: str) -> Dict[str, Any]:
        """Scrape Vulmon."""
        url = f"https://vulmon.com/vulnerabilitydetails?qid={cve_id}"
        
        # Add headers to avoid bot detection
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            response.raise_for_status()
            
            # Check if we got a valid response
            if not response.text or len(response.text) < 100:
                print(f"[vulmon] Warning: Empty or very short response for {cve_id}")
                return {'cve_id': cve_id}
            
            return self._parse_html(response.text, cve_id)
        except requests.exceptions.RequestException as e:
            print(f"[vulmon] Error scraping {cve_id}: {e}")
            return {'cve_id': cve_id}
    
    def _parse_html(self, html_content: str, cve_id: str) -> Dict[str, Any]:
        """Parse Vulmon HTML content."""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        return {
            'cve_id': cve_id,
            'cwe': None, # Vulmon doesn't always provide a specific CWE prominently in the main section
            'cvss': self._extract_cvss(soup),
            'epss': self._extract_epss(soup),
            'lifecycle': self._extract_lifecycle(soup),
            'date_published': self._extract_date_published(soup),
            'description': self._extract_description(soup),
            'affected': self._extract_affected(soup),
            'urls': self._extract_urls(soup),
            'exploit': self._extract_exploit(soup)
        }
    
    def _extract_cvss(self, soup: BeautifulSoup) -> Optional[float]:
        # CVSS v3 is prominently displayed in a red statistic box
        stat = soup.find('div', class_='statistic red')
        if stat:
            value = stat.find('div', class_='value')
            if value:
                try:
                    return float(value.get_text().strip())
                except ValueError:
                    pass
        return None
    
    def _extract_epss(self, soup: BeautifulSoup) -> Optional[float]:
        # EPSS is in a span like: <span style="...">EPSS: 0.00064</span>
        # Using a more robust approach: finding text within a div
        text_content = soup.get_text()
        match = re.search(r'EPSS:\s*([\d\.]+)', text_content)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None
    
    def _extract_lifecycle(self, soup: BeautifulSoup) -> Optional[str]:
        # Check for KEV
        kev_span = soup.find('span', string=re.compile(r'KEV:'))
        if kev_span and "Not Included" not in kev_span.get_text():
            return "Added to CISA KEV"
        
        # Check for exploits
        if self._extract_exploit(soup):
            return "Exploitation available"
        
        return "Disclosure"
    
    def _extract_date_published(self, soup: BeautifulSoup) -> Optional[str]:
        # Published: 07/06/2025
        meta = soup.find('div', class_='meta')
        if meta:
            match = re.search(r'Published:\s*(\d{2}/\d{2}/\d{4})', meta.get_text())
            if match:
                # Convert to YYYY-MM-DD format if possible
                parts = match.group(1).split('/')
                if len(parts) == 3:
                    return f"{parts[2]}-{parts[1]}-{parts[0]}T00:00:00Z"
        return None
    
    def _extract_description(self, soup: BeautifulSoup) -> Optional[str]:
        desc_p = soup.find('p', class_='jsdescription1')
        if desc_p:
            return desc_p.get_text().strip()
        return None
    
    def _extract_affected(self, soup: BeautifulSoup) -> Optional[Dict[str, Any]]:
        res = {}
        # Find the table within the specific segment for Vulnerable Products
        table = soup.find('table', class_='ui very small very compact very basic table')
        if table:
            rows = table.find_all('tr')[1:] # Skip header
            for row in rows:
                cols = row.find_all('td')
                if cols:
                    product_p = cols[0].find('p')
                    if product_p:
                        product_text = product_p.get_text().strip()
                        # Simple split for vendor/product if there are two words
                        parts = product_text.split(' ', 1)
                        if len(parts) == 2:
                            vendor, product = parts
                        else:
                            vendor, product = "Unknown", product_text
                        
                        vendor = vendor.strip()
                        product = product.strip()
                        
                        item = {
                            'product': product,
                            'affected_versions': [],
                            'fixed_versions': []
                        }
                        
                        if vendor in res:
                            res[vendor].append(item)
                        else:
                            res[vendor] = [item]
        return res if res else None
    
    def _extract_urls(self, soup: BeautifulSoup) -> List[str]:
        urls = []
        # Find References by heading
        ref_header = soup.find('h2', string='References')
        if ref_header:
            segment = ref_header.find_parent('div', class_='segment')
            if segment:
                links = segment.find_all('a', href=True)
                for link in links:
                    href = link.get('href', '').strip()
                    if href and href not in urls:
                        urls.append(href)
        return urls
    
    def _extract_exploit(self, soup: BeautifulSoup) -> List[str]:
        exploits = []
        # Check Github Repositories segment
        github_header = soup.find('h2', string='Github Repositories')
        if github_header:
            segment = github_header.find_parent('div', class_='segment')
            if segment:
                links = segment.find_all('a', href=True)
                for link in links:
                    href = link.get('href', '').strip()
                    if "github.com" in href and href not in exploits:
                        exploits.append(href)
        
        # Check Mailing Lists for exploit details
        mail_header = soup.find('h2', string='Mailing Lists')
        if mail_header:
            segment = mail_header.find_parent('div', class_='segment')
            if segment:
                links = segment.find_all('a', href=True)
                for link in links:
                    href = link.get('href', '').strip()
                    if "exploitdetails" in href:
                         # Normalize local links
                        if href.startswith('/'):
                            href = "https://vulmon.com" + href
                        if href not in exploits:
                            exploits.append(href)
                            
        return exploits
