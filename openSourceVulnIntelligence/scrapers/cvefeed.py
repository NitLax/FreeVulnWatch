"""
CVEFeed scraper implementation for cvefeed.io.
"""
import requests
import re
import urllib3
import warnings
from typing import Dict, Any, Optional, List
from bs4 import BeautifulSoup
from .base import BaseScraper
from .registry import register_scraper

# Suppress insecure request warnings for verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

@register_scraper
class CVEFeedScraper(BaseScraper):
    """
    Scraper for cvefeed.io.
    """
    
    def get_name(self) -> str:
        return "cvefeed"
    
    def get_priority(self) -> int:
        return 5 # Curated source
    
    def scrape(self, cve_id: str) -> Dict[str, Any]:
        """
        Scrape vulnerability data from cvefeed.io.
        """
        url = f"https://cvefeed.io/vuln/detail/{cve_id}"
        try:
            response = requests.get(url, timeout=15, verify=False)
            if response.status_code != 200:
                return {'cve_id': cve_id}
            
            return self._parse_html(response.text, cve_id)
        except Exception as e:
            print(f"[cvefeed] Error scraping {cve_id}: {e}")
            return {'cve_id': cve_id}

    def _parse_html(self, html_content: str, cve_id: str) -> Dict[str, Any]:
        """
        Parse HTML content from cvefeed.io.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        date_published = self._extract_date_published(soup)
        
        return {
            'cve_id': self._extract_cve_id(soup, cve_id),
            'cwe': self._extract_cwe(soup),
            'cvss': self._extract_cvss(soup),
            'epss': None,
            'lifecycle': self._extract_lifecycle(soup, date_published),
            'date_published': date_published,
            'description': self._extract_description(soup),
            'affected': self._extract_affected(soup),
            'urls': self._extract_urls(soup),
            'exploit': self._extract_exploits(soup)
        }

    def _extract_cve_id(self, soup: BeautifulSoup, cve_id: str) -> str:
        """Extract and validate CVE ID."""
        cve_header = soup.find('h5', class_='fs-36')
        if cve_header and 'CVE-' in cve_header.get_text():
            extracted_cve = cve_header.get_text().strip()
            return extracted_cve
        return cve_id

    def _extract_description(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract vulnerability description."""
        desc_header = soup.find('h6', string=re.compile(r'Description', re.I))
        if desc_header:
            desc_card = desc_header.find_parent('div', class_='card')
            if desc_card:
                desc_p = desc_card.find('p', class_='card-text')
                if desc_p:
                    return desc_p.get_text().strip()
        return None

    def _extract_cvss(self, soup: BeautifulSoup) -> Optional[float]:
        """Extract CVSS score."""
        severity_btn = soup.find('div', class_=re.compile(r'btn-severity-'))
        if severity_btn:
            score_b = severity_btn.find('b')
            if score_b:
                try:
                    score_str = score_b.get_text().strip().replace(',', '.')
                    return float(score_str)
                except ValueError:
                    pass
        return None

    def _extract_date_published(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract publication date."""
        pub_p = soup.find('p', string=re.compile(r'Published Date :', re.I))
        if pub_p:
            pub_h6 = pub_p.find_next_sibling('h6', class_='text-truncate')
            if pub_h6:
                return pub_h6.get_text().strip()
        return None

    def _extract_lifecycle(self, soup: BeautifulSoup, date_published: Optional[str] = None) -> str:
        """Extract lifecycle status."""
        # 1. Added to CISA KEV
        # Search for CISA KEV text in common header/info tags
        if soup.find(lambda tag: tag.name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'div', 'p'] and \
                    'CISA KEV' in tag.get_text()):
            return "Added to CISA KEV"
            
        # 2. Exploitation available
        # Look for the Public Exploits section or PoC mentions
        if soup.find(lambda tag: tag.name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p'] and \
                    ('Public PoC/Exploit' in tag.get_text() or 'Public Exploits' in tag.get_text())):
            return "Exploitation available"
            
        # 3. Disclosure
        # Check if we found a published date anywhere (either passed or in HTML)
        if date_published or soup.find(lambda tag: tag.name in ['p', 'h6', 'div'] and \
                    'Published Date :' in tag.get_text()):
            return "Disclosure"
            
        # 4. Exploitation Unknown
        return "Exploitation Unknown"

    def _extract_cwe(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract CWE title."""
        cwe_pattern = re.compile(r'CWE\-\d+:\s*(.*)', re.I)
        
        # Try links first
        cwe_links = soup.find_all('a', href=re.compile(r'/cwe/detail/cwe-'))
        for link in cwe_links:
            text = ' '.join(link.get_text().split()).strip()
            match = cwe_pattern.search(text)
            if match:
                return match.group(1).strip()
            elif text.upper().startswith('CWE-'):
                return text
                
        # Fallback to general text search
        cwe_text_node = soup.find(string=re.compile(r'CWE-\d+:', re.I))
        if cwe_text_node:
            text = ' '.join(cwe_text_node.split()).strip()
            match = cwe_pattern.search(text)
            if match:
                return match.group(1).strip()
        return None

    def _extract_affected(self, soup: BeautifulSoup) -> Dict[str, List[Dict]]:
        """Extract affected products."""
        affected = {}
        affected_header = soup.find('h5', string=re.compile(r'Affected Products', re.I))
        if affected_header:
            card_body = affected_header.find_parent('div', class_='card-body')
            if card_body:
                table = card_body.find('table')
                if table:
                    tbody = table.find('tbody')
                    if tbody:
                        rows = tbody.find_all('tr')
                        for row in rows:
                            cols = row.find_all('td')
                            if len(cols) >= 3:
                                vendor = cols[1].get_text().strip()
                                product = cols[2].get_text().strip()
                                
                                if vendor not in affected:
                                    affected[vendor] = []
                                
                                if not any(p['product'] == product for p in affected[vendor]):
                                    affected[vendor].append({
                                        'product': product,
                                        'affected_versions': [],
                                        'fixed_versions': []
                                    })
        return affected

    def _extract_urls(self, soup: BeautifulSoup) -> List[str]:
        """Extract reference URLs."""
        urls = []
        ref_header = soup.find('h6', string=re.compile(r'References to Advisories', re.I))
        if ref_header:
            card = ref_header.find_parent('div', class_='card')
            if card:
                table = card.find('table')
                if table:
                    links = table.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        if href.startswith('http') and href not in urls:
                            urls.append(href)
        return urls

    def _extract_exploits(self, soup: BeautifulSoup) -> List[str]:
        """Extract exploit URLs from repositories tab and references table badge."""
        exploits = []
        
        # 1. GitHub repositories from 'repositories' tab
        repo_tab = soup.find('div', id='repositories')
        if repo_tab:
            repo_links = repo_tab.find_all('a', href=re.compile(r'github\.com', re.I))
            for link in repo_links:
                href = link['href']
                if href.startswith('http') and href not in exploits:
                    exploits.append(href)
        
        # 2. References table links with 'Exploit' badge
        ref_header = soup.find('h6', string=re.compile(r'References to Advisories', re.I))
        if ref_header:
            card = ref_header.find_parent('div', class_='card')
            if card:
                table = card.find('table')
                if table:
                    rows = table.find_all('tr')
                    for row in rows:
                        # Check badge in the second <td>
                        badges = row.find_all('span', class_='badge')
                        is_exploit = any('Exploit' in b.get_text() for b in badges)
                        
                        if is_exploit:
                            link = row.find('a', href=True)
                            if link:
                                href = link['href']
                                if href.startswith('http') and href not in exploits:
                                    exploits.append(href)
        
        return exploits