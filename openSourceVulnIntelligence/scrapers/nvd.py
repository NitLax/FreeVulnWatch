"""
NVD (National Vulnerability Database) API scraper.
"""
import requests
import re
import warnings
from typing import Dict, Any, Optional
from .base import BaseScraper
from .registry import register_scraper
from ..utils import get_mitre_cwe_name, unescape, IsInCISAKEV, itemCrawler

# Disable SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

@register_scraper
class NVDScraper(BaseScraper):
    """Scraper for NVD API."""
    
    def get_name(self) -> str:
        return "nvd"
    
    def get_priority(self) -> int:
        return 10  # Official source
    
    def scrape(self, cve_id: str) -> Dict[str, Any]:
        """Scrape NVD API."""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=15, verify=False)
        response.raise_for_status()
        data = response.json()
        
        return {
            'cve_id': cve_id,
            'cwe': unescape(get_mitre_cwe_name(self._extract_cwe_id(data))),
            'cvss': self._extract_cvss(data),
            'epss': None,
            'lifecycle': self._extract_lifecycle(data, cve_id),
            'date_published': self._extract_date_published(data),
            'description': self._extract_description(data),
            'affected': self._extract_affected(data),
            'urls': self._extract_urls(data),
            'exploit': self._extract_exploit(data)
        }
    
    def _extract_cwe_id(self, api: dict) -> Optional[str]:
        try:
            weaknesses = api.get('vulnerabilities', {})[0].get('cve', {}).get('weaknesses', [])
        except IndexError:
            return None
        cwe_ids = list(set(re.findall(r"CWE-(\d+)", str(weaknesses))))
        if len(cwe_ids) > 0:
            # Return the highest CWE ID (most specific)
            return max(cwe_ids, key=int)
        return None
    
    def _extract_cvss(self, api: dict) -> Optional[float]:
        try:
            metrics = api.get('vulnerabilities', {})[0].get('cve', {}).get('metrics', {})
            latestcvssversion = [cvssV for cvssV in metrics.keys() if str(cvssV).startswith('cvssMetricV')][0]
            cvss = metrics[latestcvssversion][0].get('cvssData', {}).get('baseScore', None)
            return float(cvss) if cvss is not None else None
        except (IndexError, KeyError):
            return None
    
    def _extract_lifecycle(self, api: dict, cve_id: str) -> Optional[str]:
        if IsInCISAKEV(cve_id):
            return "Added to CISA KEV"
        try:
            references = api.get('vulnerabilities', {})[0].get('cve', {}).get('references', [])
            tags = [tag.lower() for ref in references for tag in ref.get('tags', [])]
            urls = [ref.get('url', "") for ref in references]
            if any(tag in tags for tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"]):
                return "Exploitation available"
            if any(word in urli for urli in urls for word in ["exploit", "poc", "proof-of-concept", "issue-tracking", "writeups", "sploit", "packetstormsecurity"]):
                return "Exploitation available"
            if 'published' in api.get('vulnerabilities', {})[0].get('cve', {}).keys():
                return "Disclosure"
        except IndexError:
            return None
        return None
    
    def _extract_date_published(self, data: dict) -> Optional[str]:
        try:
            res = data.get('vulnerabilities')[0].get('cve', {}).get('published', None)
        except IndexError:
            return None
        if res is not None:
            res = res[:-4] + 'Z'
        return res
    
    def _extract_description(self, data: dict) -> Optional[str]:
        try:
            descriptions = data.get('vulnerabilities')[0].get('cve', {}).get('descriptions', [])
            english_description_list = itemCrawler(descriptions, ['lang'], 'en')
            if len(english_description_list) > 0:
                return english_description_list[0].get('value', None)
            return None
        except IndexError:
            return None
    
    def _extract_affected(self, data: dict) -> Optional[Dict[str, Any]]:
        res = {}
        try:
            configurations = data.get('vulnerabilities')[0].get('cve', {}).get('configurations', [])
            
            # Iterate through all configurations, not just the first one
            for config in configurations:
                nodes = config.get('nodes', [])
                
                # Iterate through all nodes in each configuration
                for node in nodes:
                    cpes = node.get('cpeMatch', [])
                    
                    for cpe in cpes:
                        criteria = cpe.get('criteria')
                        if not criteria:
                            continue
                        
                        parts = criteria.split(':')
                        if len(parts) < 5:
                            continue
                        
                        vendor = parts[3].replace('_', ' ').capitalize()
                        product = parts[4].replace('_', ' ').capitalize()
                        vfix = cpe.get('versionEndExcluding', None)
                        vaffected = f'before {vfix}' if vfix else None
                        
                        item = {
                            'product': product,
                            'affected_versions': [vaffected] if vaffected else [],
                            'fixed_versions': [vfix] if vfix else []
                        }
                        
                        if vendor in res:
                            res[vendor].append(item)
                        else:
                            res[vendor] = [item]
        except (IndexError, KeyError):
            return None
        return res if res else None
    
    def _extract_urls(self, data: dict) -> Optional[list]:
        try:
            references = data.get('vulnerabilities', {})[0].get('cve', {}).get('references', [])
            urls = [ref.get('url', None) for ref in references]
            return [url for url in urls if url] if urls else None
        except IndexError:
            return None
    
    def _extract_exploit(self, data: dict) -> Optional[list]:
        all_exploit_url = None
        try:
            exploit_tagged_url = []
            exploit_worded_url = []
            references = data.get('vulnerabilities', {})[0].get('cve', {}).get('references', [])
            for ref in references:
                if any(tag.lower() in [lowertag.lower() for lowertag in ref.get('tags', [])] for tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"]):
                    exploit_tagged_url.append(ref.get('url', None))
                if any(word in ref.get('url', '') for word in ["exploit", "poc", "proof-of-concept", "proofofconcept", "issue-tracking", "writeups", "sploit", "packetstormsecurity"]) and 'cisa.gov' not in ref.get('url', ''):
                    exploit_worded_url.append(ref.get('url', None))
            all_exploit_url = list(set(exploit_tagged_url + exploit_worded_url))
        except IndexError:
            return None
        if all_exploit_url == []:
            return None
        return all_exploit_url
