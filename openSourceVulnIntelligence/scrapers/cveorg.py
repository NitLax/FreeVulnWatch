"""
CVE.org API scraper.
"""
import requests
import warnings
from typing import Dict, Any, Optional
from .base import BaseScraper
from .registry import register_scraper

# Disable SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


@register_scraper
class CVEOrgScraper(BaseScraper):
    """Scraper for CVE.org API."""
    
    def get_name(self) -> str:
        return "cveorg"
    
    def get_priority(self) -> int:
        return 10  # Official source
    
    def scrape(self, cve_id: str) -> Dict[str, Any]:
        """Scrape CVE.org API."""
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url, timeout=15, verify=False)
        response.raise_for_status()
        data = response.json()
        
        return {
            'cve_id': cve_id,
            'cwe': self._extract_cwe(data),
            'cvss': self._extract_cvss(data),
            'epss': None,
            'lifecycle': self._extract_lifecycle(data),
            'date_published': self._extract_date_published(data),
            'description': self._extract_description(data),
            'affected': self._extract_affected(data),
            'urls': self._extract_urls(data),
            'exploit': self._extract_exploits(data)
        }
    
    def _extract_cwe(self, api: dict) -> Optional[str]:
        try:
            containers = api.get("containers", {})
            
            # Check CNA first
            cna_problems = containers.get("cna", {}).get("problemTypes", [])
            for pt in cna_problems:
                for desc in pt.get("descriptions", []):
                    if "cweId" in desc:
                        return desc["description"]
            
            # Fallback: Check ADP
            adp_entries = containers.get("adp", [])
            for entry in adp_entries:
                for pt in entry.get("problemTypes", []):
                    for desc in pt.get("descriptions", []):
                        if "cweId" in desc:
                            return desc["description"]
            
            return None
        except Exception:
            return None
    
    def _extract_cvss(self, api: dict) -> Optional[float]:
        try:
            containers = api.get("containers", {})
            all_metrics = []
            
            # Collect metrics from both CNA and ADP
            cna_metrics = containers.get("cna", {}).get("metrics", [])
            adp_entries = containers.get("adp", [])
            adp_metrics = []
            for entry in adp_entries:
                adp_metrics.extend(entry.get("metrics", []))
            
            all_metrics.extend(cna_metrics)
            all_metrics.extend(adp_metrics)
            
            priority = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
            
            for level in priority:
                for metric in all_metrics:
                    if level in metric:
                        data = metric[level]
                        score = data.get("baseScore")
                        if isinstance(score, (int, float)):
                            return float(score)
            return None
        except Exception:
            return None
    
    def _extract_lifecycle(self, api: dict) -> Optional[str]:
        try:
            containers = api.get("containers", {})
            
            # Check for CISA KEV in ADP
            adp_entries = containers.get("adp", [])
            for adp in adp_entries:
                for tl in adp.get("timeline", []):
                    if "CISA KEV" in tl.get("value", "").upper():
                        return "Added to CISA KEV"
                for ref in adp.get('references', []):
                    if "cisa.gov/known-exploited-vulnerabilities-catalog" in ref.get('url', ''):
                        return "Added to CISA KEV"
                for metric in adp.get("metrics", []):
                    if "KEV" in metric.get("other", {}).get("type", "").upper():
                        return "Added to CISA KEV"
            
            # Check for exploit indicators in references
            references = containers.get("cna", {}).get("references", [])
            for ref in references:
                tags = [t.lower() for t in ref.get("tags", [])]
                if any(tag in tags for tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"]):
                    return "Exploitation available"
            
            # Check for ADP metrics exploitation hints
            for adp in adp_entries:
                for metric in adp.get("metrics", []):
                    content = metric.get("other", {}).get("content", {})
                    if isinstance(content, dict):
                        for opt in content.get("options", []):
                            if "Exploitation" in opt and opt["Exploitation"].lower() in ["poc", "active"]:
                                return "Exploitation available"
            
            # If CVE has publication date but no exploit
            if api.get("cveMetadata", {}).get("datePublished"):
                return "Disclosure"
            
            return None
        except Exception:
            return None
    
    def _extract_affected(self, api: dict) -> Optional[Dict[str, Any]]:
        affected_data = {}
        
        try:
            affected_entries = api.get("containers", {}).get("cna", {}).get("affected", [])
            for entry in affected_entries:
                vendor = entry.get("vendor", "Unknown Vendor").strip()
                product = entry.get("product", "Unknown Product").strip()
                versions = entry.get("versions", [])
                
                affected_versions = []
                fixed_versions = []
                
                for ver in versions:
                    status = ver.get("status", "").lower()
                    version = ver.get("version")
                    if not version:
                        continue
                    if status == "affected":
                        affected_versions.append(version)
                    elif status in ["fixed", "patched", "unaffected"]:
                        fixed_versions.append(version)
                
                product_entry = {
                    "product": product,
                    "affected_versions": affected_versions,
                    "fixed_versions": fixed_versions
                }
                
                if vendor not in affected_data:
                    affected_data[vendor] = []
                affected_data[vendor].append(product_entry)
            
            return affected_data if affected_data else None
        except Exception:
            return None
    
    def _extract_date_published(self, api: dict) -> Optional[str]:
        try:
            return api.get("cveMetadata", {}).get("datePublished", None)
        except Exception:
            return None
    
    def _extract_description(self, api: dict) -> Optional[str]:
        try:
            descs = api.get("containers", {}).get("cna", {}).get("descriptions", [])
            # Prefer 'en-US' first
            for lang in ["en-US", "en"]:
                for d in descs:
                    if d.get("lang") == lang and d.get("value"):
                        return d["value"]
            # Fallback: first available
            if descs:
                return descs[0].get("value", None)
            return None
        except Exception:
            return None
    
    def _extract_urls(self, api: dict) -> Optional[list]:
        urls = []
        try:
            references = api.get("containers", {}).get("cna", {}).get("references", [])
            for ref in references:
                url = ref.get("url")
                if not url:
                    continue
                tags = [t.lower() for t in ref.get("tags", [])]
                # Skip PoC/exploit/issue-tracking
                if any(tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"] for tag in tags):
                    continue
                if url not in urls:
                    urls.append(url)
            return urls if urls else None
        except Exception:
            return None
    
    def _extract_exploits(self, api: dict) -> Optional[list]:
        exploits = []
        try:
            references = api.get("containers", {}).get("cna", {}).get("references", [])
            for ref in references:
                url = ref.get("url")
                if not url:
                    continue
                tags = [t.lower() for t in ref.get("tags", [])]
                if any(tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"] for tag in tags):
                    if url not in exploits:
                        exploits.append(url)
            return exploits if exploits else None
        except Exception:
            return None
