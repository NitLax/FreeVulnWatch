"""
Utility functions for vulnerability intelligence.
"""
import requests
import re
import html
from typing import List, Dict, Any, Optional


def get_vendors(vuln_item: Dict[str, Any]) -> List[str]:
    """
    Extract vendors from vulnerability item.
    
    Args:
        vuln_item: Vulnerability dictionary
        
    Returns:
        List of vendor names
    """
    if vuln_item.get('affected') is None:
        return []
    return list(vuln_item['affected'].keys())


def IsInCISAKEV(cve_id: str) -> bool:
    """
    Check if CVE is in CISA Known Exploited Vulnerabilities catalog.
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        True if CVE is in CISA KEV, False otherwise
    """
    try:
        url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        data = response.json()
        return len(re.findall(cve_id, str(data))) > 0
    except Exception:
        return False


def itemCrawler(items: List[Dict], keys: List[str], value: Any) -> List[Dict]:
    """
    Search items by nested keys.
    
    Args:
        items: List of dictionaries to search
        keys: List of keys to navigate (e.g., ['lang'] or ['metrics', 'cvss'])
        value: Value to match
        
    Returns:
        List of matching items
    """
    if len(keys) == 1:
        return [item for item in items if item.get(keys[0]) == value]
    if len(keys) == 2:
        return [item for item in items if item.get(keys[0], {}).get(keys[1]) == value]
    return []


def get_mitre_cwe_name(cwe_id: Optional[str]) -> Optional[str]:
    """
    Get CWE name from MITRE.
    
    Args:
        cwe_id: CWE ID (e.g., '79' or 'CWE-79')
        
    Returns:
        CWE name or None
    """
    if cwe_id is None:
        return None
    
    # Remove CWE- prefix if present
    if cwe_id.startswith('CWE-'):
        cwe_id = cwe_id[4:]
    
    try:
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        response = requests.get(url, timeout=10, verify=False)  # SSL issues workaround
        response.raise_for_status()
        data = response.text
        
        # Try multiple regex patterns (MITRE format may vary)
        patterns = [
            rf'CWE-{cwe_id}:\s*([^<]+)</h2>',  # Standard format
            rf'CWE-{cwe_id}\s*-\s*([^<]+)</h2>',  # Alternative format with dash
            rf'<h2[^>]*>CWE-{cwe_id}:\s*([^<]+)</h2>',  # With h2 attributes
            rf'<h2[^>]*>CWE-{cwe_id}\s*-\s*([^<]+)</h2>',  # Alternative with attributes
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                # Clean up the result (remove extra whitespace)
                return matches[0].strip()
        
        return None
    except Exception as e:
        # Silently fail - CWE name is not critical
        return None


def unescape(text: Optional[str]) -> Optional[str]:
    """
    Unescape HTML entities.
    
    Args:
        text: Text to unescape
        
    Returns:
        Unescaped text or None
    """
    if text is None:
        return None
    return html.unescape(text)


def extract_cves_from_text(text: str) -> List[str]:
    """
    Extract CVE IDs from text.
    
    Args:
        text: Text to search for CVE IDs
        
    Returns:
        List of unique CVE IDs found
    """
    pattern = r'CVE-\d{4}-\d{4,}'
    matches = re.findall(pattern, text, re.IGNORECASE)
    # Normalize to uppercase and deduplicate
    return list(set([cve.upper() for cve in matches]))


def read_cves_from_file(filepath: str) -> List[str]:
    """
    Read CVE IDs from a file.
    
    Supports:
    - One CVE per line
    - Comments with #
    - Automatic CVE extraction from text
    
    Args:
        filepath: Path to file
        
    Returns:
        List of unique CVE IDs
    """
    cves = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                # Remove comments
                line = line.split('#')[0].strip()
                if not line:
                    continue
                
                # Extract CVEs from the line
                found_cves = extract_cves_from_text(line)
                cves.extend(found_cves)
        
        # Deduplicate while preserving order
        seen = set()
        unique_cves = []
        for cve in cves:
            if cve not in seen:
                seen.add(cve)
                unique_cves.append(cve)
        
        return unique_cves
    
    except Exception as e:
        raise Exception(f"Error reading file {filepath}: {e}")
