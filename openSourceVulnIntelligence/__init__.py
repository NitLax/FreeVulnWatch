"""
openSourceVulnIntelligence - Open Source Vulnerability Intelligence Module

A Python module for gathering vulnerability intelligence from multiple sources.
"""
from .vulnerability import Vulnerability
from .scrapers import get_registry, CVEOrgScraper, NVDScraper, WizScraper, VulmonScraper, CVEFeedScraper
from .cache import get_cache
from .utils import read_cves_from_file, extract_cves_from_text
from typing import List, Optional


__version__ = "2.0.0"
__all__ = [
    'Vulnerability',
    'get_vulnerability',
    'get_vulnerabilities',
    'get_registry',
    'get_cache',
    'CVEOrgScraper',
    'NVDScraper',
    'WizScraper',
    'VulmonScraper',
    'CVEFeedScraper',
    'read_cves_from_file',
    'extract_cves_from_text'
]


def get_vulnerability(
    cve_id: str,
    scrapers: Optional[List[str]] = None,
    use_cache: bool = True,
    verbose: bool = False
) -> Vulnerability:
    """
    Get vulnerability information for a CVE.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        scrapers: List of scraper names to use (default: all)
        use_cache: Whether to use cached data
        
    Returns:
        Vulnerability object with merged data from all sources
        
    Example:
        >>> vuln = get_vulnerability("CVE-2024-1234")
        >>> print(vuln.display())
        >>> print(vuln.to_json())
    """
    cve_id = cve_id.upper()
    vuln = Vulnerability(cve_id)
    
    # Get cache
    cache = get_cache() if use_cache else None
    
    # Get registry
    registry = get_registry()
    
    # Determine which scrapers to use
    if scrapers is None:
        scraper_instances = registry.get_all_scrapers(sorted_by_priority=True)
    else:
        scraper_instances = []
        for scraper_name in scrapers:
            scraper = registry.get_scraper(scraper_name)
            if scraper:
                scraper_instances.append(scraper)
        scraper_instances.sort(key=lambda s: s.get_priority(), reverse=True)
    
    # Scrape from each source
    for scraper in scraper_instances:
        scraper_name = scraper.get_name()
        cache_key = f"{scraper_name}_{cve_id}"
        
        # Try cache first
        if cache:
            cached_data = cache.get(cache_key)
            if cached_data:
                if verbose:
                    print(f"[{scraper_name}] Using cached data for {cve_id}")
                vuln.merge_data(cached_data, source=scraper_name)
                continue
        
        # Scrape
        if verbose:
            print(f"[{scraper_name}] Scraping {cve_id}...")
        data = scraper.scrape_safe(cve_id, verbose=verbose)
        
        if data:
            vuln.merge_data(data, source=scraper_name)
            
            # Cache the result
            if cache:
                cache.set(cache_key, data)
    
    return vuln


def get_vulnerabilities(
    cve_ids: List[str],
    scrapers: Optional[List[str]] = None,
    use_cache: bool = True,
    verbose: bool = False
) -> List[Vulnerability]:
    """
    Get vulnerability information for multiple CVEs.
    
    Args:
        cve_ids: List of CVE identifiers
        scrapers: List of scraper names to use (default: all)
        use_cache: Whether to use cached data
        
    Returns:
        List of Vulnerability objects
        
    Example:
        >>> vulns = get_vulnerabilities(["CVE-2024-1234", "CVE-2024-5678"])
        >>> for vuln in vulns:
        ...     print(vuln.display())
    """
    vulnerabilities = []
    
    for cve_id in cve_ids:
        try:
            vuln = get_vulnerability(cve_id, scrapers=scrapers, use_cache=use_cache, verbose=verbose)
            vulnerabilities.append(vuln)
        except Exception as e:
            if verbose:
                print(f"Error processing {cve_id}: {e}")
    
    return vulnerabilities
