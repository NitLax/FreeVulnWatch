"""
Base scraper class for vulnerability intelligence sources.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import time


class BaseScraper(ABC):
    """
    Abstract base class for all vulnerability scrapers.
    
    All scrapers must implement:
    - get_name(): Return scraper identifier
    - get_priority(): Return priority for data merging (higher = more authoritative)
    - scrape(cve_id): Fetch and return vulnerability data
    """
    
    def __init__(self, rate_limit_delay: float = 0.5):
        """
        Initialize scraper.
        
        Args:
            rate_limit_delay: Delay in seconds between requests
        """
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0
    
    @abstractmethod
    def get_name(self) -> str:
        """
        Get scraper name/identifier.
        
        Returns:
            Scraper name (e.g., 'nvd', 'cveorg')
        """
        pass
    
    @abstractmethod
    def get_priority(self) -> int:
        """
        Get scraper priority for data merging.
        
        Higher priority scrapers are considered more authoritative.
        Recommended values:
        - 10: Official sources (NVD, CVE.org)
        - 5: Curated sources (Wiz, VulnCheck)
        - 1: Community sources
        
        Returns:
            Priority value (1-10)
        """
        pass
    
    @abstractmethod
    def scrape(self, cve_id: str) -> Dict[str, Any]:
        """
        Scrape vulnerability data for a CVE.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            
        Returns:
            Dictionary with vulnerability data following the standard format:
            {
                'cve_id': str,
                'cwe': Optional[str],
                'cvss': Optional[float],
                'epss': Optional[float],
                'lifecycle': Optional[str],
                'date_published': Optional[str],
                'description': Optional[str],
                'affected': Optional[Dict[str, List[Dict]]],
                'urls': Optional[List[str]],
                'exploit': Optional[List[str]]
            }
        """
        pass
    
    def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        current_time = time.time()
        time_since_last_request = current_time - self._last_request_time
        
        if time_since_last_request < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last_request)
        
        self._last_request_time = time.time()
    
    def scrape_safe(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Scrape with error handling and rate limiting.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Vulnerability data or None if scraping failed
        """
        try:
            self._rate_limit()
            return self.scrape(cve_id)
        except Exception as e:
            print(f"[{self.get_name()}] Error scraping {cve_id}: {e}")
            return None
    
    def __repr__(self) -> str:
        """Developer representation."""
        return f"{self.__class__.__name__}(name='{self.get_name()}', priority={self.get_priority()})"
