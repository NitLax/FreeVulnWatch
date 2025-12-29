"""
Scrapers package for vulnerability intelligence.
"""
from .base import BaseScraper
from .registry import ScraperRegistry, register_scraper, get_registry

# Import all scrapers to trigger registration
from .cveorg import CVEOrgScraper
from .nvd import NVDScraper
from .wiz import WizScraper

__all__ = [
    'BaseScraper',
    'ScraperRegistry',
    'register_scraper',
    'get_registry',
    'CVEOrgScraper',
    'NVDScraper',
    'WizScraper'
]
