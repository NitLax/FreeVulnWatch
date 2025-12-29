"""
Scraper registry for automatic discovery and management.
"""
from typing import Dict, List, Type, Optional
from .base import BaseScraper


class ScraperRegistry:
    """
    Registry for managing vulnerability scrapers.
    
    Provides automatic scraper discovery and priority-based ordering.
    """
    
    def __init__(self):
        """Initialize empty registry."""
        self._scrapers: Dict[str, Type[BaseScraper]] = {}
    
    def register(self, scraper_class: Type[BaseScraper]) -> None:
        """
        Register a scraper class.
        
        Args:
            scraper_class: Scraper class to register
        """
        # Instantiate to get name
        instance = scraper_class()
        name = instance.get_name()
        self._scrapers[name] = scraper_class
    
    def get_scraper(self, name: str) -> Optional[BaseScraper]:
        """
        Get scraper instance by name.
        
        Args:
            name: Scraper name
            
        Returns:
            Scraper instance or None
        """
        scraper_class = self._scrapers.get(name)
        if scraper_class:
            return scraper_class()
        return None
    
    def get_all_scrapers(self, sorted_by_priority: bool = True) -> List[BaseScraper]:
        """
        Get all registered scrapers.
        
        Args:
            sorted_by_priority: If True, sort by priority (highest first)
            
        Returns:
            List of scraper instances
        """
        scrapers = [scraper_class() for scraper_class in self._scrapers.values()]
        
        if sorted_by_priority:
            scrapers.sort(key=lambda s: s.get_priority(), reverse=True)
        
        return scrapers
    
    def get_scraper_names(self) -> List[str]:
        """
        Get list of registered scraper names.
        
        Returns:
            List of scraper names
        """
        return list(self._scrapers.keys())
    
    def __len__(self) -> int:
        """Get number of registered scrapers."""
        return len(self._scrapers)
    
    def __repr__(self) -> str:
        """Developer representation."""
        return f"ScraperRegistry(scrapers={self.get_scraper_names()})"


# Global registry instance
_registry = ScraperRegistry()


def register_scraper(scraper_class: Type[BaseScraper]) -> Type[BaseScraper]:
    """
    Decorator to register a scraper class.
    
    Usage:
        @register_scraper
        class MyScraper(BaseScraper):
            ...
    
    Args:
        scraper_class: Scraper class to register
        
    Returns:
        The same scraper class (for chaining)
    """
    _registry.register(scraper_class)
    return scraper_class


def get_registry() -> ScraperRegistry:
    """
    Get the global scraper registry.
    
    Returns:
        Global ScraperRegistry instance
    """
    return _registry
