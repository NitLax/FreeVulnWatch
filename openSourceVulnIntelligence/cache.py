"""
Simple file-based caching for API responses.
"""
import json
import os
import time
from typing import Optional, Any
from pathlib import Path


class Cache:
    """
    Simple file-based cache with TTL support.
    """
    
    def __init__(self, cache_dir: str = ".cache", ttl: int = 86400):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory to store cache files
            ttl: Time-to-live in seconds (default: 24 hours)
        """
        self.cache_dir = Path(cache_dir)
        self.ttl = ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for a key."""
        # Sanitize key for filename
        safe_key = key.replace('/', '_').replace('\\', '_').replace(':', '_')
        return self.cache_dir / f"{safe_key}.json"
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Check if expired
            if time.time() - cache_data['timestamp'] > self.ttl:
                cache_path.unlink()  # Delete expired cache
                return None
            
            return cache_data['value']
        except Exception:
            return None
    
    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
        """
        cache_path = self._get_cache_path(key)
        
        try:
            cache_data = {
                'timestamp': time.time(),
                'value': value
            }
            
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Warning: Failed to cache {key}: {e}")
    
    def clear(self) -> None:
        """Clear all cache files."""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except Exception:
                pass
    
    def clear_expired(self) -> int:
        """
        Clear expired cache files.
        
        Returns:
            Number of files cleared
        """
        cleared = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                if time.time() - cache_data['timestamp'] > self.ttl:
                    cache_file.unlink()
                    cleared += 1
            except Exception:
                pass
        
        return cleared


# Global cache instance
_cache = Cache()


def get_cache() -> Cache:
    """
    Get the global cache instance.
    
    Returns:
        Global Cache instance
    """
    return _cache
