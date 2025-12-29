# openSourceVulnIntelligence

A Python module for gathering vulnerability intelligence from multiple sources with an object-oriented architecture.

## Features

- **OOP Design**: `Vulnerability` class encapsulates all CVE data
- **Extensible Architecture**: Easy to add new scrapers with decorator pattern
- **Multiple Data Sources**: CVE.org, NVD, Wiz (easily add more)
- **Smart Data Merging**: Intelligently combines data from multiple sources
- **Caching**: File-based caching to avoid redundant API calls
- **Priority Scoring**: Calculate risk scores based on CVSS, EPSS, and lifecycle
- **Multiple Export Formats**: JSON, CSV, Markdown, STIX 2.1
- **Batch Processing**: Process multiple CVEs from a file
- **CLI Interface**: Full-featured command-line tool

## Installation

```bash
pip install beautifulsoup4 requests
```

## Usage

### As a Python Module

```python
from openSourceVulnIntelligence import get_vulnerability

# Get vulnerability data
vuln = get_vulnerability("CVE-2024-1234")

# Display information
print(vuln.display())
print(f"Priority Score: {vuln.calculate_priority_score()}/10")

# Export to different formats
print(vuln.to_json())
print(vuln.to_markdown())
```

### As a CLI Tool

```bash
# Single CVE lookup
python openSourceVulnIntelligence.py CVE-2024-1234

# Batch processing from file
python openSourceVulnIntelligence.py --file cve_list.txt

# Save results to JSON
python openSourceVulnIntelligence.py --file cve_list.txt --output results.json

# Use specific scrapers (space-separated)
python openSourceVulnIntelligence.py CVE-2024-1234 --scrapers nvd cveorg

# Use specific scrapers (comma-separated)
python openSourceVulnIntelligence.py CVE-2024-1234 --scrapers nvd,cveorg,wiz

# Export to CSV
python openSourceVulnIntelligence.py --file cve_list.txt --output report.csv --format csv

# Clear cache
python openSourceVulnIntelligence.py --clear-cache
```

### Available Scraper Codenames

- `cveorg` - CVE.org official API (priority 10)
- `nvd` - National Vulnerability Database (priority 10)
- `wiz` - Wiz vulnerability database with EPSS data (priority 5)

### File Format for Batch Processing

Create a text file with CVE IDs (one per line):

```
# Critical vulnerabilities
CVE-2024-3094
CVE-2021-44228

# The tool automatically extracts CVEs from text
Found CVE-2023-23397 in production logs
```

## Adding a New Scraper

The architecture makes it easy to add new scrapers:

```python
from openSourceVulnIntelligence.scrapers.base import BaseScraper
from openSourceVulnIntelligence.scrapers.registry import register_scraper

@register_scraper
class ExploitDBScraper(BaseScraper):
    def get_name(self):
        return "exploitdb"
    
    def get_priority(self):
        return 3  # Lower priority than official sources
    
    def scrape(self, cve_id):
        # Your scraping logic here
        return {
            'cve_id': cve_id,
            'cwe': None,
            'cvss': None,
            'epss': None,
            'lifecycle': None,
            'date_published': None,
            'description': None,
            'affected': None,
            'urls': [],
            'exploit': []
        }
```

That's it! The scraper is automatically registered and available.

## Module Structure

```
openSourceVulnIntelligence/
├── __init__.py           # Main module interface
├── vulnerability.py      # Vulnerability class
├── cache.py             # Caching layer
├── utils.py             # Utility functions
└── scrapers/
    ├── __init__.py
    ├── base.py          # Abstract base scraper
    ├── registry.py      # Scraper registry
    ├── cveorg.py        # CVE.org scraper
    ├── nvd.py           # NVD scraper
    └── wiz.py           # Wiz scraper
```

## API Reference

### Vulnerability Class

- `merge_data(data, source)` - Merge data from a scraper
- `calculate_priority_score()` - Calculate risk score (0-10)
- `to_dict()` - Export to dictionary
- `to_json()` - Export to JSON
- `to_csv_row()` - Export to CSV row
- `to_markdown()` - Export to Markdown
- `display()` - Human-readable display

### Main Functions

- `get_vulnerability(cve_id, scrapers=None, use_cache=True)` - Get single vulnerability
- `get_vulnerabilities(cve_ids, scrapers=None, use_cache=True)` - Get multiple vulnerabilities
- `get_registry()` - Get scraper registry
- `get_cache()` - Get cache instance

## License

Open source - feel free to use and modify.
