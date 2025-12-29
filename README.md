# openSourceVulnIntelligence

A Python module for gathering vulnerability intelligence from multiple sources with an object-oriented architecture.

## Features

- **OOP Design**: `Vulnerability` class encapsulates all CVE data
- **Extensible Architecture**: Easy to add new scrapers with decorator pattern
- **Multiple Data Sources**: CVE.org, NVD, Wiz, Vulmon (easily add more)
- **Smart Data Merging**: Intelligently combines data from multiple sources
- **Caching**: File-based caching to avoid redundant API calls
- **Priority Scoring**: Calculate risk scores based on CVSS, EPSS, and lifecycle
- **Multiple Export Formats**: JSON, CSV, Markdown, STIX 2.1
- **Batch Processing**: Process multiple CVEs from a file
- **CLI Interface**: Full-featured command-line tool
- **Microsoft KB Mapping**: Dedicated tool to map CVEs to Microsoft Knowledge Base IDs

## Installation

```bash
pip install -r requirements.txt
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

# Disable caching
python openSourceVulnIntelligence.py CVE-2024-1234 --no-cache

# Clear cache
python openSourceVulnIntelligence.py --clear-cache
```

### CLI Reference

| Argument | Shorthand | Description | Default |
| :--- | :--- | :--- | :--- |
| `cve_id` | *(positional)* | Single CVE identifier (e.g., `CVE-2024-1234`). | None |
| `--file` | `-f` | Path to file containing CVE IDs (one per line). | None |
| `--output` | `-o` | Path to save the results. | None (prints to stdout) |
| `--format` | | Output format: `text`, `json`, `csv`, or `markdown`. | `text` |
| `--scrapers` | `-s` | Space or comma-separated list of scrapers to use. | All available |
| `--no-cache` | | Disable reading from and writing to the local cache. | `False` |
| `--clear-cache` | | Delete all locally cached vulnerability data and exit. | `False` |

### Available Scraper Codenames

- `cveorg` - CVE.org official API (priority 10)
- `nvd` - National Vulnerability Database (priority 10)
- `wiz` - Wiz vulnerability database with EPSS data (priority 5)
- `vulmon` - Vulmon vulnerability database with exploit info (priority 5)

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

## Legacy Scripts

For users who prefer the original script-based approach, `CheckVulns.py` is still available. It provides a quick way to analyze a file containing CVEs and filter them according to a predefined tech stack (`technos` file).

```bash
python CheckVulns.py --filename vulns.txt --filters True
```

### KB Mapping Utility (`cve2kb.py`)

Fetch Microsoft KB IDs for specific CVEs using the MSRC API.

```bash
# Single CVE lookup
python cve2kb.py CVE-2024-38063

# Batch processing
python cve2kb.py --file cve_list.txt --json
```

## License

Open source - feel free to use and modify.
