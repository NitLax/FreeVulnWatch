#!/usr/bin/env python3
"""
Command-line interface for openSourceVulnIntelligence.

Usage:
    python openSourceVulnIntelligence.py CVE-2024-1234
    python openSourceVulnIntelligence.py --file cve_list.txt
    python openSourceVulnIntelligence.py --file cve_list.txt --output results.json --format json
"""
import sys
import argparse
import json
import csv
from pathlib import Path
from typing import List

# Import the module
try:
    from openSourceVulnIntelligence import (
        get_vulnerability,
        get_vulnerabilities,
        read_cves_from_file,
        get_cache
    )
except ImportError:
    # If running as script, add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent))
    from openSourceVulnIntelligence import (
        get_vulnerability,
        get_vulnerabilities,
        read_cves_from_file,
        get_cache
    )


def display_vulnerability(vuln, format_type: str = "text"):
    """Display vulnerability in specified format."""
    if format_type == "text":
        print("\n" + "=" * 80)
        print(vuln.display())
        print("=" * 80)
        
        if vuln.affected:
            print("\nAffected Products:")
            for vendor, products in vuln.affected.items():
                print(f"  {vendor}:")
                # Deduplicate products by name for display
                seen_products = set()
                for product_info in products:
                    product = product_info.get('product', 'Unknown')
                    if product not in seen_products:
                        print(f"    - {product}")
                        seen_products.add(product)
        
        if vuln.exploit:
            print(f"\nExploits Available: {len(vuln.exploit)}")
            for exploit_url in vuln.exploit[:3]:  # Show first 3
                print(f"  - {exploit_url}")
        
        print(f"\nPriority Score: {vuln.calculate_priority_score()}/100")
        print()
    
    elif format_type == "json":
        print(vuln.to_json())
    
    elif format_type == "markdown":
        print(vuln.to_markdown())


def save_results(vulnerabilities: List, output_file: str, format_type: str):
    """Save results to file."""
    output_path = Path(output_file)
    
    if format_type == "json":
        data = [vuln.to_dict() for vuln in vulnerabilities]
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\nResults saved to {output_file}")
    
    elif format_type == "csv":
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Header
            writer.writerow([
                'CVE ID', 'CWE', 'CVSS', 'EPSS', 'Lifecycle',
                'Date Published', 'Description', 'Vendors', 'Products',
                'Exploit Count', 'Priority Score'
            ])
            # Data
            for vuln in vulnerabilities:
                writer.writerow(vuln.to_csv_row())
        print(f"\nResults saved to {output_file}")
    
    elif format_type == "markdown":
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# Vulnerability Intelligence Report\n\n")
            f.write(f"Total CVEs analyzed: {len(vulnerabilities)}\n\n")
            f.write("---\n\n")
            for vuln in vulnerabilities:
                f.write(vuln.to_markdown())
                f.write("\n---\n\n")
        print(f"\nResults saved to {output_file}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Open Source Vulnerability Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single CVE lookup
  python openSourceVulnIntelligence.py CVE-2024-1234
  
  # Batch processing from file
  python openSourceVulnIntelligence.py --file cve_list.txt
  
  # Save results to JSON
  python openSourceVulnIntelligence.py --file cve_list.txt --output results.json
  
  # Use specific scrapers only (space-separated)
  python openSourceVulnIntelligence.py CVE-2024-1234 --scrapers nvd cveorg
  
  # Use specific scrapers only (comma-separated)
  python openSourceVulnIntelligence.py CVE-2024-1234 --scrapers nvd,cveorg
  
  # Clear cache
  python openSourceVulnIntelligence.py --clear-cache
        """
    )
    
    # Positional argument for single CVE
    parser.add_argument(
        'cve_id',
        nargs='?',
        help='CVE identifier (e.g., CVE-2024-1234)'
    )
    
    # File input
    parser.add_argument(
        '--file', '-f',
        help='File containing CVE IDs'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        help='Output file path'
    )
    
    parser.add_argument(
        '--format',
        choices=['text', 'json', 'csv', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )
    
    # Scraper selection
    parser.add_argument(
        '--scrapers', '-s',
        nargs='*',
        metavar='SCRAPER',
        help='Scraper(s) to use (space-separated). Available: wiz, nvd, cveorg. Examples: --scrapers nvd cveorg OR --scrapers nvd,cveorg'
    )
    
    # Cache options
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable caching'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Reduce informational output'
    )
    
    parser.add_argument(
        '--clear-cache',
        action='store_true',
        help='Clear all cached data'
    )
    
    args = parser.parse_argument_list() if hasattr(parser, 'parse_argument_list') else parser.parse_args()
    
    verbose = not args.quiet
    
    # Handle cache clearing
    if args.clear_cache:
        cache = get_cache()
        cache.clear()
        print("Cache cleared successfully.")
        return 0
    
    # Validate input
    if not args.cve_id and not args.file:
        parser.print_help()
        print("\nError: Either provide a CVE ID or use --file to specify a file.")
        return 1
    
    # Parse scrapers
    scrapers = None
    if args.scrapers:
        # args.scrapers is now a list due to nargs='*'
        # Handle both: --scrapers nvd cveorg (list) and --scrapers nvd,cveorg (comma in first element)
        if len(args.scrapers) == 1 and ',' in args.scrapers[0]:
            # Comma-separated in single string
            scrapers = [s.strip() for s in args.scrapers[0].split(',')]
        else:
            # Space-separated (already a list)
            scrapers = [s.strip() for s in args.scrapers]
        
        # Validate scraper names
        from openSourceVulnIntelligence import get_registry
        registry = get_registry()
        available = registry.get_scraper_names()
        invalid = [s for s in scrapers if s not in available]
        if invalid:
            print(f"Warning: Unknown scraper(s): {', '.join(invalid)}")
            print(f"Available scrapers: {', '.join(available)}")
            scrapers = [s for s in scrapers if s in available]
            if not scrapers:
                print("Error: No valid scrapers specified.")
                return 1
    
    # Process CVEs
    try:
        if args.file:
            # Batch processing
            print(f"Reading CVEs from {args.file}...")
            cve_ids = read_cves_from_file(args.file)
            print(f"Found {len(cve_ids)} CVE(s): {', '.join(cve_ids)}\n")
            
            vulnerabilities = get_vulnerabilities(
                cve_ids,
                scrapers=scrapers,
                use_cache=not args.no_cache,
                verbose=verbose
            )
            
            # Display or save results
            if args.output:
                save_results(vulnerabilities, args.output, args.format)
            else:
                for vuln in vulnerabilities:
                    display_vulnerability(vuln, args.format)
        
        else:
            # Single CVE
            vuln = get_vulnerability(
                args.cve_id,
                scrapers=scrapers,
                use_cache=not args.no_cache,
                verbose=verbose
            )
            
            # Display or save results
            if args.output:
                save_results([vuln], args.output, args.format)
            else:
                display_vulnerability(vuln, args.format)
        
        return 0
    
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())