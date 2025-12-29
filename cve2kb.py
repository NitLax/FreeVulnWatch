#!/usr/bin/env python3
"""
CVE to KB (Knowledge Base) mapping tool for Microsoft vulnerabilities.
Fetches data from the MSRC (Microsoft Security Response Center) API.
"""

import sys
import argparse
import json
import requests
from typing import List, Union

def get_kb_from_cve(cve_id: str) -> Union[List[str], str]:
    """
    Fetch KB IDs associated with a specific CVE from MSRC API.
    """
    base_url = "https://api.msrc.microsoft.com/cvrf/v3.0"
    
    # 1. Find which update document contains this CVE
    update_url = f"{base_url}/updates('{cve_id}')"
    headers = {'Accept': 'application/json'}
    
    try:
        response = requests.get(update_url, headers=headers, timeout=10)
        if response.status_code != 200:
            return f"Error: Could not find update for {cve_id} (Status: {response.status_code})"
        
        updates = response.json().get('value', [])
        if not updates:
            return f"No records found for {cve_id}"

        # Most CVEs are fixed in one main document (e.g., a specific Patch Tuesday)
        doc_id = updates[0].get('ID')
        
        # 2. Get the full CVRF document for that update
        doc_url = f"{base_url}/document/{doc_id}"
        doc_response = requests.get(doc_url, headers=headers, timeout=10)
        
        if doc_response.status_code != 200:
            return "Error fetching document details."

        data = doc_response.json()
        vulnerabilities = data.get('Vulnerability', [])
        
        # 3. Filter for the specific CVE and extract KBs
        kb_list = set()
        for vuln in vulnerabilities:
            if vuln.get('CVE') == cve_id:
                remediations = vuln.get('Remediations', [])
                for rem in remediations:
                    # KBs are typically stored in the Description field
                    desc = rem.get('Description', {}).get('Value', '')
                    if desc.isdigit(): # Microsoft often provides the numeric KB ID
                        kb_list.add(f"KB{desc}")
                    elif "KB" in desc:
                        kb_list.add(desc)
                        
        return sorted(list(kb_list))
    except Exception as e:
        return f"Error: {str(e)}"

def process_file(filepath: str) -> dict:
    """Process multiple CVEs from a file."""
    results = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                cve = line.strip()
                if cve and not cve.startswith('#'):
                    # Support lines that contain more than just CVE
                    import re
                    match = re.search(r'CVE-\d{4}-\d+', cve.upper())
                    if match:
                        found_cve = match.group(0)
                        print(f"Fetching KBs for {found_cve}...", file=sys.stderr)
                        results[found_cve] = get_kb_from_cve(found_cve)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found.", file=sys.stderr)
        sys.exit(1)
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Fetch Microsoft KB IDs for given CVEs using MSRC API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cve2kb.py CVE-2024-38063
  python cve2kb.py --file cve_list.txt
  python cve2kb.py CVE-2024-38063 --json
        """
    )
    
    parser.add_argument(
        'cve_id',
        nargs='?',
        help='CVE identifier (e.g., CVE-2024-38063)'
    )
    
    parser.add_argument(
        '--file', '-f',
        help='File containing CVE IDs (one per line)'
    )
    
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output results in JSON format'
    )

    args = parser.parse_args()

    if not args.cve_id and not args.file:
        parser.print_help()
        sys.exit(1)

    if args.file:
        results = process_file(args.file)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for cve, kbs in results.items():
                if isinstance(kbs, list):
                    print(f"{cve}: {', '.join(kbs)}")
                else:
                    print(f"{cve}: {kbs}")
    else:
        kbs = get_kb_from_cve(args.cve_id.upper())
        if args.json:
            print(json.dumps({args.cve_id.upper(): kbs}, indent=2))
        else:
            if isinstance(kbs, list):
                print(f"KBs for {args.cve_id.upper()}: {', '.join(kbs)}")
            else:
                print(kbs)

if __name__ == "__main__":
    main()
