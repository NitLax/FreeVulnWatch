import sys
import os

# Add the parent directory to sys.path to import vulnerability
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openSourceVulnIntelligence.vulnerability import Vulnerability

def test_deduplication():
    vuln = Vulnerability("CVE-2024-TEST")
    
    # Source 1: Apple iOS
    data1 = {
        "affected": {
            "apple": [
                {"product": "ios", "affected_versions": ["17.0"]}
            ]
        }
    }
    
    # Source 2: APPLE iOS (different case)
    data2 = {
        "affected": {
            "APPLE": [
                {"product": "IOS", "fixed_versions": ["17.1"]}
            ]
        }
    }
    
    # Source 3: Another product
    data3 = {
        "affected": {
            "Apple": [
                {"product": "mac_os", "affected_versions": ["14.0"]}
            ]
        }
    }
    
    vuln.merge_data(data1, source="source1")
    vuln.merge_data(data2, source="source2")
    vuln.merge_data(data3, source="source3")
    
    print("Affected Products Structure:")
    import json
    print(json.dumps(vuln.affected, indent=2))
    
    # Assertions
    assert "Apple" in vuln.affected
    assert len(vuln.affected) == 1
    
    products = vuln.affected["Apple"]
    assert len(products) == 2 # Ios and MacOs
    
    ios_product = next(p for p in products if p["product"] == "Ios")
    assert "17.0" in ios_product["affected_versions"]
    assert "17.1" in ios_product["fixed_versions"]
    
    macos_product = next(p for p in products if p["product"] == "MacOs")
    assert macos_product["product"] == "MacOs"
    
    print("\nSUCCESS: Deduplication and CamelCase normalization verified!")

if __name__ == "__main__":
    test_deduplication()
