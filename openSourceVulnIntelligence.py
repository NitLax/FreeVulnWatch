import requests
import re
import json
from bs4 import BeautifulSoup
import sys
import cloudscraper
from collections import OrderedDict
import datetime
import html


# class Vulnerability:
#     def __init__(self,cve_id):
#         self.cve_id = cve_id,
#         self.cwe = None,
#         self.cvss = None,
#         self.score = None,
#         self.epss = None,
#         self.lifecycle = None,
#         
self.date
_published = None,
#         self.affected = None,
#         self.mitigation = None,
        
# res_to_get = {
#     'cve_id':'',
#     'cwe':'',
#     'cvss':'',
#     'epss':'',
#     'lifecycle':"Exploitation Unknown|Disclosure|Exploitation available|Added to CISA KEV",
#     'date_published':'',
#     'description':'',
#     'affected':{vendor:[{product,affected_version,fix}]},
#     'mitigation':'',
#     'urls':[],
#     'exploit':[]|None
# }

def get_vendors(vuln_item):
    if vuln_item['affected']==None: return []
    return vuln_item['affected'].keys()

def IsInCISAKEV(cve_id):
    url = f"
https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    return len(re.findall(cve_id,str(data)))>0

# def get_products(vuln_item):
#     if vuln_item['affected']==None: return []
#     return [item['product'] for item in vendor for vendor in vuln_item{affected}.keys()]

def itemCrawler(items,keys,value):
    # return [item for item in items if item.get(keys[0])==value]
    # res = []
    # for item in items:
    if len(keys)==1:
        return [item for item in items if item.get(keys[0])==value]
    if len(keys)==2:
        return [item for item in items if item.get(keys[0]).get(keys[1])==value]

def get_mitre_cwe_name(cwe_id):
    cwe = None
    if cwe_id == None: return None
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    response = requests.get(url)
    response.raise_for_status()
    data = response.text
    list_cwe = re.findall(f'CWE\-{cwe_id}\:\s(.*?)\<\/h2\>',data)
    if len(list_cwe)>0 : cwe = list_cwe[0]
    return cwe 

def unescape(str):
    if str == None:
        return None
    else:
        return html.unescape(str)
    
#vulmon,wiz,inthewild,exploitdb,vulners?,nvd

def cveorgScraper(cve):
    # url = f"https://cve.org/CVERecord?id={cve}"
    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()

    def extract_cwe(api: dict) -> str:
        try:
            containers = api.get("containers", {})

            # --- Check CNA first ---
            cna_problems = containers.get("cna", {}).get("problemTypes", [])
            for pt in cna_problems:
                for desc in pt.get("descriptions", []):
                    if "cweId" in desc:
                        return desc["description"]

            # --- Fallback: Check ADP ---
            adp_entries = containers.get("adp", [])
            for entry in adp_entries:
                for pt in entry.get("problemTypes", []):
                    for desc in pt.get("descriptions", []):
                        if "cweId" in desc:
                            return desc["description"]

            return None
        except Exception:
            return None

    def extract_cvss(api: dict) -> float:
        try:
            containers = api.get("containers", {})
            all_metrics = []

            # Collect metrics from both CNA and ADP if present
            cna_metrics = containers.get("cna", {}).get("metrics", [])
            adp_entries = containers.get("adp", [])
            adp_metrics = []
            for entry in adp_entries:
                adp_metrics.extend(entry.get("metrics", []))

            all_metrics.extend(cna_metrics)
            all_metrics.extend(adp_metrics)

            priority = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]

            for level in priority:
                for metric in all_metrics:
                    if level in metric:
                        data = metric[level]
                        score = data.get("baseScore")
                        if isinstance(score, (int, float)):
                            return score
            return 0
        except Exception:
            return 0
        
    def extract_lifecycle(api: dict) -> str:
        try:
            containers = api.get("containers", {})

            # --- Check for CISA KEV in ADP timeline ---
            adp_entries = containers.get("adp", [])
            for adp in adp_entries:
                for tl in adp.get("timeline", []):
                    if "CISA KEV" in tl.get("value", "").upper():
                        return "Added to CISA KEV"
                for ref in adp.get('references',[]):
                    if "cisa.gov/known-exploited-vulnerabilities-catalog" in ref.get('url',''):
                        return "Added to CISA KEV"
                for metric in adp.get("metrics", []):
                    print(metric.get("other",{}).get("type", "").upper())
                    if "KEV" in metric.get("other",{}).get("type", "").upper():
                        return "Added to CISA KEV"
                
            # --- Check for exploit or PoC indicators in references ---
            references = containers.get("cna", {}).get("references", [])
            for ref in references:
                tags = [t.lower() for t in ref.get("tags", [])]
                if any(tag in tags for tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"]):
                    return "Exploitation available"

            # --- Check for ADP metrics exploitation hints ---
            for adp in adp_entries:
                for metric in adp.get("metrics", []):
                    content = metric.get("other", {}).get("content", {})
                    if isinstance(content, dict):
                        for opt in content.get("options", []):
                            if "Exploitation" in opt and opt["Exploitation"].lower() in ["poc", "active"]:
                                return "Exploitation available"

            # --- If CVE has publication date but no exploit ---
            if api.get("cveMetadata", {}).get("datePublished"):
                return "Disclosure"

            # --- 5️⃣ Default fallback ---
            return None

        except Exception:
            return None
        
    def extract_affected(api: dict) -> dict:
        affected_data = {}

        try:
            affected_entries = api.get("containers", {}).get("cna", {}).get("affected", [])
            for entry in affected_entries:
                vendor = entry.get("vendor", "Unknown Vendor").strip()
                product = entry.get("product", "Unknown Product").strip()
                versions = entry.get("versions", [])

                affected_versions = []
                fixed_versions = []

                for ver in versions:
                    status = ver.get("status", "").lower()
                    version = ver.get("version")
                    if not version:
                        continue
                    if status == "affected":
                        affected_versions.append(version)
                    elif status in ["fixed", "patched", "unaffected"]:
                        fixed_versions.append(version)

                product_entry = {
                    "product": product,
                    "affected_versions": affected_versions,
                    "fixed_versions": fixed_versions
                }

                # Append under vendor key
                if vendor not in affected_data:
                    affected_data[vendor] = []
                affected_data[vendor].append(product_entry)

            return affected_data or {}

        except Exception:
            return {}
        
    def extract_date_published(api: dict) -> str:
        try:
            return api.get("cveMetadata", {}).get("datePublished", "")
        except Exception:
            return ""

    def extract_description(api: dict) -> str:
        try:
            descs = api.get("containers", {}).get("cna", {}).get("descriptions", [])
            # Prefer 'en-US' first
            for lang in ["en-US", "en"]:
                for d in descs:
                    if d.get("lang") == lang and d.get("value"):
                        return d["value"]
            # Fallback: first available
            if descs:
                return descs[0].get("value", "")
            return ""
        except Exception:
            return ""
            
    def extract_urls(api: dict) -> list:
        urls = []
        try:
            references = api.get("containers", {}).get("cna", {}).get("references", [])
            for ref in references:
                url = ref.get("url")
                if not url:
                    continue
                tags = [t.lower() for t in ref.get("tags", [])]
                # Skip PoC/exploit/issue-tracking
                if any(tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"] for tag in tags):
                    continue
                if url not in urls:
                    urls.append(url)
            return urls
        except Exception:
            return []

    def extract_exploits(api: dict) -> list:
        exploits = []
        try:
            references = api.get("containers", {}).get("cna", {}).get("references", [])
            for ref in references:
                url = ref.get("url")
                if not url:
                    continue
                tags = [t.lower() for t in ref.get("tags", [])]
                if any(tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"] for tag in tags):
                    if url not in exploits:
                        exploits.append(url)
            return exploits if exploits else None
        except Exception:
            return None
    res = {
        'cve_id':cve,
        'cwe':extract_cwe(data),
        'cvss':extract_cvss(data),
        'epss':None,
        'lifecycle':extract_lifecycle(data),
        'date_published':extract_date_published(data),
        'description':extract_description(data),
        'affected':extract_affected(data),
        'urls':extract_urls(data),
        'exploit':extract_exploits(data)
    }
    return res

def wizScraper(cve):
    # url = f"https://cve.org/CVERecord?id={cve}"
    url = f"https://www.wiz.io/vulnerability-database/cve/{cve.lower()}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.text
    soup = BeautifulSoup(data,'html.parser')
    text = soup.get_text(" ",strip=True)
    
    def extract_cvss(text: str) -> float:
        try:
            # Look for things like "CVSS 9.8" or "CVSS Score: 7.5"
            matches = re.findall(r"CVSS[^0-9]*([0-9]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
            scores = [float(s) for s in matches if 0.0 <= float(s) <= 10.0]
            return max(scores) if scores else 0.0
        except Exception:
            return 0.0
    
    res = {
        'cve_id':cve,
        'cwe':None,
        'cvss':extract_cvss(data),
    #     'epss':'n/a',
    #     'lifecycle':extract_lifecycle(data),
    #     'date_published':extract_date_published(data),
    #     'description':extract_description(data),
    #     'affected':extract_affected(data),
    #     'urls':extract_urls(data),
    #     'exploit':extract_exploits(data)
    }
    return res

def nvdapiScraper(cve):
    # url = f"https://cveawg.mitre.org/api/cve/{cve}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()

    def extract_cwe_id(api):
        cwe_id = None
        try : 
            weaknesses = api.get('vulnerabilities',{})[0].get('cve',{}).get('weaknesses',[])
        except IndexError: return None
        cwe_ids = list(set(re.findall(r"CWE\-(\d+)",str(weaknesses))))
        if len(cwe_ids)>0 : cwe_id = cwe_ids[-1]
        return cwe_id
        
    def extract_cvss(api):
        cvss = None
        try : 
            metrics =  api.get('vulnerabilities',{})[0].get('cve',{}).get('metrics',{})
            latestcvssversion = [cvssV for cvssV in metrics.keys() if str(cvssV).startswith('cvssMetricV')][0]
            cvss = metrics[latestcvssversion][0].get('cvssData',{}).get('baseScore',None)
        except IndexError: return None
        return cvss
    
    def extract_lifecycle(api):
        if IsInCISAKEV(cve):
            return "Added to CISA KEV"
        try :
            references =  api.get('vulnerabilities',{})[0].get('cve',{}).get('references',[])
            # tags = [ref.get("tags", '').lower() for ref in references]
            tags = [tag.lower() for ref in references for tag in ref.get('tags',[])]
            urls = [ref.get('url',"") for ref in references]
            if any(tag in tags for tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"]):
                return "Exploitation available"
            if any(word in urli for urli in urls for word in ["exploit", "poc", "proof-of-concept", "issue-tracking","writeups","sploit","packetstormsecurity"]):
                return "Exploitation available"
            if 'published' in api.get('vulnerabilities',{})[0].get('cve',{}).keys():
                return "Disclosure"
        except IndexError:
            return None
    
    def extract_date_published(data):
        try :
            res = data.get('vulnerabilities')[0].get('cve',{}).get('published',None)
        except IndexError:
            return None
        if res != None:
            res=res[:-4]+'Z'
        return res
    
    def extract_description(data):
        try :
            descriptions = data.get('vulnerabilities')[0].get('cve',{}).get('descriptions',[])
            english_description_list = itemCrawler(descriptions,['lang'],'en')
            if len(english_description_list)>0:
                res = english_description_list[0].get('value',None)
            else:
                return None
        except IndexError:
            return None
        return res
    
    def extract_affected(data):
        res = {}
        try :
            cpes = data.get('vulnerabilities')[0].get('cve',{}).get('configurations',[])[0].get('nodes',[])[0].get('cpeMatch',[])
            for cpe in cpes:
                criteria = cpe.get('criteria')
                vendor = criteria.split(':')[3].replace('_',' ').capitalize()
                product = criteria.split(':')[4].replace('_',' ').capitalize()
                vfix = cpe.get('versionEndExcluding',None)
                vaffected = f'before {vfix}' if vfix else None
                item = {'product':product,'affected_version':vaffected,'fixed_versions':vfix}
                if vendor in res:
                    res[vendor].append(item)
                else:
                    res[vendor] = [item]
        except IndexError:
            return None
        return res        
        
    def extract_urls(data):
        try :
            references =  data.get('vulnerabilities',{})[0].get('cve',{}).get('references',[])
            return [ref.get('url',None) for ref in references]
        except IndexError:
            return None
    
    def extract_exploit(data):
        all_exploit_url = None
        try :
            exploit_tagged_url = []
            exploit_worded_url = []
            references =  data.get('vulnerabilities',{})[0].get('cve',{}).get('references',[])
            exploit_tagged_url = []
            for ref in references:
                if any(tag.lower() in [lowertag.lower() for lowertag in ref.get('tags',[])] for tag in ["exploit", "poc", "proof-of-concept", "issue-tracking"]):
                    exploit_tagged_url.append(ref.get('url',None))
                if any(word in ref.get('url','') for word in ["exploit", "poc", "proof-of-concept","proofofconcept", "issue-tracking","writeups","sploit","packetstormsecurity"]) and '
cisa.gov
' not in ref.get('url',''):
                    exploit_worded_url.append(ref.get('url',None))
            all_exploit_url = list(set(exploit_tagged_url + exploit_worded_url))
            # urls = [ref.get('url','') for ref in references]
            # if any(word in urli for urli in urls for word in ["exploit", "poc", "proof-of-concept", "issue-tracking","writeups","sploit","packetstormsecurity"]):
            #     return "Exploitation available"
            # print(exploit_tagged_url)
        except IndexError:
            return None
        return all_exploit_url
        
    res = {
        'cve_id':cve,
        'cwe':unescape(get_mitre_cwe_name(extract_cwe_id(data))),
        'cvss':extract_cvss(data),
        'epss':None,
        'lifecycle':extract_lifecycle(data),
        'date_published':extract_date_published(data),
        'description':extract_description(data),
        'affected':extract_affected(data),
        'urls':extract_urls(data),
        'exploit':extract_exploit(data)
    }
    return res
    



def display_vuln(vuln_item):
    return f"{vuln_item['cve_id']} ({vuln_item['cvss']}) - {vuln_item['cwe']} [{vuln_item['lifecycle']}]\n{vuln_item['description']}"

if __name__ == "__main__":
    if len(sys.argv)<1 or not sys.argv[1].startswith('CVE-'):
        print("Need CVE ID arg")
    else:
        cve = str(sys.argv[1]).upper()
    oui = cveorgScraper(cve)
    # oui = wizScraper(cve)

    print(json.dumps(oui,indent=4))
    
    non = nvdapiScraper(cve)
    print(json.dumps(non,indent=4))
    # print(display_vuln(oui))
    # oui = vulmonScrapper(cve)
    # print("Affected Techs:")
    # print(oui["affectedTechs"])
    # print("Mitigations and workarounds:")
    # print(oui["mitigationAndWorkarounds"])
