import os
import sys
import json
import requests
from tqdm import tqdm
import re
import datetime
from requests_html import HTMLSession
import argparse

session =  HTMLSession()

parser = argparse.ArgumentParser(
                    prog='FreeVulnWatch',
                    description='Analyses the CVEs in the file included in the parameters and gives and select the ones interesting'
                    )
parser.add_argument('-f','--filename',type=str,required=True, help= "The name of the file where you store the vulns you want to analyse")
parser.add_argument('-X','--filters',type=str,choices=["True","False"],default="True",help="If you want to filter the date/importance/vulnignore. Must be 'True' or 'False'. Default is True.")

args = parser.parse_args()

THEFILE = args.filename
FILTERS = args.filters == "True"
print(args.filters)

    
PATH = os.getcwd()

def get_content_of_js_page(url):
    response = session.get(url)
    response.html.render()
    return(response.html.html)
    

def get_CVSS_from_NVD(nvdcontent):
    regex = r"(\d\.?\d?) ([A-Z]{3,8})<\/a>"
    # regex = r"<article class=\"book\"><span class=\"number\">\#(\d)</span><img src=\".*?\" alt=\"(.*?)\">"
    found = re.findall(regex,nvdcontent)
    if found == []:
        res = "Product not Found"
    else :
        res = found[0]
    return res

#Fonction qui recupère l'integralité de la page NVD de la CVE en paramètre 
def get_CWE_from_NVD(nvdcontent):
    found = re.findall(r'\"vuln\-CWEs\-link\-\d\"\>(.+)\<',nvdcontent)
    res = ""
    if found == []:
        res = "CWE not found"
    else :
        res = found[-1]
    return res

def get_description_from_NVD(nvdcontent):
    regex = r"<p data\-testid=\"vuln\-description\">(.*?)<\/p>"
    try :
        description = re.findall(regex,nvdcontent)[0]
    except IndexError:
        description = ""
        print(f"NVD does not have infos on {cve}.")
        # sys.exit(-1)
    return description

def get_exploitation_state_from_inthewild(cve):
    url = "https://inthewild.io/vuln/"+cve
    inthewildcontent = requests.get(url).text
    regex = r"<dt class=\"css-yv1hg8\">Type\:<\/dt><dd class=\"css\-gwpoux\">(.*?)<\/dd>"
    exploitlink = ""
    try :
        exploitstate = list(set(re.findall(regex,inthewildcontent)))
        exploitation = "exploitation" in exploitstate
        exploitlink = "exploit" in exploitstate
        if re.findall(r"class=\"chakra\-link css\-14ttpe2\" href=\"https\:\/\/www\.cisa\.gov\/known\-exploited\-vulnerabilities\-catalog\">",inthewildcontent)!=[]:
            exploitation = "in CISA KEV"
        if exploitlink:
            exploitlink = re.findall(r"<dd class=\"css\-gwpoux\">exploit<.*?Reference url to background.*?href=(.*?)>",inthewildcontent)[0]
        else:
            exploitlink=""
        exploitstate = (exploitation,exploitlink)
    except IndexError:
        exploitstate = "Unknown"
    return exploitstate
    

def get_vulnerable_product_from_vulmon(cve):
    url = "https://vulmon.com/vulnerabilitydetails?qid="+cve
    response = requests.get(url)
    regex = r"<tr>\n\s*<td><p>(.*?)<\/p><\/td>"
    products = re.findall(regex,response.text)
    return products
    # description = re.findall(r"\<p data\-testid\=\"vuln\-description\"\>(.*?)\<\/p\>\<br\/\>",response.text)
    # try:
    #     res = description[0]
    # except IndexError:
    #     print(response.text)
    #     # test = re.findall('<pre>((.*\n*)*)<\/pre>',response.text)
    #     test = re.findall("vuln\-change\-history\-\d\-new\"\>\n\s*<pre.*?>((.*\n*)*)<\/pre>",response.text)
    #     print(test[0],cve)
    #     sys.exit(-3)
    #     res = ""
    # # description_pattern = re.compile(r'^\[\'(.*?)(?=(?:AV:[A-Z]+/AC:[A-Z]+|CWE-\d+|https?://\S+))', re.DOTALL) 
    # # match = description_pattern.search(str(description))
    # # if match: human_readable_part = match.group(1).strip()  
    # return res

#retrieve all cves in filename in argument
def get_vuln_in_file(filename,thisyearbool):
    with open(filename,'r') as vulnfilebuffer:
        oui = vulnfilebuffer.read()
    vulnfilebuffer.close()
    return list_this_year_cve(oui,thisyearbool)

#check in advisory tracker if theres on which cve_number matches the cve
def IsAdvisorySent(cveID,advisories):
    advisorySent = False
    return advisorySent

def list_this_year_cve(text,thisyearbool):
    #Filtering all CVE : this year
    if thisyearbool:
        thisYear = str(datetime.datetime.now().year)
    else:
        thisYear = r"\d{4}"
    regex = "CVE\-"+thisYear+"\-\d{4,5}"
    return re.findall(regex,text)

# build a list of tech from cve description
def check_technos_in_description(techstack, description):
    res = "No Product found"
    if description == None : description = ""
    lower_desc = description.lower()
    for tech in techstack:
        if tech.lower() in lower_desc:
            res = tech
    return res

def get_techstack():
    techstack=[]
    with open("technos",'r') as technobuffer:
        techstack = technobuffer.readlines()
    technobuffer.close()
    for i in range(len(techstack)):
        techstack[i] = techstack[i][:-1]
    return sorted(techstack,key=lambda k:len(k))

vulns = list(set(get_vuln_in_file(THEFILE,FILTERS)))
print(vulns)

with open("vulnignore","r") as f:
    vulnignore = list_this_year_cve(f.read(),FILTERS)
f.close()

#getting advisories from advisory tracker
advisories = []

techstack = get_techstack()

now = datetime.datetime.now()

print(f"Getting data for CVEs in file {THEFILE}")
prod_obj = {}
#For all CVEs
print("Gathering data over those CVEs ...")
for cve in tqdm(vulns):
    iter = 0
    nvdcontent = get_content_of_js_page("https://nvd.nist.gov/vuln/detail/"+cve)
    exploitstate = get_exploitation_state_from_inthewild(cve)
    cvss = get_CVSS_from_NVD(nvdcontent)
    oui = {
        'cve_id': cve,
        'CVSS':float(cvss[0]),
        'risk':cvss[1],
        'CWE':get_CWE_from_NVD(nvdcontent),
        'nvd_description':get_description_from_NVD(nvdcontent),
        'exploitation_state':exploitstate[0],
        'exploit_link':exploitstate[1]
        # 'affected_product':get_affected_products_from_cveorg(cve)
    }
    product = check_technos_in_description(techstack,oui['nvd_description'])

    advisorySent = IsAdvisorySent(cve,advisories)
    
    if FILTERS:
        interestingCVE = not advisorySent and ('note' in oui.keys() and oui['note']>=5) and product in techstack and cve not in vulnignore
    else:
        interestingCVE = True
    
    if interestingCVE:
        if product not in prod_obj.keys():
            prod_obj[product]=[]
        try :
            prod_obj[product].append({"cve":cve,"score":oui['CVSS'],"description":oui['nvd_description'],"cwe":oui['CWE'],"exploitation":oui["exploitation_state"],"exploit_link":oui["exploit_link"]})
        except KeyError:
            print(json.dumps(oui,indent=4))
            sys.exit(-2)

str_res = ""
for techno in prod_obj:
    prod_obj[techno] = sorted(prod_obj[techno],key=lambda k:k["score"],reverse=True)
    print("\n",techno.upper(),":\n\n")
    str_res += "\n"+techno.upper()+":\n\n"
    for cve in prod_obj[techno]:
        str_res+=f"{cve['cve']} ({cve['score']}) - {cve['cwe']} [ {cve['exploitation']} ]\n{cve['description']}\n"
        if cve["exploit_link"]!="":
            str_res += f"POC: {cve['exploit_link']}\n\n"
        else:
            str_res +="\n"

print(str_res)
with open("vulns-report.txt",'w') as f:
    f.write(str_res)
f.close()