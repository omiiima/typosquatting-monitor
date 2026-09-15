import requests
import dns.resolver
import ssl, os
import socket
from bs4 import BeautifulSoup

VT_API_KEY = os.getenv("VT_API_KEY") 

def resolve_dns(domain):
    result = {"exists": False, "A": None, "MX": None, "NS": None}

    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=2)
        result["exists"] = True
        result["A"] = [r.to_text() for r in answers]
    except:
        return result

    try:
        mx = dns.resolver.resolve(domain, "MX")
        result["MX"] = [r.to_text() for r in mx]
    except:
        pass

    try:
        ns = dns.resolver.resolve(domain, "NS")
        result["NS"] = [r.to_text() for r in ns]
    except:
        pass

    return result

from requests.exceptions import SSLError

def get_http_status(domain):
    result = {
        "http_code": None,
        "https_code": None,
        "final_url": None,
        "ssl_verify_failed": False   # new field
    }

    try:
        r = requests.get(f"http://{domain}", timeout=3)
        result["http_code"] = r.status_code
        result["final_url"] = r.url
    except:
        pass

    try:
        # try WITH verification first
        r = requests.get(f"https://{domain}", timeout=3)
        result["https_code"] = r.status_code
        result["final_url"] = r.url
    except SSLError:
        # verification failed — that's a signal, not just noise
        result["ssl_verify_failed"] = True
        try:
            r = requests.get(f"https://{domain}", timeout=3, verify=False)
            result["https_code"] = r.status_code
            result["final_url"] = r.url
        except:
            pass
    except:
        pass

    return result

def get_html_title(domain):
    try:
        r = requests.get(f"http://{domain}", headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True, timeout=3)
        soup = BeautifulSoup(r.text, "html.parser")
        if soup.title:
            return soup.title.string.strip()
    except:
        pass

    return None


def get_ssl_certificate_info(domain):
    result = {"issuer": None, "subject": None}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()

            result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            result["subject"] = dict(x[0] for x in cert.get("subject", []))

    except:
        pass

    return result


def check_virustotal(domain):
    if not VT_API_KEY:
        print("No VirusTotal API key found.")
        return None

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        r = requests.get(url, headers=headers, timeout=5)

        if r.status_code != 200:
            return None

        data = r.json()

        malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious_count = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        reputation = data["data"]["attributes"].get("reputation", 0)

        return {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "reputation": reputation
        }

    except Exception as e:
        print(f"[!] VT error for {domain}: {e}")
        return None

def compute_score(scan):
    score = 0

    if scan["dns"]["exists"]:
        score += 2

    if scan["http"]["http_code"] or scan["http"]["https_code"]:
        score += 3

    # NEW: broken/self-signed TLS is itself suspicious
    if scan["http"].get("ssl_verify_failed"):
        score += 3

    if scan["ssl"]["issuer"]:
        issuer_name = scan["ssl"]["issuer"].get("organizationName", "")
        if "Let's Encrypt" in issuer_name:
            score += 2
        if issuer_name == "":
            score += 2

    vt = check_virustotal(scan["domain"])
    if vt:
        score += vt["malicious"] * 5 + vt["suspicious"] * 2

    title = scan["title"] or ""
    for word in ["login", "verify", "secure", "update", "account"]:
        if word.lower() in title.lower():
            score += 3

    return score

def scan_domain(domain):
    dns_info = resolve_dns(domain)
    http_info = get_http_status(domain)
    title = get_html_title(domain)
    ssl_info = get_ssl_certificate_info(domain)

    result = { "domain": domain, "dns": dns_info, "http": http_info, "title": title, 
              "ssl": ssl_info,
              "score": None}

    result["score"] = compute_score(result)

    return result