import tkinter as tk
from tkinter import messagebox
import requests
import validators
import tldextract
import datetime
import json

# === API KEYS ===
VT_API_KEY = "52d67f7b41e6004b4d2c41b254b7c99d7a236c04bc48c98a6295c19f3e1b402c"
IPQS_API_KEY = "X0WYfFX9a76nmfBCWqjDUzNPbWyYjLfV"
WHOIS_API_KEY = "at_rXLb1FWYFRMZOSZHND0Ddn3ziqVO9"
SAFE_BROWSING_KEY = "AIzaSyCHwBdSkUYljqk4sh9TkmpRa5wJrUAZ4r4"

# === Known Brands ===
KNOWN_BRANDS = ["apple.com", "paypal.com", "google.com", "microsoft.com", "facebook.com", "amazon.com", "netflix.com"]

# === Check Functions ===

def is_valid_url(url):
    return validators.url(url)

def resolve_redirects(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        final_url = response.url
        if final_url != url:
            print(f"[INFO] Redirected to: {final_url}")
        return final_url
    except Exception as e:
        print(f"[!] Redirect resolution failed: {e}")
        return url

def check_brand_spoofing(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    for brand in KNOWN_BRANDS:
        brand_domain = brand.replace("www.", "")
        if brand_domain.split(".")[0] in url.lower() and domain != brand_domain:
            return True
    return False

def check_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    try:
        scan_res = requests.post(api_url, headers={"x-apikey": VT_API_KEY}, data={"url": url})
        scan_res.raise_for_status()
        url_id = scan_res.json()["data"]["id"]

        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_res = requests.get(report_url, headers={"x-apikey": VT_API_KEY})
        report_res.raise_for_status()
        data = report_res.json()["data"]["attributes"]
        malicious_count = data["last_analysis_stats"]["malicious"]
        if malicious_count > 0:
            return True, "⚠️ VirusTotal flagged this URL!"
    except Exception as e:
        return False, f"VT error: {e}"
    return False, "✓ VirusTotal OK"

def check_ipqs(url):
    try:
        res = requests.get(f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}", params={"url": url, "strictness": 1})
        res.raise_for_status()
        data = res.json()
        if data.get("unsafe"):
            return True, "⚠️ IPQualityScore flagged this URL!"
    except Exception as e:
        return False, f"IPQS error: {e}"
    return False, "✓ IPQS OK"

def check_whois(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    try:
        res = requests.get("https://www.whoisxmlapi.com/whoisserver/WhoisService", params={
            "apiKey": WHOIS_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        })
        res.raise_for_status()
        data = res.json()
        created_str = data.get("WhoisRecord", {}).get("createdDate", "")
        if created_str:
            created_date = datetime.datetime.strptime(created_str.split("T")[0], "%Y-%m-%d")
            age_days = (datetime.datetime.now() - created_date).days
            if age_days < 30:
                return True, f"⚠️ Domain is newly registered ({age_days} days old)"
    except Exception as e:
        return False, f"Whois error: {e}"
    return False, "✓ Domain age OK"

def check_safe_browsing(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        if response.json().get("matches"):
            return True, "⚠️ Google Safe Browsing flagged this URL!"
    except Exception as e:
        return False, f"GSB error: {e}"
    return False, "✓ Safe Browsing OK"

def check_https(url):
    try:
        parsed = requests.utils.urlparse(url)
        if parsed.scheme == "https":
            return False, "✓ HTTPS is enabled"
        else:
            return True, "⚠️ Site does not use HTTPS"
    except:
        return False, "✓ Could not parse HTTPS status"

# === Prediction Logic ===

def predict():
    input_url = url_entry.get().strip()
    if not input_url.startswith(("http://", "https://")):
        input_url = "http://" + input_url

    result_label.config(text="", fg="black")

    if not is_valid_url(input_url):
        result_label.config(text="❌ Invalid URL", fg="red")
        return

    url = resolve_redirects(input_url)

    if check_brand_spoofing(url):
        result_label.config(text="⚠️ Brand Spoofing Detected", fg="orange")
        return

    https_flag, https_msg = check_https(url)
    vt_flag, vt_msg = check_virustotal(url)
    ipqs_flag, ipqs_msg = check_ipqs(url)
    whois_flag, whois_msg = check_whois(url)
    gsb_flag, gsb_msg = check_safe_browsing(url)

    all_msgs = f"{https_msg}\n{vt_msg}\n{ipqs_msg}\n{whois_msg}\n{gsb_msg}"

    if any([https_flag, vt_flag, ipqs_flag, whois_flag, gsb_flag]):
        result_label.config(text=f"🚨 Suspicious URL Detected!\n\n{all_msgs}", fg="red")
    else:
        result_label.config(text=f"✅ Looks safe\n\n{all_msgs}", fg="green")

def clear_input():
    url_entry.delete(0, tk.END)
    result_label.config(text="", fg="black")

# === GUI Setup ===
root = tk.Tk()
root.title("Phishing Site Detector - API Powered")
root.geometry("500x450")

tk.Label(root, text="Enter URL:", font=("Arial", 12)).pack(pady=10)
url_entry = tk.Entry(root, width=60, font=("Arial", 10))
url_entry.pack(pady=5)

tk.Button(root, text="Check", command=predict, bg="blue", fg="white", font=("Arial", 11)).pack(pady=10)
tk.Button(root, text="Clear", command=clear_input, bg="gray", fg="white", font=("Arial", 10)).pack()

result_label = tk.Label(root, text="", font=("Arial", 12), wraplength=450, justify="left")
result_label.pack(pady=20)

root.mainloop()
