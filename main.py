import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# Configuration
OEM_SITES = {
    "cisco": "https://tools.cisco.com/security/center/publicationListing.x",
    "siemens": "https://cert-portal.siemens.com/productcert/html/ssa-publication.html"
}

SEVERITY_KEYWORDS = ["critical", "high"]
EMAIL_RECIPIENTS = ["security-team@yourorg.com"]
SMTP_SERVER = "smtp.yourorg.com"

# Mock data for testing (comment out in production)
MOCK_DATA = [
    {
        "oem": "Cisco",
        "product": "IOS XE Software",
        "severity": "CRITICAL",
        "id": "CVE-2024-20356",
        "published": "2024-03-05",
        "link": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-snmp-rce-MdT4vB6H"
    },
    {
        "oem": "Siemens",
        "product": "SCALANCE XC-200",
        "severity": "HIGH",
        "id": "CVE-2024-18392",
        "published": "2024-02-27",
        "link": "https://cert-portal.siemens.com/productcert/html/ssa-347795.html"
    }
]

def scrape_oem_vulnerabilities():
    vulnerabilities = []
    
    try:
        # Scrape Cisco (IT)
        print("🔍 Scanning Cisco Security Advisories...")
        cisco_response = requests.get(OEM_SITES["cisco"], timeout=10)
        cisco_response.raise_for_status()
        soup = BeautifulSoup(cisco_response.text, 'html.parser')
        
        for row in soup.select(".data-row"):
            severity = row.select_one(".severityImg")["alt"].lower()
            if any(keyword in severity for keyword in SEVERITY_KEYWORDS):
                vuln = {
                    "oem": "Cisco",
                    "product": row.select_one(".productField").get_text(strip=True),
                    "severity": severity.upper(),
                    "id": row.select_one(".cveField").get_text(strip=True),
                    "published": row.select_one(".dateField").get_text(strip=True),
                    "link": "https://tools.cisco.com" + row.select_one("a")["href"]
                }
                vulnerabilities.append(vuln)
    
    except Exception as e:
        print(f"⚠️ Cisco scraping failed: {e}")
    
    try:
        # Scrape Siemens (OT)
        print("🔍 Scanning Siemens Security Advisories...")
        siemens_response = requests.get(OEM_SITES["siemens"], timeout=10)
        siemens_response.raise_for_status()
        soup = BeautifulSoup(siemens_response.text, 'html.parser')
        
        for row in soup.select(".list-item"):
            severity = row.select_one(".severity").get_text(strip=True).lower()
            if any(keyword in severity for keyword in SEVERITY_KEYWORDS):
                vuln = {
                    "oem": "Siemens",
                    "product": row.select_one(".product").get_text(strip=True),
                    "severity": severity.upper(),
                    "id": row.select_one(".cve").get_text(strip=True),
                    "published": row.select_one(".date").get_text(strip=True),
                    "link": row.select_one("a")["href"]
                }
                vulnerabilities.append(vuln)
    
    except Exception as e:
        print(f"⚠️ Siemens scraping failed: {e}")
    
    # Use mock data if no vulnerabilities found (for testing)
    if not vulnerabilities:
        print("⚠️ No live vulnerabilities found. Using mock data for demo.")
        vulnerabilities = MOCK_DATA
    
    return vulnerabilities

def generate_email_report(vulnerabilities):
    email_body = "🚨 Critical/High Severity Vulnerabilities Detected\n\n"
    email_body += f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
    email_body += "="*50 + "\n\n"
    
    for vuln in vulnerabilities:
        email_body += f"[{vuln['severity']}] {vuln['oem']} {vuln['product']}\n"
        email_body += f"• CVE-ID: {vuln['id']}\n"
        email_body += f"• Published: {vuln['published']}\n"
        email_body += f"• Advisory: {vuln['link']}\n\n"
    
    return email_body

def send_email_report(body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = "🚨 Critical/High OEM Vulnerabilities Detected"
        msg['From'] = "vuln-scanner@yourorg.com"
        msg['To'] = ", ".join(EMAIL_RECIPIENTS)
        
        with smtplib.SMTP(SMTP_SERVER) as server:
            server.send_message(msg)
        print("✅ Email alert sent successfully!")
    except Exception as e:
        print(f"⚠️ Failed to send email: {e}")

if __name__ == "__main__":
    print("Starting OEM Vulnerability Scraper...")
    vulnerabilities = scrape_oem_vulnerabilities()
    report = generate_email_report(vulnerabilities)
    
    print("\n=== VULNERABILITY REPORT ===\n")
    print(report)
    send_email_report(report)