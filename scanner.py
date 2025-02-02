import requests
from bs4 import BeautifulSoup

# Set Password for Access
PASSWORD = "demon001@"

def check_sql_injection(url):
    payloads = ["'", '"', "' OR '1'='1", "' OR '1'='1' --", "'; DROP TABLE users; --"]
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"[!] SQL Injection Vulnerability Found: {test_url}")
            return
    print("[-] No SQL Injection Found.")

def check_xss(url):
    payloads = ['<script>alert("XSS")</script>', '"><script>alert("XSS")</script>']
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        
        if payload in response.text:
            print(f"[!] XSS Vulnerability Found: {test_url}")
            return
    print("[-] No XSS Found.")

def check_directory_listing(url):
    response = requests.get(url)
    if "Index of /" in response.text:
        print(f"[!] Open Directory Listing Found: {url}")
    else:
        print("[-] No Open Directories.")

def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    
    missing_headers = []
    required_headers = ["X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options", "Strict-Transport-Security"]
    
    for header in required_headers:
        if header not in headers:
            missing_headers.append(header)
    
    if missing_headers:
        print(f"[!] Missing Security Headers: {', '.join(missing_headers)}")
    else:
        print("[+] All Security Headers Present.")

def check_server_info(url):
    response = requests.get(url)
    server = response.headers.get("Server", "Unknown")
    print(f"[+] Server Info: {server}")

def main():
    print("\n[+] Welcome to Secure Web Scanner")
    user_password = input("Enter Password to Continue: ")
    
    if user_password != PASSWORD:
        print("[-] Incorrect Password! Access Denied.")
        return
    
    target = input("\nEnter target URL (with http/https): ")
    
    if not target.startswith("http"):
        print("[!] Invalid URL format. Include http:// or https://")
        return
    
    print("\n[+] Scanning for vulnerabilities...\n")
    check_sql_injection(target)
    check_xss(target)
    check_directory_listing(target)
    check_security_headers(target)
    check_server_info(target)
    print("\n[+] Scan Complete.")

if __name__ == "__main__":
    main()