#!/usr/bin/env python3
"""
Security.txt Scanner Server
Start een lokale webserver met een UI om meerdere domeinen te scannen op security.txt.

Gebruik: python security_scanner_server.py
Open dan: http://localhost:8181 in je browser
"""

import json
import sys
import os
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT = 8181

# Standaard locaties waar security.txt kan staan
SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def check_security_txt(base_url: str, timeout: int = 10) -> dict:
    """Controleert een enkel domein op security.txt."""
    base_url = normalize_url(base_url)
    parsed = urlparse(base_url)
    domain = parsed.netloc or parsed.path
    
    result = {
        "domain": domain,
        "url": base_url,
        "found": False,
        "locations": [],
    }
    
    for path in SECURITY_TXT_PATHS:
        check_url = base_url + path
        location_result = {
            "path": path,
            "url": check_url,
            "status": None,
            "found": False,
            "content": None,
            "content_type": None,
            "size": 0,
            "error": None,
            "validation": {},
        }
        
        try:
            response = requests.get(
                check_url,
                headers=HEADERS,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            
            location_result["status"] = response.status_code
            location_result["final_url"] = response.url
            
            if response.status_code == 200:
                content = response.text.strip()
                if content:
                    location_result["found"] = True
                    location_result["content"] = content
                    location_result["content_type"] = response.headers.get("Content-Type", "")
                    location_result["size"] = len(content)
                    result["found"] = True
                    result["content"] = content
                    result["content_url"] = response.url
                    
                    # Validatie
                    content_lower = content.lower()
                    validation = {}
                    validation["contact"] = "contact:" in content_lower
                    validation["expires"] = "expires:" in content_lower
                    validation["encryption"] = "encryption:" in content_lower
                    validation["acknowledgments"] = "acknowledgments:" in content_lower
                    validation["policy"] = "policy:" in content_lower
                    validation["hiring"] = "hiring:" in content_lower
                    location_result["validation"] = validation
                    
            elif response.status_code in [301, 302, 307, 308]:
                location_result["error"] = f"Redirect naar {response.url}"
                # Probeer de redirect te volgen
                try:
                    redir_resp = requests.get(
                        response.url,
                        headers=HEADERS,
                        timeout=timeout,
                        verify=False,
                    )
                    if redir_resp.status_code == 200 and redir_resp.text.strip():
                        content = redir_resp.text.strip()
                        location_result["found"] = True
                        location_result["content"] = content
                        location_result["content_type"] = redir_resp.headers.get("Content-Type", "")
                        location_result["size"] = len(content)
                        location_result["final_url"] = redir_resp.url
                        result["found"] = True
                        result["content"] = content
                        result["content_url"] = redir_resp.url
                        location_result["error"] = None
                        
                        content_lower = content.lower()
                        validation = {}
                        validation["contact"] = "contact:" in content_lower
                        validation["expires"] = "expires:" in content_lower
                        validation["encryption"] = "encryption:" in content_lower
                        validation["acknowledgments"] = "acknowledgments:" in content_lower
                        validation["policy"] = "policy:" in content_lower
                        validation["hiring"] = "hiring:" in content_lower
                        location_result["validation"] = validation
                except requests.RequestException:
                    location_result["error"] = f"Redirect kon niet gevolgd worden"
            elif response.status_code == 403:
                location_result["error"] = "Toegang geweigerd (403)"
            elif response.status_code == 404:
                location_result["error"] = "Niet gevonden (404)"
            else:
                location_result["error"] = f"Status {response.status_code}"
                
        except requests.exceptions.SSLError:
            location_result["error"] = "SSL Fout"
        except requests.exceptions.ConnectionError:
            location_result["error"] = "Verbindingsfout - host niet bereikbaar"
        except requests.exceptions.Timeout:
            location_result["error"] = "Time-out"
        except requests.exceptions.RequestException as e:
            location_result["error"] = str(e)
        
        result["locations"].append(location_result)
    
    return result


class ScannerHandler(BaseHTTPRequestHandler):
    """HTTP request handler voor de scanner."""
    
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.serve_html()
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == "/api/scan":
            self.handle_scan()
        else:
            self.send_error(404)
    
    def serve_html(self):
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_scanner.html")
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except FileNotFoundError:
            self.send_error(500, "security_scanner.html niet gevonden")
    
    def handle_scan(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body.decode("utf-8"))
            domains = data.get("domains", [])
            timeout = data.get("timeout", 10)
            
            if not domains:
                self.send_json({"error": "Geen domeinen opgegeven"}, 400)
                return
            
            # Beperk aantal domeinen
            if len(domains) > 50:
                self.send_json({"error": "Maximaal 50 domeinen tegelijk"}, 400)
                return
            
            results = []
            for domain in domains:
                domain = domain.strip()
                if domain and not domain.startswith("#"):
                    result = check_security_txt(domain, timeout=timeout)
                    results.append(result)
            
            self.send_json({"results": results})
            
        except json.JSONDecodeError:
            self.send_json({"error": "Ongeldige JSON"}, 400)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def send_json(self, data, status=200):
        content = json.dumps(data, ensure_ascii=False, indent=2)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))
    
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    server = HTTPServer(("127.0.0.1", PORT), ScannerHandler)
    print(f"\n🔒 Security.txt Scanner Server")
    print(f"{'=' * 40}")
    print(f"🌐 Server gestart op: http://localhost:{PORT}")
    print(f"📂 Scannen van meerdere domeinen op security.txt")
    print(f"{'=' * 40}")
    print(f"\n📌 Open je browser en ga naar: http://localhost:{PORT}")
    print(f"   Druk op Ctrl+C om de server te stoppen\n")
    
    # Open browser automatisch
    threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Server gestopt.")
        server.server_close()


if __name__ == "__main__":
    main()