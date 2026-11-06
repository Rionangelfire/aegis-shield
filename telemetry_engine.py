# portfolio/aegis-shield/telemetry_engine.py
import json
import random
import time
import sys
from urllib.parse import parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler

# ==========================================
# AEGIS SHIELD v2.3 - STRUCTURED METADATA CATALOG
# ==========================================
THREAT_CATALOG = {
    "baseline": [
        {
            "severity": "INFO", 
            "message": "Standard HTTP GET request processed", 
            "tactic": "TA0001", 
            "technique": "T1078", 
            "asset_group": "Web-Public", 
            "confidence": 100, 
            "mitigated": True
        },
        {
            "severity": "INFO", 
            "message": "DNS Query resolved successfully for internal domain", 
            "tactic": "TA0001", 
            "technique": "T1016", 
            "asset_group": "Infrastructure", 
            "confidence": 100, 
            "mitigated": True
        }
    ],
    "storm": [
        {
            "severity": "ELEVATED", 
            "message": "Sequential SYN port scan detected across internal subnet", 
            "tactic": "TA0007", 
            "technique": "T1046", 
            "asset_group": "Perimeter", 
            "confidence": 85, 
            "mitigated": True
        },
        {
            "severity": "INFO", 
            "message": "ICMP Echo request sweep observed", 
            "tactic": "TA0007", 
            "technique": "T1595.002", 
            "asset_group": "Perimeter", 
            "confidence": 80, 
            "mitigated": True
        }
    ],
    "brute_force": [
        {
            "severity": "ELEVATED", 
            "message": "Repeated failed authentication threshold exceeded (>10 attempts/sec)", 
            "tactic": "TA0006", 
            "technique": "T1110.001", 
            "asset_group": "Authentication", 
            "confidence": 94, 
            "mitigated": True
        }
    ],
    "powershell": [
        {
            "severity": "CRITICAL", 
            "message": "Obfuscated PowerShell payload execution detected via command line", 
            "tactic": "TA0002", 
            "technique": "T1059.001", 
            "asset_group": "Workstation-Finance", 
            "confidence": 92, 
            "mitigated": False
        }
    ],
    "cred_dump": [
        {
            "severity": "CRITICAL", 
            "message": "LSASS process memory access attempt by unverified service", 
            "tactic": "TA0006", 
            "technique": "T1003.001", 
            "asset_group": "Domain-Controllers", 
            "confidence": 98, 
            "mitigated": False
        }
    ],
    "c2": [
        {
            "severity": "CRITICAL", 
            "message": "Periodic outbound C2 beaconing callback detected to external destination", 
            "tactic": "TA0011", 
            "technique": "T1071.001", 
            "asset_group": "Core-Servers", 
            "confidence": 91, 
            "mitigated": False
        }
    ],
    "lateral": [
        {
            "severity": "ELEVATED", 
            "message": "Remote SMB/PsExec service execution targeting primary controller", 
            "tactic": "TA0008", 
            "technique": "T1021.002", 
            "asset_group": "Internal-Network", 
            "confidence": 88, 
            "mitigated": True
        }
    ],
    "ransomware": [
        {
            "severity": "CRITICAL", 
            "message": "Massive file system rename pattern and volume entropy spike detected", 
            "tactic": "TA0040", 
            "technique": "T1486", 
            "asset_group": "Storage-SAN", 
            "confidence": 99, 
            "mitigated": False
        }
    ]
}

HOST_POOL = ["WS-001", "WS-004", "SRV-DB-02", "DC-01", "APP-GW-03", "FIN-WS-09"]

def get_event_payload(profile_name):
    """
    Selects event payload, injecting structured metadata fields (event_id, host, timestamp).
    """
    key = profile_name.lower()
    
    if key in THREAT_CATALOG:
        pool = THREAT_CATALOG[key]
    elif key == "all" or key == "storm_all":
        pool = [item for sublist in THREAT_CATALOG.values() for item in sublist]
    else:
        pool = THREAT_CATALOG["baseline"]
        
    event = random.choice(pool).copy()
    
    # Inject v2.3 Structured Metadata Fields
    date_str = time.strftime("%Y%m%d")
    rand_id = random.randint(10000, 99999)
    event["event_id"] = f"AEG-{date_str}-{rand_id}"
    event["host"] = random.choice(HOST_POOL)
    event["ip"] = f"192.168.1.{random.randint(10, 254)}"
    event["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    return event


class TelemetryHandler(BaseHTTPRequestHandler):
    default_profile = "baseline"

    def do_GET(self):
        parsed_url = urlparse(self.path)
        
        if parsed_url.path == '/stream':
            query_params = parse_qs(parsed_url.query)
            selected_profile = query_params.get('profile', [TelemetryHandler.default_profile])[0]
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            print(f"[+] Client connected. Streaming v2.3 metadata profile: '{selected_profile.upper()}'")
            
            try:
                while True:
                    event_data = get_event_payload(selected_profile)
                    payload = f"data: {json.dumps(event_data)}\n\n"
                    self.wfile.write(payload.encode('utf-8'))
                    self.wfile.flush()
                    time.sleep(2)
            except (ConnectionResetError, BrokenPipeError):
                print("[-] Client disconnected.")

if __name__ == '__main__':
    for i, arg in enumerate(sys.argv):
        if arg == '--profile' and i + 1 < len(sys.argv):
            TelemetryHandler.default_profile = sys.argv[i + 1]
            
    print(f"==================================================")
    print(f" AEGIS SHIELD TELEMETRY ENGINE v2.3")
    print(f" Default Profile : {TelemetryHandler.default_profile.upper()}")
    print(f" Metadata Spec   : event_id, technique, host, confidence")
    print(f" Target Endpoint : http://localhost:8080/stream?profile=<name>")
    print(f"==================================================")
    
    server = HTTPServer(('localhost', 8080), TelemetryHandler)
    server.serve_forever()
