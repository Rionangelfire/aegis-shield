# portfolio/aegis-shield/telemetry_engine.py
import json
import random
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

THREAT_SCENARIOS = [
    {"severity": "INFO", "message": "Standard packet flow - baseline nominal", "mitigated": True, "tactic": "TA0001"},
    {"severity": "ELEVATED", "message": "Port scan detected from remote host", "mitigated": True, "tactic": "TA0007"},
    {"severity": "CRITICAL", "message": "MITRE T1486: Ransomware file encryption pattern detected", "mitigated": False, "tactic": "TA0040"}
]

class TelemetryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            while True:
                event_data = random.choice(THREAT_SCENARIOS)
                event_data["ip"] = f"192.168.1.{random.randint(10, 254)}"
                event_data["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                
                payload = f"data: {json.dumps(event_data)}\n\n"
                self.wfile.write(payload.encode('utf-8'))
                self.wfile.flush()
                time.sleep(3)

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), TelemetryHandler)
    print("[+] Aegis Telemetry Engine running on http://localhost:8080/stream")
    server.serve_forever()
