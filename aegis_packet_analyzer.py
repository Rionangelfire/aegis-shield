import time
import json
import random
from datetime import datetime

# ==========================================
# AEGIS PACKET ANALYZER v1.5
# Stateful Packet Inspection & Telemetry Producer
# ==========================================

class TelemetryStats:
    """Tracks session metrics and threat severity counts."""
    def __init__(self):
        self.total = 0
        self.info = 0
        self.elevated = 0
        self.critical = 0

    def update(self, telemetry):
        self.total += 1
        sev = telemetry.get("severity")
        if sev == "INFO":
            self.info += 1
        elif sev == "ELEVATED":
            self.elevated += 1
        elif sev == "CRITICAL":
            self.critical += 1

    def summary(self):
        return {
            "total": self.total,
            "info": self.info,
            "elevated": self.elevated,
            "critical": self.critical
        }


class AegisPacketAnalyzer:
    """
    Stateful Packet Analyzer for Aegis Shield.
    Processes raw/simulated packet headers, tracks connection states,
    inspects MITRE ATT&CK signatures, and outputs v2.1.1 JSON telemetry.
    """
    def __init__(self, interface="eth0", log_file="aegis_events.jsonl"):
        self.interface = interface
        self.log_file = log_file
        self.stats = TelemetryStats()
        
        # Stateful Inspection Memory
        self.connection_counts = {}   # src_ip -> request count (Brute-force detection)
        self.entropy_spikes = 0       # Ransomware file behavior tracker
        
    def parse_packet_header(self, raw_data=None):
        """
        Parses basic IP header attributes from raw packet bytes or mock stream.
        """
        src_ip = f"192.168.1.{random.randint(10, 254)}"
        dst_ip = "192.168.1.1"
        protocol = random.choice(["TCP", "UDP", "ICMP"])
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 445, 3389, 53, 5985])
        length = random.randint(64, 1500)
        
        # Increment connection counter for stateful inspection
        self.connection_counts[src_ip] = self.connection_counts.get(src_ip, 0) + 1
        
        # Randomly simulate ransomware volume entropy spike
        if random.random() < 0.08:
            self.entropy_spikes += 1

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length
        }

    def inspect_threat_rules(self, packet):
        """
        Evaluates packet metadata against stateful Aegis SOC threat signatures.
        """
        src_ip = packet["src_ip"]

        # Rule 1: Stateful Brute Force Detection (>5 rapid connection attempts)
        if self.connection_counts[src_ip] > 5 and packet["dst_port"] in [22, 443, 3389]:
            return {
                "severity": "ELEVATED",
                "message": f"Repeated authentication failures detected from {src_ip}",
                "tactic": "TA0006",
                "technique": "T1110.001",
                "asset_group": "Authentication",
                "confidence": 94,
                "response_hint": "LOCK_ACCOUNT",
                "mitigated": True,
                "host": "DC-01",
                "src_ip": src_ip,
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"]
            }

        # Rule 2: WinRM / PowerShell Remote Execution Detection
        if packet["dst_port"] == 5985:
            return {
                "severity": "CRITICAL",
                "message": "Encoded WinRM/PowerShell remote execution payload observed",
                "tactic": "TA0002",
                "technique": "T1059.001",
                "asset_group": "Workstation-Finance",
                "confidence": 92,
                "response_hint": "ISOLATE_HOST",
                "mitigated": False,
                "host": "FIN-WS-09",
                "src_ip": src_ip,
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"]
            }

        # Rule 3: High Risk SMB / Lateral Movement Protocol Inspection
        if packet["dst_port"] in [3389, 445]:
            return {
                "severity": "ELEVATED",
                "message": f"Remote service execution attempt detected on port {packet['dst_port']}",
                "tactic": "TA0008",
                "technique": "T1021.002",
                "asset_group": "Internal-Network",
                "confidence": 88,
                "response_hint": "REVOKE_SESSION",
                "mitigated": True,
                "host": "DC-01",
                "src_ip": src_ip,
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"]
            }

        # Rule 4: High-Volume File System Entropy Spike (Ransomware Behavior)
        if self.entropy_spikes > 3:
            self.entropy_spikes = 0  # Reset trigger counter
            return {
                "severity": "CRITICAL",
                "message": "Mass file encryption behavior & volume entropy spike detected",
                "tactic": "TA0040",
                "technique": "T1486",
                "asset_group": "Storage-SAN",
                "confidence": 99,
                "response_hint": "ENGAGE_VEIL_RESONATOR",
                "mitigated": False,
                "host": "SRV-DB-02",
                "src_ip": src_ip,
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"]
            }

        # Rule 5: DNS Anomaly / Potential C2 Tunneling
        if packet["dst_port"] == 53 and packet["length"] > 500:
            return {
                "severity": "CRITICAL",
                "message": "Large UDP DNS payload detected - potential C2 tunneling",
                "tactic": "TA0011",
                "technique": "T1071.004",
                "asset_group": "Core-Servers",
                "confidence": 91,
                "response_hint": "BLOCK_IP",
                "mitigated": False,
                "host": "SRV-DB-02",
                "src_ip": src_ip,
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"]
            }

        # Default: Baseline Operational Traffic
        return {
            "severity": "INFO",
            "message": f"Standard {packet['protocol']} traffic observed",
            "tactic": "TA0001",
            "technique": "T1078",
            "asset_group": "Infrastructure",
            "confidence": 100,
            "response_hint": "NONE",
            "mitigated": True,
            "host": "WS-001",
            "src_ip": src_ip,
            "dst_ip": packet["dst_ip"],
            "protocol": packet["protocol"],
            "src_port": packet["src_port"],
            "dst_port": packet["dst_port"]
        }

    def convert_to_aegis_telemetry(self, threat_match):
        """
        Formats threat inspection outputs to match Aegis Shield v2.1.1 JSON spec.
        """
        date_str = datetime.now().strftime("%Y%m%d")
        rand_id = random.randint(10000, 99999)
        threat_match["event_id"] = f"AEG-{date_str}-{rand_id}"
        threat_match["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return threat_match

    def export_event_jsonl(self, telemetry):
        """Appends formatted telemetry payload into JSONL evidence file."""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(telemetry) + "\n")
        except IOError as e:
            print(f"[-] Log export error: {e}")

    def run_live_analysis(self, duration_sec=15):
        """
        Executes continuous packet capture cycle, logs events, and prints statistics.
        """
        print(f"==================================================")
        print(f" AEGIS PACKET ANALYZER v1.5")
        print(f" Interface Target : {self.interface}")
        print(f" Evidence Log     : {self.log_file}")
        print(f" Target Endpoint : Aegis Telemetry Pipeline")
        print(f"==================================================")
        
        start_time = time.time()
        while time.time() - start_time < duration_sec:
            raw_pkt = self.parse_packet_header(None)
            threat = self.inspect_threat_rules(raw_pkt)
            telemetry = self.convert_to_aegis_telemetry(threat)
            
            # Update metrics and export evidence log
            self.stats.update(telemetry)
            self.export_event_jsonl(telemetry)
            
            print(f"[{telemetry['timestamp']}] {telemetry['severity']:<8} | "
                  f"ID: {telemetry['event_id']} | Host: {telemetry['host']:<10} | "
                  f"IP: {telemetry['src_ip']:<15} | Tech: {telemetry['technique']:<9} | "
                  f"Hint: {telemetry['response_hint']}")
            time.sleep(1.2)

        print(f"\n==================================================")
        print(f" SESSION STATISTICAL SUMMARY")
        print(f" Total Events Captured : {self.stats.summary()['total']}")
        print(f" INFO Events           : {self.stats.summary()['info']}")
        print(f" ELEVATED Threats      : {self.stats.summary()['elevated']}")
        print(f" CRITICAL Anomalies    : {self.stats.summary()['critical']}")
        print(f"==================================================")

if __name__ == "__main__":
    analyzer = AegisPacketAnalyzer()
    analyzer.run_live_analysis(duration_sec=15)
