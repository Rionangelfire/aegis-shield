### Mobile-Friendly Summary: telemetry_engine.py (v2.3)

**Role**
- Acts as the **back-end telemetry simulator** for Aegis Shield.
- Generates and streams live cybersecurity events to the SOC dashboard.

**Server Details**
- Uses Python's built-in `HTTPServer`.
- Runs locally on:
  ```
  http://localhost:8080
  ```
- Exposes a streaming endpoint:
  ```
  /stream
  ```
- Profile selection, two ways:
  - CLI flag: `python telemetry_engine.py --profile ransomware`
  - HTTP query: `/stream?profile=powershell`
  - Unknown profile names fall back to `baseline`.

**Streaming Method**
- Uses **Server-Sent Events (SSE)**.
- Returns:
  ```
  Content-Type: text/event-stream
  ```
- Sends a new event every **2 seconds**.

**Threat Profiles (v2.3)**

| Profile | Severity | Description | MITRE Tactic / Technique |
|----------|----------|-------------|--------------------------|
| baseline | INFO | Standard HTTP GET / DNS query | TA0001 / T1078, T1016 |
| storm | ELEVATED / INFO | SYN port scan / ICMP sweep | TA0007 / T1046, T1595.002 |
| brute_force | ELEVATED | Failed-auth threshold exceeded | TA0006 / T1110.001 |
| powershell | CRITICAL | Obfuscated PowerShell execution | TA0002 / T1059.001 |
| cred_dump | CRITICAL | LSASS memory access attempt | TA0006 / T1003.001 |
| c2 | CRITICAL | Outbound C2 beaconing callback | TA0011 / T1071.001 |
| lateral | ELEVATED | SMB/PsExec execution vs controller | TA0008 / T1021.002 |
| ransomware | CRITICAL | Mass rename + entropy spike | TA0040 / T1486 |

`?profile=all` (or `storm_all`) mixes every profile into one stream.

**Structured Metadata (v2.3)**
Each generated alert carries:
- Severity, message, mitigation state
- MITRE tactic and technique (separate fields)
- Asset group
- Confidence score (0–100)
- Event ID (`AEG-YYYYMMDD-#####`)
- Host (from a fixed pool: WS-001, WS-004, SRV-DB-02, DC-01, APP-GW-03, FIN-WS-09)
- Random internal IP address (`192.168.1.x`)
- Current timestamp

**Example Output**
```json
{
  "severity": "CRITICAL",
  "message": "LSASS process memory access attempt by unverified service",
  "tactic": "TA0006",
  "technique": "T1003.001",
  "asset_group": "Domain-Controllers",
  "confidence": 98,
  "mitigated": false,
  "event_id": "AEG-20261105-15993",
  "host": "APP-GW-03",
  "ip": "192.168.1.202",
  "timestamp": "2026-11-05 18:27:19"
}
```

**Architecture Position**
```text
telemetry_engine.py v2.3
        │
        ▼
HTTP Server (localhost:8080)
        │
        ▼
/stream?profile=<name> (SSE)
        │
        ▼
aegis_soc_console.html
        │
        ▼
Live Threat Dashboard
```

**Bottom Line**
This file is the **live event generator** for Aegis Shield. It simulates normal traffic, reconnaissance, brute force, PowerShell execution, credential dumping, C2 beaconing, lateral movement, and ransomware incidents, then streams them as structured, MITRE-tagged telemetry to the SOC console for monitoring, demonstrations, and incident-response visualization.
