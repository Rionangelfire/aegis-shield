### Mobile-Friendly Summary: telemetry_engine.py

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

**Streaming Method**
- Uses **Server-Sent Events (SSE)**.
- Returns:
  ```
  Content-Type: text/event-stream
  ```
- Sends a new event every **3 seconds**.

**Built-In Threat Profiles**

| Severity | Description | Mitigated | MITRE Tactic |
|----------|-------------|-----------|--------------|
| INFO | Standard packet flow (normal activity) | Yes | TA0001 |
| ELEVATED | Port scan detected | Yes | TA0007 |
| CRITICAL | MITRE T1486 ransomware behavior detected | No | TA0040 |

**Event Enrichment**
Each generated alert is automatically assigned:
- Random internal IP address (`192.168.1.x`)
- Current timestamp
- Severity
- Alert message
- Mitigation state
- MITRE tactic identifier

**Example Output**
```json
{
  "severity": "CRITICAL",
  "message": "MITRE T1486: Ransomware file encryption pattern detected",
  "mitigated": false,
  "tactic": "TA0040",
  "ip": "192.168.1.77",
  "timestamp": "2026-11-05 18:18:00"
}
```

**Architecture Position**
```text
telemetry_engine.py
        │
        ▼
HTTP Server (localhost:8080)
        │
        ▼
/stream (SSE)
        │
        ▼
aegis_soc_console.html
        │
        ▼
Live Threat Dashboard
```

**Bottom Line**
This file is the **live event generator** for Aegis Shield. It simulates normal traffic, reconnaissance activity, and ransomware incidents, then streams them in real time to the SOC console for monitoring, demonstrations, and incident-response visualization.
