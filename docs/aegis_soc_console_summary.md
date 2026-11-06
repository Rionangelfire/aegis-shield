### Mobile-Friendly Summary: aegis_soc_console.html

**Purpose**
- Browser-based **Security Operations Center (SOC)** dashboard for Aegis Shield.
- Connects to the live telemetry engine and displays security events in real time.

**Technology**
- HTML + JavaScript
- Tailwind CSS (via CDN)
- Server-Sent Events (SSE) for live streaming

**Layout**

#### Left Sidebar
Displays:
- Aegis Shield version
- System status
- Control parameters:
  - Veil Resonator
  - Apex Resonance
  - Harmonic Engine
- Session metrics:
  - Total Logs
  - Total Threats

#### Main Dashboard
Displays:
- Connection status
- MITRE T1486 monitor indicator
- Live telemetry feed

---

### Telemetry Integration

Connects directly to:

```javascript
http://localhost:8080/stream
```

using:

```javascript
const eventSource = new EventSource(
    'http://localhost:8080/stream'
);
```

When connected:

```text
DISCONNECTED
        ↓
LIVE // CONNECTED
```

Status changes from:

```text
INITIALIZING LISTENERS...
```

to:

```text
STREAMING TELEMETRY
```

---

### Event Processing

For every incoming telemetry record:

1. Parse JSON event
2. Increment total log count
3. Check severity
4. Increment threat count for:
   - ELEVATED
   - CRITICAL
5. Build and display an event card

---

### Severity Handling

#### INFO
Normal operating activity

Visual style:
- Standard slate colors

#### ELEVATED
Potential threat activity

Examples:
- Port scans
- Reconnaissance events

Visual style:
- Amber alerts

#### CRITICAL
Major security event

Examples:
- Ransomware detection
- High-priority incidents

Visual style:
- Red alert
- Pulsing animation

---

### Event Card Contents

Each card displays:

```text
Severity
Timestamp
Source IP
MITRE Tactic
Alert Message
Mitigation State
```

Example:

```text
CRITICAL
2026-11-05 18:20:01
IP: 192.168.1.77
TACTIC: TA0040

MITRE T1486:
Ransomware file encryption pattern detected

Mitigation State:
ACTION REQUIRED
```

---

### Architecture

```text
telemetry_engine.py
        │
        ▼
localhost:8080/stream
        │
        ▼
Server-Sent Events (SSE)
        │
        ▼
aegis_soc_console.html
        │
        ▼
Live SOC Dashboard
```

### Bottom Line

This file is the **front-end SOC console** for Aegis Shield. It receives live security telemetry from the Python telemetry engine, tracks threat metrics, highlights elevated and critical events, and presents them in a professional SOC-style monitoring dashboard designed for demonstrations, training, and portfolio use.
