# Aegis Shield 🛡️

A single-file mobile **IOC / SOC simulator** — built to practice detection, threshold tuning, and MITRE mapping with synthetic data.

## Modes

| Mode | What it simulates |
|---|---|
| **Baseline** | Normal traffic — 0 alerts |
| **Thunderstorm** | Loss bursts, SYN flood, possible DDoS — 3 alerts, 5,335 packets |
| **Ransomware** | 1 consolidated `RANSOMWARE_ENCRYPTION` alert |

## Detection

- **Thresholds:** 500 packets/sec, 5s loss burst, 10s window
- **MITRE ATT&CK:** T1498 (Network Denial of Service) and T1486 (Data Encrypted for Impact) — defensible mappings. T1499 is a prototype label only; T1046 is not implemented.
- **Containment:** the Auto-Isolate playbook button is labeled **SIMULATED** — this is a training tool, not a production control.
- **Data:** synthetic only. No real logs, no real hosts.

## In this repo

- `aegis-shield-portfolio.pdf` — the full demonstration portfolio (10 pages)
- Screenshots of all three modes: standby, storm, ransomware

The interactive single-file simulator will be added here when the source file is ready.

## Built by

Robert Bostick — CTU Online, B.S. Computer Science (cybersecurity focus), Hillsboro, Texas.
