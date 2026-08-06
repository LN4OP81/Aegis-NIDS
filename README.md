# Aegis NIDS

> **A multi-layer, real-time Network Intrusion Detection System that combines signature detection, protocol anomaly analysis, behavioral machine learning, and attack correlation for intelligent threat detection.**

Aegis NIDS is a Python-based Network Intrusion Detection System built to monitor live network traffic and detect malicious activity using multiple complementary detection techniques. Instead of relying solely on static signatures, Aegis combines protocol inspection, statistical analysis, behavioral anomaly detection, and attack correlation to identify both known and previously unseen network threats.

---

# Features

- 📡 Real-time packet capture using Scapy
- 🛡️ Multi-layer hybrid intrusion detection architecture
- 🧠 Per-device behavioral anomaly detection using Isolation Forest
- 🔍 Protocol anomaly analysis and TCP flag inspection
- ⚡ Signature detection for common network attacks
- 🔗 Temporal attack-correlation engine for multi-stage attack detection
- 📊 Interactive Streamlit dashboard with live traffic visualization
- 📈 Real-time network statistics and threat analytics

---

# Detection Capabilities

Aegis currently detects multiple classes of network attacks, including:

- SYN Flood attacks
- Port Scanning
- ARP Spoofing
- ICMP Floods
- UDP Floods
- TCP-based anomalies
- Suspicious behavioral deviations through machine learning

Detection combines both rule-based logic and behavioral analysis to improve accuracy while reducing false positives.

---

# System Architecture

```
Live Network Traffic
        │
        ▼
Packet Capture (Scapy)
        │
        ▼
────────────────────────────────────
Layer 1
Signature Detection
────────────────────────────────────

────────────────────────────────────
Layer 2
Protocol & TCP Flag Analysis
────────────────────────────────────

────────────────────────────────────
Layer 3
Behavioral ML
(Isolation Forest)
────────────────────────────────────

────────────────────────────────────
Layer 4
Attack Correlation Engine
────────────────────────────────────

────────────────────────────────────
Layer 5
Visualization & Alert Dashboard
(Streamlit)
────────────────────────────────────
```

---

# Tech Stack

| Category | Technologies |
|----------|--------------|
| Language | Python |
| Packet Capture | Scapy |
| Machine Learning | scikit-learn |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Numerical Computing | NumPy |
| Packet Driver | Npcap |
| Validation | Wireshark |

---

# Installation

Clone the repository

```bash
git clone https://github.com/<your-username>/Aegis-NIDS.git
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python aegis_nids.py
```

---

# Requirements

- Python 3.10+
- Npcap
- Scapy
- Streamlit
- scikit-learn
- Plotly
- NumPy

Wireshark is optional and may be used for packet inspection and validation during testing.

---

# Dashboard

The Streamlit dashboard provides live visibility into:

- Network traffic statistics
- Active hosts
- Detected attacks
- Behavioral anomalies
- Alert history
- Detection analytics

---

# Design Philosophy

Traditional IDS solutions often rely entirely on static signatures, making them ineffective against novel or evolving attack patterns.

Aegis follows a hybrid detection approach by combining:

- Signature-based detection
- Protocol analysis
- Statistical inspection
- Behavioral machine learning
- Attack-chain correlation

This layered architecture enables the system to identify both known attacks and suspicious behavioral changes occurring within the monitored network.

---

# Future Improvements

- [ ] Additional attack signatures
- [ ] Deep learning anomaly detection
- [ ] Distributed monitoring
- [ ] Threat intelligence integration
- [ ] Email and webhook alerts
- [ ] SIEM integration
- [ ] Automatic rule generation

---

# Warning

Aegis performs live packet capture and network analysis.

Only use this software on networks you own or where you have explicit authorization to monitor traffic. Unauthorized packet capture may violate organizational policies or local laws.

---

## About

Aegis NIDS was developed as a cybersecurity project to explore modern intrusion detection techniques through a layered architecture combining network security, behavioral machine learning, protocol analysis, and real-time visualization.
