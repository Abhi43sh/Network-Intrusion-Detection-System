# 🛡️ Network Intrusion Detection System (NIDS)

A comprehensive, real-time Network Intrusion Detection System (NIDS) built in Python. It monitors network traffic, detects suspicious patterns, generates alerts, and optionally blocks malicious IPs. It also provides an interactive web dashboard for visualization and alert management.

---

## 🚀 Features

- 📡 **Real-Time Packet Capture and Analysis**
- 🛠️ **Rule-Based Detection Engine** (Port Scans, DDoS, Brute Force, etc.)
- 🔐 **Automated Responses** (IP blocking via `iptables` or Windows Firewall)
- 🌐 **Web Dashboard** using Flask + Plotly
- 🧠 **Built-in Detection Capabilities**:
  - Port Scanning
  - ICMP Sweeps
  - DDoS Attacks
  - Suspicious DNS Queries
  - SQL Injection / XSS / Credential Exposure
  - Data Exfiltration
- 📊 **SQLite Integration** for traffic stats and alert storage
- 📄 **Security Reports** (JSON-based)

---

## 📷 Dashboard Preview

> **Access Dashboard:** http://localhost:5000  
> Displays real-time stats, alert logs, traffic graphs, and blocked IPs.

---

## 🧰 Technologies Used

- Python 3
- Scapy (Packet Sniffing & Parsing)
- Flask (Web Server)
- Plotly (Data Visualization)
- SQLite (Database)
- Pandas (Data Handling)
- Regex (Payload Matching)
- Multithreading

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/your-username/network-intrusion-detection-system.git
cd network-intrusion-detection-system

# Install required packages
pip install scapy flask plotly pandas
