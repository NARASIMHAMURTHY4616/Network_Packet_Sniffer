# Packet Sniffer & DFIR Dashboard
installing -> (https://github.com/NARASIMHAMURTHY4616/Network_Packet_Sniffer/blob/main/README.md#-installation)

A Python-based Network Monitoring and DFIR Dashboard that captures live network traffic using Scapy and visualizes packet activity through an interactive Streamlit interface.

The project combines packet capture, protocol analysis, DNS monitoring, suspicious activity detection, and export functionality into a single lightweight monitoring solution.

---

# 🚀 Features

### Packet Capture
- Real-time packet sniffing using Scapy
- IPv4 and IPv6 support
- TCP, UDP, ICMP detection
- Packet metadata extraction

### Traffic Analysis
- Source IP tracking
- Destination IP tracking
- Protocol identification
- Service detection (HTTP, HTTPS, DNS, SSH, FTP)
- DNS query monitoring
- TCP flag analysis

### Dashboard
- Live Streamlit dashboard
- Auto-refreshing packet statistics
- Interactive packet table
- Protocol filtering
- Responsive layout

### Visualizations
- Top Source IP chart
- Top Destination IP chart
- Protocol distribution chart
- Top DNS Queries analysis

### DFIR Features
- Suspicious port detection
- SYN flood detection
- Basic threat indicators
- Network activity monitoring

### Data Management
- Latest 500 packets displayed in UI
- Full packet history stored separately
- CSV Export
- JSON Export
- Thread-safe packet storage

---

# 🛠 Technologies Used

- Python 3.12
- Scapy
- Streamlit
- Pandas
- Threading
- Collections (Counter)
- JSON

---

# 📂 Project Structure

```text
BPS/
│
├── main.py
├── prototype.py
├── requirements.txt
├── README.md
│
└── __pycache__/
```

---

# ⚙️ Architecture

```text
Scapy Packet Capture
          │
          ▼
     prototype.py
          │
          ▼
 Packet Processing Engine
          │
 ┌────────┴────────┐
 │                 │
 ▼                 ▼

UI Packets      Export Packets
(Last 500)      (Complete History)

 │                 │
 ▼                 ▼

Streamlit UI    CSV / JSON Export
```

---

# 📋 Packet Information Collected

Each captured packet contains:

| Field | Description |
|---------|-------------|
| packet_number | Sequential packet number |
| Time_Stamp | Capture timestamp |
| source_ip | Source IP address |
| destination_ip | Destination IP address |
| protocol | TCP/UDP/ICMP |
| source_port | Source port |
| destination_port | Destination port |
| service | Identified service |
| flags | TCP flags |
| dns_query | DNS query name |
| packet_length | Packet size |
| info | Packet summary |

---

# 🔍 Suspicious Activity Detection

The dashboard currently identifies:

### Suspicious Ports

- 23 (Telnet)
- 445 (SMB)
- 3389 (RDP)
- 4444
- 1337

### SYN Activity

- TCP SYN packet monitoring
- Potential SYN flood detection

---

# 📊 Dashboard Sections

## Metrics

Displays:

- Total Packets
- TCP Packets
- UDP Packets
- DNS Packets
- ICMP Packets

---

## Packet Table

Shows:

- Latest packet captures
- Protocol filtering
- Scrollable packet history

---

## Top Source IPs

Displays the most active source IP addresses.

---

## Top Destination IPs

Displays the most contacted destination IP addresses.

---

## Protocol Distribution

Shows protocol usage statistics.

---

## DNS Queries

Lists the most frequently requested domains.

---

# 📁 Export System

The dashboard stores packets in two locations:

### UI Storage

```python
ui_packets
```

- Stores latest 500 packets
- Used for dashboard rendering

### Export Storage

```python
export_packets
```

- Stores complete capture history
- Used for CSV/JSON exports

---

# 🔄 Multithreading

Packet capture runs in a dedicated daemon thread.

```python
capture_thread = threading.Thread(
    target=prototype.packet_detect,
    daemon=True
)
```

Benefits:

- Non-blocking UI
- Continuous packet capture
- Live dashboard updates

---

# 📦 Installation

Clone repository:

```bash
git clone https://github.com/NARASIMHAMURTHY4616/Network_Packet_Sniffer.git
```

Move into project:

```bash
cd Network_Packet_Sniffer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Project

Start dashboard:

```bash
streamlit run main.py
```

The packet capture engine starts automatically in the background.

---

---

# 📈 Future Improvements

- PCAP export support
- Geo-IP lookup
- WHOIS integration
- Packet search engine
- Threat intelligence feeds
- Dark DFIR theme enhancements
- Real-time alerts panel
- Live protocol pie charts
- Packet payload inspection
- Session tracking

---

# 🎯 Learning Outcomes

This project demonstrates:

- Network Packet Analysis
- Digital Forensics Fundamentals
- Python Threading
- Real-Time Data Processing
- Streamlit Dashboard Development
- Scapy Packet Sniffing
- Data Visualization
- DFIR Concepts

---

# ⚠ Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes only. Use only on networks you own or have explicit permission to monitor.

---

# 👨‍💻 Author

**Narasimha Balla**

Cybersecurity Enthusiast | DFIR Learner | Python Developer

Built as a hands-on project to learn packet analysis, network monitoring, threading, and DFIR dashboard development.
