# Aegis NIDS

Aegis is a Python-based Network Intrusion Detection System designed to monitor and analyze live network traffic. It uses advanced packet-sniffing techniques with Scapy to detect common attack patterns like port scans, SYN flood attacks, and general intrusions. Wireshark is used for validating captured traffic and confirming anomalies.

## Features

- Real-time network traffic monitoring  
- Detection of port scans, SYN flood attacks, and general intrusions  
- Raw packet capture with Scapy  
- Traffic validation using Wireshark  

## Installation

1. Clone the repository:  
   ```bash
   git clone https://github.com/yourusername/aegis-nids.git
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the main script:
   ```
   python aegis_nids.pyUsage


Run the system on a network interface to start live traffic monitoring. The tool will log suspicious activities based on predefined detection rules.
Requirements:
```
- Python 3.8+
- Scapy
- Wireshark (for traffic validation)
```
Contributing:
Feel free to submit issues or pull requests. Contributions to enhance detection logic or improve usability are welcome.

License:
MIT License

## Warning
```
This tool performs packet sniffing on network traffic, which may violate network policies or laws if used without proper authorization. Use responsibly and only on networks where you have explicit permission. Unauthorized sniffing can lead to disciplinary action or legal consequences.
```


