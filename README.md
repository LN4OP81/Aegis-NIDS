# Aegis-NIDS
Aegis is a Python-based Network Intrusion Detection System that monitors live traffic using packet-sniffing with Scapy. It detects intrusions, port scans, and SYN flood attacks, with Wireshark used for traffic validation. A hands-on tool for learning real-time network threat detection and analysis.

This project is a collection of demonstration scripts. The repository should be clean and focused on the code.

  Files to Add to GitHub:
   * IDS_demo.py
   * port_scan_demo.py
   * SYN_demo.py

  Files to Create:

  A) `README.md`
  Explain the purpose of the project and how to run each script.

    1 # Aegis - Network Intrusion Detection System (NIDS)
    2
    3 Aegis NIDS is a Python-based project demonstrating several network monitoring and intrusion detection techniques. It uses Scapy to perform deep packet
      sniffing and analysis to identify potential network threats.
    4
    5 ## Features
    6 - **Packet Sniffing:** Captures and analyzes raw network packets in real-time.
    7 - **Port Scan Detection:** Identifies patterns consistent with network port scanning.
    8 - **SYN Flood Detection:** Detects the initial signs of a SYN flood (half-open scan) attack.
    9
   10 ## How to Run
   11 **Note:** These scripts must be run with administrator/root privileges to access raw network sockets.
   12
   13 1.  **Clone the repository and install dependencies:**
      git clone <your-repo-url>
      cd Aegis-NIDS
      pip install -r requirements.txt
   1 2.  **Run a specific demo:**
  To run the general IDS demo
      sudo python IDS_demo.py

  To run the port scan detector
      sudo python port_scan_demo.py
   1
   2 ## Tools Used
   3 - Python
   4 - Scapy
   5 - Wireshark (for manual packet analysis and verification)

  B) `requirements.txt`
  This project needs a requirements.txt file.

   1 scapy

  C) `.gitignore`
  A standard Python gitignore is sufficient.

   1 # Byte-compiled / optimized / DLL files
   2 __pycache__/
   3 *.py[cod]
   4 *$py.class

  ---
