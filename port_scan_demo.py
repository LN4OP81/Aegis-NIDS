# portscan_demo.py — Port Scan Simulation (updated for Aegis 3.0)
from scapy.all import IP, TCP, send
import time

TARGET_IP        = "10.55.0.1"    # <-- UPDATE BEFORE RUNNING
SPOOFED_SRC_IP   = "10.55.0.100"
PORTS_TO_SCAN    = [21, 22, 23, 80, 443, 3389, 8080, 9000]

print(f"[PORT SCAN] Scanning {len(PORTS_TO_SCAN)} ports on {TARGET_IP}")
print(f"  Spoofed source: {SPOOFED_SRC_IP}")

for port in PORTS_TO_SCAN:
    pkt = IP(src=SPOOFED_SRC_IP, dst=TARGET_IP) / TCP(dport=port, flags="S")
    send(pkt, verbose=False)
    time.sleep(0.08)
    print(f"  → SYN sent to port {port}")

print("[PORT SCAN] Done — check AEGIS for MEDIUM severity alert.")
