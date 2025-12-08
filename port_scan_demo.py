# port_scan_demo.py - For reliable external testing
from scapy.all import IP, TCP, send
import time

# --- TARGET IP CONFIGURATION ---
# IMPORTANT: MUST update this to the IP of your network (or hotspot)

# Default Gateway (your phone's IP) as shown by 'ipconfig' (e.g., 192.168.x.1).
TARGET_IP = "10.55.0.1" 

# Source IP is spoofed to ensure clean tracking by the NIDS
SPOOFED_SOURCE_IP = "10.55.0.100"

# Target 8 unique ports (to trigger your sensitive threshold of 6)
PORTS_TO_SCAN = [21, 22, 23, 80, 443, 3389, 8080, 9000]

print(f"Starting Port Scan Demo against: {TARGET_IP} (Spoofed Source: {SPOOFED_SOURCE_IP})")

for port in PORTS_TO_SCAN:
    # Construct an IP packet with a spoofed source and SYN flag
    pkt = IP(src=SPOOFED_SOURCE_IP, dst=TARGET_IP)/TCP(dport=port, flags="S")
    send(pkt, verbose=False)
    # Slight delay to mimic a scanner and ensure NIDS tracks time accurately
    time.sleep(0.08) 
    print(f"Sent SYN to port {port}")

print("Port scan demo done")