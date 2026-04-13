# syn_demo.py — SYN Flood Simulation (updated for Aegis 3.0)
from scapy.all import IP, TCP, send

TARGET_IP        = "172.20.10.2"   # <-- UPDATE (your machine's IP)
TARGET_PORT      = 80
SPOOFED_SRC_IP   = "172.20.10.100"
PACKET_COUNT     = 20

print(f"[SYN FLOOD] Sending {PACKET_COUNT} SYN packets → {TARGET_IP}:{TARGET_PORT}")
print(f"  Spoofed source: {SPOOFED_SRC_IP}")

packets = [
    IP(src=SPOOFED_SRC_IP, dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S")
    for _ in range(PACKET_COUNT)
]
send(packets, verbose=False)
print("[SYN FLOOD] Done — check AEGIS for HIGH severity alert.")
