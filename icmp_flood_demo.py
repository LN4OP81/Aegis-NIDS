# icmp_flood_demo.py — ICMP Flood Simulation (Ping Flood)
# Sends a rapid stream of ICMP Echo Requests to overwhelm the target.
# Aegis triggers at 10 ICMP packets within 5 seconds from one source.

from scapy.all import IP, ICMP, send

# ── CONFIGURATION ───────────────────────────────────────────
TARGET_IP      = "10.55.0.1"    # <-- UPDATE BEFORE RUNNING
SPOOFED_SRC_IP = "10.55.0.201"
COUNT          = 20             # Exceeds threshold of 10

print(f"[ICMP FLOOD] Sending {COUNT} ICMP Echo Requests → {TARGET_IP}")
print(f"  Spoofed source: {SPOOFED_SRC_IP}")

packets = [
    IP(src=SPOOFED_SRC_IP, dst=TARGET_IP) / ICMP()
    for _ in range(COUNT)
]

send(packets, verbose=False)
print("[ICMP FLOOD] Done — check AEGIS for MEDIUM severity alert.")
