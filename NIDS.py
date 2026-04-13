import streamlit as st
import pandas as pd
import threading
import time
import math
from scapy.all import sniff, TCP, IP, UDP, ICMP, ARP
from collections import deque, defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import plotly.graph_objects as go

# ═══════════════════════════════════════════════════════════
#  GLOBAL STOP EVENT — lives outside session_state so the
#  background thread can safely read it across reruns
# ═══════════════════════════════════════════════════════════
_STOP_EVENT = threading.Event()

# ═══════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════
SYN_WINDOW_SEC        = 5
SYN_THRESHOLD         = 5
SCAN_WINDOW_SEC       = 8
SCAN_PORT_THRESHOLD   = 6
UDP_WINDOW_SEC        = 5
UDP_THRESHOLD         = 50
ICMP_WINDOW_SEC       = 5
ICMP_THRESHOLD        = 10
ML_BASELINE_SIZE      = 50      # global baseline
PER_DEVICE_MIN        = 20      # packets before per-device model trains
TIMING_MIN_SAMPLES    = 10      # gaps needed before entropy fires
TIMING_CV_THRESHOLD   = 0.15    # CV below this = suspiciously regular
CHAIN_WINDOW_SEC      = 60      # scan→flood must happen within this window
ML_CONFIDENCE_MIN     = 40      # suppress ML alerts below this %
ML_COOLDOWN_SEC       = 30
MAX_DISPLAY           = 15

SEVERITY = {
    "SYN Flood":        "HIGH",
    "Port Scan":        "MEDIUM",
    "LAND Attack":      "CRITICAL",
    "UDP Flood":        "HIGH",
    "ICMP Flood":       "MEDIUM",
    "ARP Spoof":        "CRITICAL",
    "Protocol Anomaly": "HIGH",
    "Timing Anomaly":   "MEDIUM",
    "Attack Chain":     "CRITICAL",
    "ML Anomaly":       "LOW",
    "Error":            "INFO",
}

SEVERITY_COLOR = {
    "CRITICAL": "#FF2D2D",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00BFFF",
    "INFO":     "#A9A9A9",
}

# ═══════════════════════════════════════════════════════════
#  PAGE CONFIG + CSS
# ═══════════════════════════════════════════════════════════
st.set_page_config(
    page_title="AEGIS 3.0 — Network IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
  [data-testid="stAppViewContainer"] { background:#0a0e1a; }
  [data-testid="stSidebar"]          { background:#0f1526; }
  h1,h2,h3,.stMarkdown p            { color:#e0e8ff; }
  .metric-card {
    background:#131d35; border:1px solid #1e3a5f;
    border-radius:10px; padding:16px 20px; text-align:center;
  }
  .metric-val { font-size:2.2rem; font-weight:700; color:#4fc3f7; }
  .metric-lbl { font-size:0.8rem; color:#8899bb; text-transform:uppercase; letter-spacing:1px; }
  .alert-critical { border-left:4px solid #FF2D2D; background:#1a0a0a; padding:6px 10px; border-radius:4px; margin-bottom:4px; }
  .alert-high     { border-left:4px solid #FF8C00; background:#1a1200; padding:6px 10px; border-radius:4px; margin-bottom:4px; }
  .alert-medium   { border-left:4px solid #FFD700; background:#1a1800; padding:6px 10px; border-radius:4px; margin-bottom:4px; }
  .alert-low      { border-left:4px solid #00BFFF; background:#001a2a; padding:6px 10px; border-radius:4px; margin-bottom:4px; }
  .alert-info     { border-left:4px solid #A9A9A9; background:#1a1a1a; padding:6px 10px; border-radius:4px; margin-bottom:4px; }
  .chain-box      { border:1px solid #FF2D2D; background:#1a0a0a; border-radius:6px; padding:8px 12px; margin-bottom:6px; }
</style>
""", unsafe_allow_html=True)

st.markdown("# 🛡️ AEGIS 3.0 — Network Intrusion Detection System")
st.markdown("---")

# ═══════════════════════════════════════════════════════════
#  SESSION STATE INIT
# ═══════════════════════════════════════════════════════════
def _init_state():
    defaults = {
        'sniffing':        False,
        'packets':         deque(maxlen=500),
        'alerts':          deque(maxlen=500),
        'syn_history':     defaultdict(deque),
        'port_history':    defaultdict(deque),
        'udp_history':     defaultdict(deque),
        'icmp_history':    defaultdict(deque),
        'arp_table':       {},
        # Global ML
        'ip_features':     defaultdict(lambda: {
                               "packet_count":0,"syn_count":0,"udp_count":0,
                               "icmp_count":0,"ports":set(),"last_time":None,"avg_gap":0.0
                           }),
        'baseline_data':   [],
        'model':           IsolationForest(contamination=0.08, n_estimators=100, random_state=42),
        'scaler':          StandardScaler(),
        'model_trained':   False,
        'ml_last_alert':   {},
        # per-device models
        'device_profiles': {},   # ip -> {"gaps":[], "model":IF, "scaler":SS, "trained":bool, "last_alert":float}
        # timing entropy
        'timing_profiles': defaultdict(lambda: {"gaps": deque(maxlen=200), "last_time": None}),
        'timing_last_alert': {},
        # attack chain
        'attack_chain':    defaultdict(lambda: {"scan_time": None, "flood_time": None, "ports": set()}),
        'chain_alerts':    deque(maxlen=100),
        # Shared counters
        'alert_counts':    defaultdict(int),
        'threat_score':    0,
        'whitelist':       set(),
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ═══════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════
st.sidebar.markdown("## ⚙️ Controls")
iface = st.sidebar.text_input("Network Interface", value="Wi-Fi",
    help="Windows: 'Wi-Fi'/'Ethernet'  |  Linux/Mac: 'eth0'/'en0'")

st.sidebar.markdown("### Detection Thresholds")
syn_thresh  = st.sidebar.slider("SYN Flood (pkts/5s)",  3,  20, SYN_THRESHOLD)
scan_thresh = st.sidebar.slider("Port Scan (ports/8s)", 3,  20, SCAN_PORT_THRESHOLD)
udp_thresh  = st.sidebar.slider("UDP Flood (pkts/5s)", 10, 200, UDP_THRESHOLD)
icmp_thresh = st.sidebar.slider("ICMP Flood (pkts/5s)", 5,  50, ICMP_THRESHOLD)

st.sidebar.markdown("### Whitelist (skip SYN alerts)")
whitelist_raw = st.sidebar.text_area(
    "One IP per line",
    value="172.20.10.2\n192.168.1.1\n10.0.0.1",
    height=80,
    help="Your own machine and gateway — Windows background traffic triggers SYN rules"
)
whitelist_ips = set(l.strip() for l in whitelist_raw.splitlines() if l.strip())

st.sidebar.markdown("---")
bstart = st.sidebar.button("▶ Start Sniffing", use_container_width=True)
bstop  = st.sidebar.button("⏹ Stop Sniffing",  use_container_width=True)
clear  = st.sidebar.button("🗑 Clear All Data", use_container_width=True)

st.sidebar.markdown("---")
bd_len = len(st.session_state.baseline_data)
st.sidebar.markdown(f"**Global ML:** {'✅ Active' if st.session_state.model_trained else f'⏳ {bd_len}/{ML_BASELINE_SIZE}'}")
n_device_models = sum(1 for v in st.session_state.device_profiles.values() if v.get("trained"))
st.sidebar.markdown(f"**Per-Device Models:** {n_device_models} trained")
st.sidebar.markdown(f"**Sniffer:** {'🟢 LIVE' if st.session_state.sniffing else '🔴 STOPPED'}")

# ═══════════════════════════════════════════════════════════
#  CLEAR
# ═══════════════════════════════════════════════════════════
if clear:
    _STOP_EVENT.set()
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    _init_state()
    st.rerun()

# ═══════════════════════════════════════════════════════════
#   PROTOCOL ANOMALY DETECTION
#  Checks packet-level flag combinations that are
#  impossible in legitimate TCP/IP traffic
# ═══════════════════════════════════════════════════════════
def check_protocol_anomaly(pkt, src, dst, now, shared_state):
    if not pkt.haslayer(TCP):
        # Oversized ICMP — Ping of Death variant
        if pkt.haslayer(ICMP) and IP in pkt:
            pkt_len = pkt[IP].len if pkt[IP].len else 0
            if pkt_len > 65500:
                shared_state['alerts'].appendleft({
                    "time": now, "type": "Protocol Anomaly", "src": src,
                    "detail": f"Oversized ICMP packet ({pkt_len} bytes) — Ping of Death",
                    "severity": "HIGH",
                })
                shared_state['alert_counts']['Protocol Anomaly'] += 1
                return True
        return False

    tcp   = pkt[TCP]
    flags = int(tcp.flags)
    anomaly = None

    # Xmas scan: FIN + PSH + URG all set — impossible in normal traffic
    if (flags & 0x29) == 0x29:
        anomaly = "Xmas Scan (FIN+PSH+URG flags)"

    # NULL scan: zero flags — no valid TCP segment has zero flags
    elif flags == 0:
        anomaly = "NULL Scan (zero TCP flags)"

    # SYN+FIN: contradictory — open and close simultaneously
    elif (flags & 0x03) == 0x03:
        anomaly = "SYN+FIN flags (impossible combination)"

    # SYN+RST: also contradictory
    elif (flags & 0x06) == 0x06:
        anomaly = "SYN+RST flags (impossible combination)"

    # FIN only with no ACK — abnormal in established sessions
    elif flags == 0x01:
        anomaly = "Bare FIN (no ACK — stealth scan)"

    if anomaly:
        shared_state['alerts'].appendleft({
            "time": now, "type": "Protocol Anomaly", "src": src,
            "detail": f"{anomaly} → {dst}:{tcp.dport}",
            "severity": "HIGH",
        })
        shared_state['alert_counts']['Protocol Anomaly'] += 1
        return True
    return False

# ═══════════════════════════════════════════════════════════
#   TIMING ENTROPY
#  Coefficient of Variation on inter-packet gaps.
#  Bots/scripts produce suspiciously regular timing (low CV).
#  Human traffic is irregular (high CV).
# ═══════════════════════════════════════════════════════════
def check_timing_entropy(src, ts, shared_state):
    tp = shared_state['timing_profiles'][src]

    if tp["last_time"] is not None:
        gap = ts - tp["last_time"]
        if gap > 0:
            tp["gaps"].append(gap)

    tp["last_time"] = ts

    gaps = list(tp["gaps"])
    if len(gaps) < TIMING_MIN_SAMPLES:
        return

    mean = np.mean(gaps)
    std  = np.std(gaps)

    if mean == 0:
        return

    cv = std / mean  # coefficient of variation

    # Low CV = machine-like regularity = suspicious
    if cv < TIMING_CV_THRESHOLD:
        now  = time.time()
        last = shared_state['timing_last_alert'].get(src, 0.0)
        if now - last > 30:
            shared_state['alerts'].appendleft({
                "time":     time.strftime("%H:%M:%S", time.localtime(ts)),
                "type":     "Timing Anomaly",
                "src":      src,
                "detail":   f"Machine-like regularity detected — CV={cv:.3f} over {len(gaps)} packets (threshold <{TIMING_CV_THRESHOLD})",
                "severity": "MEDIUM",
            })
            shared_state['alert_counts']['Timing Anomaly'] += 1
            shared_state['timing_last_alert'][src] = now

# ═══════════════════════════════════════════════════════════
#   ATTACK CHAIN CORRELATION
#  Watches for: Port Scan → SYN/UDP Flood within CHAIN_WINDOW_SEC
#  This indicates a coordinated intrusion attempt, not random noise
# ═══════════════════════════════════════════════════════════
def update_attack_chain(src, event_type, ports, now_ts, shared_state):
    chain = shared_state['attack_chain'][src]
    now_str = time.strftime("%H:%M:%S", time.localtime(now_ts))

    if event_type == "Port Scan":
        chain["scan_time"] = now_ts
        chain["ports"]     = ports

    elif event_type in ("SYN Flood", "UDP Flood"):
        if chain["scan_time"] is not None:
            elapsed = now_ts - chain["scan_time"]
            if elapsed <= CHAIN_WINDOW_SEC:
                # Check if the flood targets a port that was scanned
                scanned = chain["ports"]
                chain["flood_time"] = now_ts
                shared_state['chain_alerts'].appendleft({
                    "time":    now_str,
                    "src":     src,
                    "elapsed": f"{elapsed:.0f}s",
                    "detail":  f"Port scan at {time.strftime('%H:%M:%S', time.localtime(chain['scan_time']))} "
                               f"followed by {event_type} {elapsed:.0f}s later — coordinated intrusion pattern",
                    "scanned_ports": sorted(scanned)[:8],
                })
                shared_state['alerts'].appendleft({
                    "time":     now_str,
                    "type":     "Attack Chain",
                    "src":      src,
                    "detail":   f"COORDINATED ATTACK: Port scan → {event_type} within {elapsed:.0f}s",
                    "severity": "CRITICAL",
                })
                shared_state['alert_counts']['Attack Chain'] += 1
                # Reset chain so we don't re-alert for same sequence
                chain["scan_time"] = None

# ═══════════════════════════════════════════════════════════
#   PER-DEVICE BEHAVIORAL PROFILING
#  Each IP gets its own Isolation Forest trained on that
#  device's own traffic pattern — not compared to global avg
# ═══════════════════════════════════════════════════════════
def per_device_ml(src, features, now_ts, shared_state):
    dp = shared_state['device_profiles']

    if src not in dp:
        dp[src] = {
            "samples":    [],
            "model":      IsolationForest(contamination=0.1, n_estimators=50, random_state=42),
            "scaler":     StandardScaler(),
            "trained":    False,
            "last_alert": 0.0,
        }

    dev = dp[src]
    dev["samples"].append(features)

    # Train once we have enough samples for this specific device
    if not dev["trained"] and len(dev["samples"]) >= PER_DEVICE_MIN:
        X = np.array(dev["samples"])
        dev["scaler"].fit(X)
        Xs = dev["scaler"].transform(X)
        dev["model"].fit(Xs)
        dev["trained"] = True
        return

    if not dev["trained"]:
        return

    Xs    = dev["scaler"].transform([features])
    pred  = dev["model"].predict(Xs)
    score = dev["model"].decision_function(Xs)[0]

    if pred[0] == -1:
        now  = time.time()
        conf = min(100, int((abs(score) / 0.5) * 100))
        if conf >= ML_CONFIDENCE_MIN and now - dev["last_alert"] > ML_COOLDOWN_SEC:
            now_str = time.strftime("%H:%M:%S", time.localtime(now_ts))
            shared_state['alerts'].appendleft({
                "time":     now_str,
                "type":     "ML Anomaly",
                "src":      src,
                "detail":   f"Deviates from own baseline — confidence {conf}% (per-device model, {len(dev['samples'])} samples)",
                "severity": "LOW",
            })
            shared_state['alert_counts']['ML Anomaly'] += 1
            dev["last_alert"] = now

# ═══════════════════════════════════════════════════════════
#  GLOBAL ML — FEATURE EXTRACTION + DETECTION
# ═══════════════════════════════════════════════════════════
def extract_features(src, ts, shared_state, proto="tcp", dport=None):
    f = shared_state['ip_features'][src]
    f["packet_count"] += 1
    if proto == "tcp_syn": f["syn_count"]  += 1
    if proto == "udp":     f["udp_count"]  += 1
    if proto == "icmp":    f["icmp_count"] += 1
    if dport:              f["ports"].add(dport)
    if f["last_time"] is not None:
        gap = ts - f["last_time"]
        f["avg_gap"] = (f["avg_gap"] * 0.8) + (gap * 0.2)
    f["last_time"] = ts
    return [
        f["packet_count"], f["syn_count"],  f["udp_count"],
        f["icmp_count"],   len(f["ports"]), f["avg_gap"],
    ]

def global_ml_detect(features, src, ts_str, shared_state):
    bd = shared_state['baseline_data']
    if not shared_state['model_trained']:
        bd.append(features)
        if len(bd) >= ML_BASELINE_SIZE:
            X  = np.array(bd)
            shared_state['scaler'].fit(X)
            Xs = shared_state['scaler'].transform(X)
            shared_state['model'].fit(Xs)
            shared_state['model_trained'] = True
        return

    Xs    = shared_state['scaler'].transform([features])
    pred  = shared_state['model'].predict(Xs)
    score = shared_state['model'].decision_function(Xs)[0]

    if pred[0] == -1:
        now  = time.time()
        conf = min(100, int((abs(score) / 0.5) * 100))
        last = shared_state['ml_last_alert'].get(src, 0.0)
        if conf >= ML_CONFIDENCE_MIN and now - last > ML_COOLDOWN_SEC:
            shared_state['alerts'].appendleft({
                "time":     ts_str,
                "type":     "ML Anomaly",
                "src":      src,
                "detail":   f"Global baseline anomaly — confidence {conf}%",
                "severity": "LOW",
            })
            shared_state['alert_counts']['ML Anomaly'] += 1
            shared_state['ml_last_alert'][src] = now

# ═══════════════════════════════════════════════════════════
#  THREAT SCORE HELPER
# ═══════════════════════════════════════════════════════════
SCORE_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 2}

def add_threat(severity, shared_state):
    shared_state['threat_score'] = min(
        100, shared_state['threat_score'] + SCORE_WEIGHT.get(severity, 0)
    )

# ═══════════════════════════════════════════════════════════
#  MAIN PACKET HANDLER
# ═══════════════════════════════════════════════════════════
def handle_packet(pkt, shared_state):
    ts  = time.time()
    now = time.strftime("%H:%M:%S", time.localtime(ts))
    src = pkt[IP].src if IP in pkt else ("ARP" if ARP in pkt else "N/A")
    dst = pkt[IP].dst if IP in pkt else "N/A"

    record = {
        "time": now, "src": src, "dst": dst, "proto": "N/A",
        "sport": None, "dport": None, "flags": None,
        "summary": pkt.summary()[:80],
    }

    # ── ARP SPOOF ─────────────────────────────────────────
    if ARP in pkt and pkt[ARP].op == 2:
        ip_s  = pkt[ARP].psrc
        mac_s = pkt[ARP].hwsrc
        tbl   = shared_state['arp_table']
        tbl.setdefault(ip_s, set()).add(mac_s)
        if len(tbl[ip_s]) > 1:
            shared_state['alerts'].appendleft({
                "time": now, "type": "ARP Spoof", "src": ip_s,
                "detail": f"IP {ip_s} claimed by {len(tbl[ip_s])} different MACs — MITM attempt",
                "severity": "CRITICAL",
            })
            shared_state['alert_counts']['ARP Spoof'] += 1
            add_threat("CRITICAL", shared_state)
        record["proto"] = "ARP"
        shared_state['packets'].appendleft(record)
        return

    if IP not in pkt:
        return

    # ── PROTOCOL ANOMALY ─
    check_protocol_anomaly(pkt, src, dst, now, shared_state)

    # ── TCP ───────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp    = pkt[TCP]
        is_syn = bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)  # SYN without ACK
        record.update(proto="TCP", sport=tcp.sport, dport=tcp.dport, flags=str(tcp.flags))

        # Feature extraction for both ML layers
        features = extract_features(src, ts, shared_state, "tcp_syn" if is_syn else "tcp", tcp.dport)

        # timing entropy on all TCP traffic
        check_timing_entropy(src, ts, shared_state)

        # per-device model
        per_device_ml(src, features, ts, shared_state)

        # Global ML
        global_ml_detect(features, src, now, shared_state)

        # LAND Attack
        if src == dst:
            shared_state['alerts'].appendleft({
                "time": now, "type": "LAND Attack", "src": src,
                "detail": f"src IP == dst IP ({src}:{tcp.sport} → {dst}:{tcp.dport})",
                "severity": "CRITICAL",
            })
            shared_state['alert_counts']['LAND Attack'] += 1
            add_threat("CRITICAL", shared_state)

        # SYN Flood
        if is_syn:
            dq = shared_state['syn_history'][src]
            dq.append(ts)
            while dq and dq[0] < ts - SYN_WINDOW_SEC: dq.popleft()
            is_whitelisted = src in shared_state.get('whitelist', set())
            if syn_thresh <= len(dq) < syn_thresh + 3 and not is_whitelisted:
                shared_state['alerts'].appendleft({
                    "time": now, "type": "SYN Flood", "src": src,
                    "detail": f"{len(dq)} SYNs in {SYN_WINDOW_SEC}s → {dst}:{tcp.dport}",
                    "severity": "HIGH",
                })
                shared_state['alert_counts']['SYN Flood'] += 1
                add_threat("HIGH", shared_state)
                # register flood event
                update_attack_chain(src, "SYN Flood", set(), ts, shared_state)

        # Port Scan
        ph = shared_state['port_history'][src]
        ph.append((tcp.dport, ts))
        while ph and ph[0][1] < ts - SCAN_WINDOW_SEC: ph.popleft()
        unique_ports = {p for p, _ in ph}
        if scan_thresh <= len(unique_ports) < scan_thresh + 3:
            shared_state['alerts'].appendleft({
                "time": now, "type": "Port Scan", "src": src,
                "detail": f"{len(unique_ports)} unique ports in {SCAN_WINDOW_SEC}s",
                "severity": "MEDIUM",
            })
            shared_state['alert_counts']['Port Scan'] += 1
            add_threat("MEDIUM", shared_state)
            # register scan event with port set
            update_attack_chain(src, "Port Scan", unique_ports, ts, shared_state)

    # ── UDP Flood ──────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record.update(proto="UDP", sport=udp.sport, dport=udp.dport)
        features = extract_features(src, ts, shared_state, "udp", udp.dport)
        check_timing_entropy(src, ts, shared_state)
        per_device_ml(src, features, ts, shared_state)
        global_ml_detect(features, src, now, shared_state)

        dq = shared_state['udp_history'][src]
        dq.append(ts)
        while dq and dq[0] < ts - UDP_WINDOW_SEC: dq.popleft()
        if udp_thresh <= len(dq) < udp_thresh + 5:
            shared_state['alerts'].appendleft({
                "time": now, "type": "UDP Flood", "src": src,
                "detail": f"{len(dq)} UDP pkts in {UDP_WINDOW_SEC}s → {dst}:{udp.dport}",
                "severity": "HIGH",
            })
            shared_state['alert_counts']['UDP Flood'] += 1
            add_threat("HIGH", shared_state)
            update_attack_chain(src, "UDP Flood", set(), ts, shared_state)

    # ── ICMP Flood ─────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        record["proto"] = "ICMP"
        features = extract_features(src, ts, shared_state, "icmp")
        check_timing_entropy(src, ts, shared_state)
        per_device_ml(src, features, ts, shared_state)
        global_ml_detect(features, src, now, shared_state)

        dq = shared_state['icmp_history'][src]
        dq.append(ts)
        while dq and dq[0] < ts - ICMP_WINDOW_SEC: dq.popleft()
        if icmp_thresh <= len(dq) < icmp_thresh + 3:
            shared_state['alerts'].appendleft({
                "time": now, "type": "ICMP Flood", "src": src,
                "detail": f"{len(dq)} ICMP packets in {ICMP_WINDOW_SEC}s",
                "severity": "MEDIUM",
            })
            shared_state['alert_counts']['ICMP Flood'] += 1
            add_threat("MEDIUM", shared_state)

    shared_state['packets'].appendleft(record)

# ═══════════════════════════════════════════════════════════
#  SNIFFER THREAD
# ═══════════════════════════════════════════════════════════
def sniff_packets(shared_state, iface=None):
    try:
        sniff(
            prn=lambda pkt: handle_packet(pkt, shared_state),
            iface=iface, store=False,
            stop_filter=lambda x: _STOP_EVENT.is_set(),
        )
    except Exception as e:
        shared_state['alerts'].appendleft({
            "time": time.strftime("%H:%M:%S"), "type": "Error",
            "src": "system", "detail": str(e), "severity": "INFO",
        })

# ═══════════════════════════════════════════════════════════
#  START / STOP
# ═══════════════════════════════════════════════════════════
if bstart and not st.session_state.sniffing:
    st.session_state.sniffing = True
    _STOP_EVENT.clear()
    shared_state = {
        'packets':         st.session_state.packets,
        'alerts':          st.session_state.alerts,
        'syn_history':     st.session_state.syn_history,
        'port_history':    st.session_state.port_history,
        'udp_history':     st.session_state.udp_history,
        'icmp_history':    st.session_state.icmp_history,
        'arp_table':       st.session_state.arp_table,
        'ip_features':     st.session_state.ip_features,
        'baseline_data':   st.session_state.baseline_data,
        'model':           st.session_state.model,
        'scaler':          st.session_state.scaler,
        'model_trained':   st.session_state.model_trained,
        'ml_last_alert':   st.session_state.ml_last_alert,
        'device_profiles': st.session_state.device_profiles,
        'timing_profiles': st.session_state.timing_profiles,
        'timing_last_alert': st.session_state.get('timing_last_alert', {}),
        'attack_chain':    st.session_state.attack_chain,
        'chain_alerts':    st.session_state.chain_alerts,
        'alert_counts':    st.session_state.alert_counts,
        'threat_score':    st.session_state.threat_score,
        'whitelist':       whitelist_ips,
    }
    threading.Thread(
        target=sniff_packets, args=(shared_state,),
        kwargs={"iface": iface or None}, daemon=True
    ).start()

if bstop:
    _STOP_EVENT.set()
    st.session_state.sniffing = False

# Sync model_trained (bool is immutable — detect via list length)
if not st.session_state.model_trained and len(st.session_state.baseline_data) >= ML_BASELINE_SIZE:
    st.session_state.model_trained = True

# Sync timing_last_alert back
if 'timing_last_alert' not in st.session_state:
    st.session_state.timing_last_alert = {}

# Threat score — recalculate from alert_counts (immutable int workaround)
ac = st.session_state.alert_counts
st.session_state.threat_score = min(100,
    min(ac.get("LAND Attack",      0), 1) * 40 +
    min(ac.get("ARP Spoof",        0), 1) * 40 +
    min(ac.get("Attack Chain",     0), 1) * 40 +
    min(ac.get("SYN Flood",        0), 3) * 10 +
    min(ac.get("UDP Flood",        0), 3) * 10 +
    min(ac.get("Protocol Anomaly", 0), 3) * 8  +
    min(ac.get("Port Scan",        0), 2) * 8  +
    min(ac.get("Timing Anomaly",   0), 3) * 5  +
    min(ac.get("ICMP Flood",       0), 2) * 5  +
    min(ac.get("ML Anomaly",       0), 5) * 2
)

# ═══════════════════════════════════════════════════════════
#  DASHBOARD — METRICS ROW
# ═══════════════════════════════════════════════════════════
total_alerts  = sum(st.session_state.alert_counts.values())
critical_hits = (ac.get("LAND Attack", 0) + ac.get("ARP Spoof", 0) + ac.get("Attack Chain", 0))
threat_score  = st.session_state.threat_score
score_color   = "#FF2D2D" if threat_score > 60 else "#FFD700" if threat_score > 30 else "#00ff88"

m1, m2, m3, m4, m5 = st.columns(5)

def metric_card(col, val, label, color="#4fc3f7"):
    col.markdown(
        f'<div class="metric-card">'
        f'<div class="metric-val" style="color:{color}">{val}</div>'
        f'<div class="metric-lbl">{label}</div></div>',
        unsafe_allow_html=True
    )

metric_card(m1, len(st.session_state.packets),     "Packets Captured")
metric_card(m2, total_alerts,                       "Total Alerts",  "#FF8C00")
metric_card(m3, critical_hits,                      "Critical Hits", "#FF2D2D")
metric_card(m4, len(st.session_state.ip_features), "Unique IPs")
metric_card(m5, f"{threat_score}/100",              "Threat Score",  score_color)

st.markdown("<br>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════
#  CHARTS ROW
# ═══════════════════════════════════════════════════════════
chart_col1, chart_col2 = st.columns([1, 2])

with chart_col1:
    st.markdown("#### 🎯 Threat Level")
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number", value=threat_score,
        domain={'x': [0,1], 'y': [0,1]},
        gauge={
            'axis':    {'range': [0,100], 'tickcolor': "#8899bb"},
            'bar':     {'color': score_color},
            'bgcolor': "#131d35",
            'steps':   [
                {'range': [0,  30], 'color': "#0a2a1a"},
                {'range': [30, 60], 'color': "#2a2a0a"},
                {'range': [60,100], 'color': "#2a0a0a"},
            ],
            'threshold': {'line': {'color':"#FF2D2D",'width':3}, 'thickness':0.75, 'value':80}
        }
    ))
    fig_gauge.update_layout(
        paper_bgcolor="#0a0e1a", font_color="#e0e8ff",
        height=220, margin=dict(t=20,b=10,l=20,r=20)
    )
    st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar":False})

with chart_col2:
    st.markdown("#### 📊 Alerts by Attack Type")
    if ac:
        types  = list(ac.keys())
        counts = list(ac.values())
        colors = [SEVERITY_COLOR.get(SEVERITY.get(t,"LOW"),"#4fc3f7") for t in types]
        fig_bar = go.Figure(go.Bar(x=types, y=counts, marker_color=colors,
                                   text=counts, textposition='auto'))
        fig_bar.update_layout(
            paper_bgcolor="#0a0e1a", plot_bgcolor="#131d35",
            font_color="#e0e8ff", height=220,
            margin=dict(t=20,b=10,l=20,r=20),
            xaxis=dict(gridcolor="#1e3a5f"),
            yaxis=dict(gridcolor="#1e3a5f"),
        )
        st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar":False})
    else:
        st.info("No alerts yet — start sniffing to populate chart.")

st.markdown("---")

# ═══════════════════════════════════════════════════════════
#  ATTACK CHAIN PANEL — shown onlyy when chains are detected
# ═══════════════════════════════════════════════════════════
chain_list = list(st.session_state.chain_alerts)
if chain_list:
    st.markdown("#### 🔗 Attack Chain Intelligence")
    for ch in chain_list[:5]:
        ports_str = ", ".join(str(p) for p in ch.get("scanned_ports", []))
        st.markdown(
            f'<div class="chain-box">'
            f'<span style="color:#FF2D2D;font-weight:700">⚠ COORDINATED ATTACK</span> &nbsp;'
            f'<span style="color:#8899bb">{ch["time"]}</span><br>'
            f'<span style="color:#ccd6f6"><b>Source:</b> {ch["src"]}</span> &nbsp; '
            f'<span style="color:#8899bb">Elapsed: {ch["elapsed"]}</span><br>'
            f'<span style="color:#aabbdd;font-size:0.85rem">{ch["detail"]}</span><br>'
            f'<span style="color:#667799;font-size:0.8rem">Scanned ports: {ports_str or "N/A"}</span>'
            f'</div>',
            unsafe_allow_html=True
        )
    st.markdown("---")

# ═══════════════════════════════════════════════════════════
#  LIVE PACKETS + ALERT CONSOLE
# ═══════════════════════════════════════════════════════════
pkt_col, alert_col = st.columns([3, 2])

with pkt_col:
    st.markdown("#### 📡 Live Packet Feed")
    df = pd.DataFrame(list(st.session_state.packets)[:MAX_DISPLAY])
    if not df.empty:
        cols_order = [c for c in
                      ["time","src","dst","proto","sport","dport","flags","summary"]
                      if c in df.columns]
        st.dataframe(df[cols_order], use_container_width=True, hide_index=True)
    else:
        st.info("No packets captured yet. Press ▶ Start Sniffing.")

with alert_col:
    st.markdown("#### 🚨 Alert Console")
    alerts_list = list(st.session_state.alerts)[:30]
    if alerts_list:
        for a in alerts_list:
            sev = a.get("severity", SEVERITY.get(a["type"], "LOW")).lower()
            st.markdown(
                f'<div class="alert-{sev}">'
                f'<span style="color:#8899bb;font-size:0.75rem">{a["time"]}</span> '
                f'<b style="color:{SEVERITY_COLOR.get(a.get("severity","LOW"),"#fff")}">[{a["type"]}]</b> '
                f'<span style="color:#ccd6f6"> {a["src"]}</span> '
                f'<span style="color:#8899bb;font-size:0.85rem">— {a["detail"]}</span>'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        st.info("No alerts — network looks clean.")

# ═══════════════════════════════════════════════════════════
#  FOOTER
# ═══════════════════════════════════════════════════════════
st.markdown("---")
n_dev = sum(1 for v in st.session_state.device_profiles.values() if v.get("trained"))
bd_now = len(st.session_state.baseline_data)
st.markdown(
    f"<div style='text-align:center;color:#445577;font-size:0.78rem'>"
    f"AEGIS 3.0 &nbsp;·&nbsp; "
    f"Global ML: {'Active ✅' if st.session_state.model_trained else f'Warming up ({bd_now}/{ML_BASELINE_SIZE}) ⏳'}"
    f" &nbsp;·&nbsp; Per-Device Models: {n_dev} trained"
    f" &nbsp;·&nbsp; "
    f"Rule Engine · Protocol Anomaly · Timing Entropy · Per-Device ML · Attack Chain Correlation"
    f"</div>",
    unsafe_allow_html=True
)

# ═══════════════════════════════════════════════════════════
#  AUTO REFRESH
# ═══════════════════════════════════════════════════════════
if st.session_state.sniffing:
    time.sleep(1)
    st.rerun()
