import streamlit as st
import pandas as pd
import threading
import time
from scapy.all import sniff, TCP, IP
from collections import deque, defaultdict

# ---------- CONFIG ----------
SYN_WINDOW_SEC = 5         # time window to count SYNs
SYN_THRESHOLD = 5          # SYNs within window to flag SYN flood (Adjusted for demo)
SCAN_WINDOW_SEC = 8        # window to track distinct dest ports (Adjusted for demo)
SCAN_PORT_THRESHOLD = 6    # distinct ports within window to flag port scan (Adjusted for demo)
MAX_DISPLAY = 12           # how many recent packets to show
# ----------------------------

st.set_page_config(page_title="IDS Demo (Scapy)", layout="wide")
st.title("📡 PRANET: Network IDS") # <-- Title changed here

# --- SESSION STATE INITIALIZATION ---
if 'lock' not in st.session_state:
    st.session_state.lock = threading.Lock()
if 'sniffing' not in st.session_state:
    st.session_state.sniffing = False
if 'packets' not in st.session_state:
    st.session_state.packets = deque(maxlen=500)
if 'alerts' not in st.session_state:
    st.session_state.alerts = deque(maxlen=200)
if 'syn_history' not in st.session_state:
    st.session_state.syn_history = defaultdict(deque)
if 'port_history' not in st.session_state:
    st.session_state.port_history = defaultdict(deque)
if 'sniff_thread' not in st.session_state:
    st.session_state.sniff_thread = None

# --- HELPERS ---
def handle_packet(pkt, shared_state):
    ts = time.time()
    record = {
        "time": time.strftime("%H:%M:%S", time.localtime(ts)),
        "src": pkt[IP].src if IP in pkt else "N/A",
        "dst": pkt[IP].dst if IP in pkt else "N/A",
        "proto": pkt.sprintf("%IP.proto%") if IP in pkt else pkt.name,
        "summary": pkt.summary()
    }
    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        record["sport"] = tcp.sport
        record["dport"] = tcp.dport
        flags = tcp.flags
        record["flags"] = str(flags)

        # SYN detection
        if flags & 0x02: # SYN flag
            dq = shared_state['syn_history'][record["src"]]
            dq.append(ts)
            while dq and dq[0] < ts - SYN_WINDOW_SEC:
                dq.popleft()
            
            # Debugging print removed here
            
            if len(dq) >= SYN_THRESHOLD:
                # To prevent spamming, only alert once per trigger
                if len(dq) < SYN_THRESHOLD + 2: 
                    shared_state['alerts'].appendleft({
                        "time": record["time"],
                        "type": "SYN Flood",
                        "src": record["src"],
                        "detail": f"{len(dq)} SYNs in last {SYN_WINDOW_SEC}s"
                    })

        # Port scan detection
        ph = shared_state['port_history'][record["src"]]
        ph.append((record["dport"], ts))
        while ph and ph[0][1] < ts - SCAN_WINDOW_SEC:
            ph.popleft()
        unique_ports = {p for p, t in ph}
        if len(unique_ports) >= SCAN_PORT_THRESHOLD:
            shared_state['alerts'].appendleft({
                "time": record["time"],
                "type": "Port Scan",
                "src": record["src"],
                "detail": f"{len(unique_ports)} distinct dst ports in last {SCAN_WINDOW_SEC}s"
            })
    else:
        record["sport"] = None
        record["dport"] = None
        record["flags"] = None

    shared_state['packets'].appendleft(record)

def sniff_packets(shared_state, iface=None, filter_expr=None):
    try:
        # Use shared_state['sniffing'] as the stop_filter check
        sniff(prn=lambda pkt: handle_packet(pkt, shared_state),
              iface=iface,
              filter=filter_expr,
              store=False,
              stop_filter=lambda x: not shared_state['sniffing'])
    except PermissionError:
        shared_state['alerts'].appendleft({
            "time": time.strftime("%H:%M:%S"),
            "type": "Error",
            "src": "local",
            "detail": "Permission denied. Run as admin/root or install Npcap on Windows."
        })
    except Exception as e:
        # If sniffing stops due to interface error, set state to False
        shared_state['sniffing'] = False 
        shared_state['alerts'].appendleft({
            "time": time.strftime("%H:%M:%S"),
            "type": "Error",
            "src": "local",
            "detail": str(e)
        })

# --- SIDEBAR CONTROLS ---
st.sidebar.header("Controls")
# Added placeholder 'Wi-Fi' as best guess
iface = st.sidebar.text_input("Interface (leave empty for default)", value="Wi-Fi") 
bstart = st.sidebar.button("Start Sniffing")
bstop = st.sidebar.button("Stop Sniffing")
clear = st.sidebar.button("Clear Data & Alerts")

st.sidebar.markdown("**Detection thresholds**")
syn_thresh = st.sidebar.number_input("SYN threshold (count)", value=SYN_THRESHOLD, min_value=1)
syn_window = st.sidebar.number_input("SYN window (sec)", value=SYN_WINDOW_SEC, min_value=1)
scan_ports = st.sidebar.number_input("Scan port threshold", value=SCAN_PORT_THRESHOLD, min_value=1)
scan_window = st.sidebar.number_input("Scan window (sec)", value=SCAN_WINDOW_SEC, min_value=1)

# NEW POP-OUT FOR EXPLANATIONS
with st.sidebar.expander("Threshold Explanations"):
    st.markdown("""
    **SYN Threshold (count)**
    > The number of SYN (initial connection) packets from a single source IP within the time window that will trigger a **SYN Flood** alert.

    **SYN Window (sec)**
    > The time window (in seconds) over which the SYN packets are counted.

    **Scan Port Threshold**
    > The number of *distinct* destination ports accessed by a single source IP within the time window that will trigger a **Port Scan** alert.

    **Scan Window (sec)**
    > The time window (in seconds) over which the distinct destination ports are counted.
    """)

# update thresholds
SYN_THRESHOLD = int(syn_thresh)
SYN_WINDOW_SEC = int(syn_window)
SCAN_PORT_THRESHOLD = int(scan_ports)
SCAN_WINDOW_SEC = int(scan_window)

if clear:
    with st.session_state.lock:
        st.session_state.packets.clear()
        st.session_state.alerts.clear()
        st.session_state.syn_history.clear()
        st.session_state.port_history.clear()

# start sniffing
if bstart and not st.session_state.sniffing:
    st.session_state.sniffing = True
    shared_state = {
        'lock': st.session_state.lock,
        'packets': st.session_state.packets,
        'alerts': st.session_state.alerts,
        'syn_history': st.session_state.syn_history,
        'port_history': st.session_state.port_history,
        'sniffing': st.session_state.sniffing
    }
    # Note: if iface is empty, we pass None and scapy selects default
    t = threading.Thread(target=sniff_packets, args=(shared_state,), kwargs={"iface": iface or None}, daemon=True) 
    st.session_state.sniff_thread = t
    t.start()

# stop sniffing
if bstop and st.session_state.sniffing:
    st.session_state.sniffing = False
    # No need to stop the thread explicitly; stop_filter handles it.
    st.session_state.sniff_thread = None

# --- LAYOUT ---
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Live packets (most recent)")
    with st.session_state.lock:
        df = pd.DataFrame(list(st.session_state.packets)[:MAX_DISPLAY])
    if not df.empty:
        # Use simple table format for better alignment
        st.dataframe(df.style.set_properties(**{'font-size': '10pt'}), height=360) 
    else:
        st.write("No packets captured yet. Start sniffing (admin/root required).")

with col2:
    # --- SUMMARY MOVED TO TOP ---
    st.subheader("Summary")
    with st.session_state.lock:
        total = len(st.session_state.packets)
        attacks = len([x for x in st.session_state.alerts if x["type"] not in ["Error"]])
    st.markdown(f"**Total packets:** {total} \n**Alerts recorded:** {attacks}")
    st.markdown("---")
    # -----------------------------

    st.subheader("Alerts")
    if st.session_state.alerts:
        for a in list(st.session_state.alerts)[:20]:
            if a["type"] == "Error":
                 st.error(f"**{a['time']}** — **{a['type']}** from `{a['src']}` — {a['detail']}")
            else:
                 st.warning(f"**{a['time']}** — **{a['type']}** from `{a['src']}` — {a['detail']}")
    else:
        st.write("No alerts")

st.caption("")


# --- AUTO-REFRESH (Keep this line to make the dashboard update) ---
if st.session_state.sniffing:
    time.sleep(1)
    st.rerun()
