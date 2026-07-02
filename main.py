import streamlit as st
import pandas as pd
import threading
import time
import json
from collections import Counter
from streamlit_autorefresh import st_autorefresh

import prototype

# ==========================
# PAGE CONFIG
# ==========================

st.set_page_config(
    page_title="BPS DFIR Dashboard",
    page_icon="📡",
    layout="wide"
)

# Auto Refresh Every 2 Seconds
st_autorefresh(interval=2000, key="bps_refresh")

# ==========================
# START SNIFFER ONCE
# ==========================

if "sniffer_started" not in st.session_state:

    capture_thread = threading.Thread(
        target=prototype.packet_detect,
        daemon=True
    )

    capture_thread.start()

    st.session_state.sniffer_started = True

# ==========================
# SAFE SNAPSHOT COPY
# ==========================

with prototype.data_lock:

    ui_packets = prototype.ui_packets.copy()

    export_packets = prototype.export_packets.copy()

    total_packets = prototype.total_packets

# ==========================
# CUSTOM THEME
# ==========================

st.markdown("""
<style>

.main {
    background-color:#0e171a;
}

div[data-testid="metric-container"]{
    border:1px solid #262730;
    padding:15px;
    border-radius:10px;
}

</style>
""", unsafe_allow_html=True)

# ==========================
# TITLE + EXPORT SCOPE
# ==========================

title_col, info_col = st.columns([4,1])

with title_col:
    st.title("📡 BPS DFIR Dashboard")

with info_col:
    st.info(
        f"""
📁 Export Scope

Captured:
{len(export_packets)}

Dashboard:
Latest 500

Exports:
Complete History
"""
    )
# ==========================
# SIDEBAR
# ==========================

st.sidebar.title("⚙ Controls")

# --------------------------
# Protocol Filter
# --------------------------

st.sidebar.subheader("Protocol Filter")

selected_protocols = st.sidebar.multiselect(
    "Select Protocols",
    ["TCP", "UDP", "ICMP"],
    default=["TCP", "UDP", "ICMP"]
)

# ==========================
# FILTERED DATA
# ==========================

filtered_packets = [
    p for p in ui_packets
    if p["protocol"] in selected_protocols
]

# ==========================
# EXPORTS
# ==========================

st.subheader("📥 Exports")

try:

    snapshot = list(export_packets)

    export_df = pd.DataFrame.from_records(snapshot)

    csv_data = export_df.to_csv(index=False)

    json_data = json.dumps(
        snapshot,
        indent=4,
        default=str
    )

    col_exp1, col_exp2 = st.columns([1, 2])

    with col_exp1:

        st.download_button(
            "📄 Download CSV",
            csv_data,
            file_name="packets.csv",
            mime="text/csv"
        )

        st.download_button(
            "📄 Download JSON",
            json_data,
            file_name="packets.json",
            mime="application/json"
        )

except Exception as e:

    st.error(f"Export Error: {e}")
# ==========================
# ALERTS
# ==========================

st.sidebar.subheader("⚠ Alerts")

alerts = []

for p in ui_packets:

    if p["destination_port"] in [445, 3389]:
        alerts.append(
            f"Port {p['destination_port']} -> {p['destination_ip']}"
        )

syn_count = sum(
    1
    for p in ui_packets
    if p["flags"] == "S"
)

if syn_count > 50:
    alerts.append(f"Possible SYN Flood ({syn_count})")

if alerts:

    for alert in alerts[:10]:
        st.sidebar.warning(alert)

else:
    st.sidebar.success("No Alerts")

# ==========================
# CAPTURE STATS
# ==========================

st.sidebar.subheader("📊 Capture Stats")

st.sidebar.write(
    f"Total Packets: {prototype.total_packets}"
)

st.sidebar.write(
    f"UI Packets: {len(ui_packets)}"
)

st.sidebar.write(
    f"Export Packets: {len(export_packets)}"
)
# ==========================
# METRICS
# ==========================

tcp_count = sum(
    1 for p in ui_packets
    if p["protocol"] == "TCP"
)

udp_count = sum(
    1 for p in ui_packets
    if p["protocol"] == "UDP"
)

dns_count = sum(
    1 for p in ui_packets
    if p["service"] == "DNS"
)

icmp_count = sum(
    1 for p in ui_packets
    if p["protocol"] == "ICMP"
)

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Packets", prototype.total_packets)
c2.metric("TCP", tcp_count)
c3.metric("UDP", udp_count)
c4.metric("DNS", dns_count)
c5.metric("ICMP", icmp_count)

st.divider()

# ==========================
# PACKET TABLE
# ==========================

st.subheader("📋 Recent Packets")

if filtered_packets:

    df = pd.DataFrame(filtered_packets)

    st.dataframe(
        df,
        use_container_width=True,
        height=400
    )

else:
    st.info("No packets captured.")

# ==========================
# CHARTS
# ==========================

col1, col2 = st.columns(2)

# --------------------------
# Top Source IP
# --------------------------

with col1:

    st.subheader("Top Source IPs")

    src_counter = Counter(
        p["source_ip"]
        for p in ui_packets
        if p["source_ip"]
    )

    src_df = pd.DataFrame(
        src_counter.most_common(10),
        columns=["IP", "Count"]
    )

    if not src_df.empty:
        st.bar_chart(
            src_df.set_index("IP")
        )

# --------------------------
# Top Destination IP
# --------------------------

with col2:

    st.subheader("Top Destination IPs")

    dst_counter = Counter(
        p["destination_ip"]
        for p in ui_packets
        if p["destination_ip"]
    )

    dst_df = pd.DataFrame(
        dst_counter.most_common(10),
        columns=["IP", "Count"]
    )

    if not dst_df.empty:
        st.bar_chart(
            dst_df.set_index("IP")
        )

# ==========================
# PROTOCOL PIE
# ==========================

st.subheader("Protocol Distribution")

protocol_counter = Counter(
    p["protocol"]
    for p in ui_packets
)

proto_df = pd.DataFrame(
    protocol_counter.items(),
    columns=["Protocol", "Count"]
)

if not proto_df.empty:

    st.dataframe(
        proto_df,
        use_container_width=True
    )

# ==========================
# DNS QUERIES
# ==========================

st.subheader("🌐 Top DNS Queries")

dns_counter = Counter(
    p["dns_query"]
    for p in ui_packets
    if p["dns_query"]
)

dns_df = pd.DataFrame(
    dns_counter.most_common(10),
    columns=["Query", "Count"]
)

if not dns_df.empty:
    st.table(dns_df)

# ==========================
# FOOTER
# ==========================

st.caption(
    "UI shows latest 500 packets. "
    "Exports contain complete capture history."
)


time.sleep(2)
st.rerun()
