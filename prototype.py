from scapy.all import *
from collections import Counter as c
from datetime import datetime
import threading

data_lock = threading.Lock()
#globaldata
total_packets=0

ui_packets = []      # Last 500 packets (UI)
export_packets = []     # Full capture (Exports)
def process_packet(packet):
    global total_packets

    total_packets += 1

    data = packet_analyzer(packet)

    export_packets.append(data)

    ui_packets.append(data)

    if len(ui_packets) > 500:
        ui_packets.pop(0)

   
def packet_analyzer(packet):
    time_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = ""
    dst_ip = ""
    protocol = ""
    src_port = ""
    dst_port = ""
    flags=""
    dnsq=""
    SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
}
    #adding analyzed data guys
    if packet.haslayer(IP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst    
    elif packet.haslayer(IPv6):
        src_ip=packet[IPv6].src
        dst_ip=packet[IPv6].dst 
    if packet.haslayer(UDP):
        protocol="UDP"
        src_port=packet[UDP].sport
        dst_port=packet[UDP].dport
    elif packet.haslayer(TCP):
        protocol="TCP"
        src_port=packet[TCP].sport
        dst_port=packet[TCP].dport
        flags=str(packet[TCP].flags)
    elif packet.haslayer(ICMP):
        protocol="ICMP"
    if packet.haslayer(DNSQR):
        dnsq = packet[DNSQR].qname.decode(errors="ignore")
    service = SERVICES.get(dst_port, "Unknown")
    return {
        "packet_number":total_packets,
        "Time_Stamp":time_stamp,
        "source_ip":src_ip,
        "destination_ip":dst_ip,
        "protocol":protocol,
        "source_port":src_port,
        "destination_port":dst_port,
        "service": service,
        "flags":flags,
        "dns_query":dnsq,
        "packet_length" :len(packet),
        "info":packet.summary()
    }

def packet_counter(ui_packets):
    return c(packet["protocol"] for packet in ui_packets if packet["protocol"])

def packet_detect():

    sniff(
        prn=process_packet,
        store=False
    )
    print("="*50)
    stats=packet_counter(ui_packets)
    print("-----------------")
    print("|protocol| count ")
    for pro,cn in stats.items():
        print(f"| {pro}    |  {cn} ")

    print("total_packets -->",total_packets)
      
def packet_show(packet):
    for key,value in packet.items():
        #data sent to the Total_packets for saving them and for future usage in web views
        print(f"{key} --> {value}")
    print("="*50)
    
#driver code

if __name__=="__main__":
    try:
        packet_detect()
    except KeyboardInterrupt:
        print("keyboard stoped")
        
    except Exception as e:
        print(e)
