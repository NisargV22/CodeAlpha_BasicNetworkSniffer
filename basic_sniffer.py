from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print("="*60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol}")

        # Optional: display packet summary
        # print(packet.summary())

# Start sniffing (press Ctrl+C to stop)
print("Starting packet capture... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=False)
