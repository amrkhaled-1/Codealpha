import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from termcolor import colored
from colorama import init
from datetime import datetime

init()  # Enable color on Windows terminals

# Argument parser
parser = argparse.ArgumentParser(description="Advanced Network Sniffer")
parser.add_argument("-c", "--count", type=int, help="Number of packets to capture", default=0)
parser.add_argument("-i", "--interface", help="Interface to sniff on", default=None)
parser.add_argument("-o", "--output", type=str, help="Save captured packets to PCAP file")
args = parser.parse_args()

captured_packets = []

# Color-coded print function
def colored_output(timestamp, src, dst, proto, ports):
    color = {
        "UDP": "green",
        "TCP": "blue",
        "ICMP": "yellow",
        "OTHER": "white"
    }.get(proto, "white")

    message = f"[{timestamp}] {src} -> {dst} | {proto} {ports}"
    print(colored(message, color))

# Packet handler
def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "OTHER"
        ports = ""

        if TCP in packet:
            proto = "TCP"
            ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            proto = "UDP"
            ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
        elif ICMP in packet:
            proto = "ICMP"

        colored_output(timestamp, src, dst, proto, ports)
        captured_packets.append(packet)

# Sniffing
print(colored("[*] Starting packet capture... Press Ctrl+C to stop.", "cyan"))
try:
    sniff(prn=process_packet, count=args.count, iface=args.interface, store=False)
except KeyboardInterrupt:
    print(colored("\n[*] Capture stopped by user.", "red"))

# Save if requested
if args.output:
    wrpcap(args.output, captured_packets)
    print(colored(f"[*] Packets saved to {args.output}", "green"))
