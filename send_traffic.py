# from scapy.all import *

# TTL=10
# SRC_IP="127.0.0.1"
# DST_IP="192.168.2.51"
# DST_PORT=9001

# ip = IP(dst=DST_IP)
# tcp = TCP(dport=DST_PORT, flags="S", seq=12345)
# pkt = ip / tcp
# send(pkt, verbose=True)

from scapy.all import *

NUM_PACKETS = 1

# Define the target IP and port
target_ip = "127.0.0.1"
target_port = 8001
conf.iface="lo"

# Craft a TCP SYN packet
tcp = TCP(dport=target_port, sport=443, flags="S", seq=[i for i in range(NUM_PACKETS)])
tcp.options = [(114, b"\x00\x01\x00\x00\x00\x00\x00\x02")]

ip = IP(dst=target_ip, ttl=10)
tcp_packet = ip / tcp

tcp_packet.show()

# Send the packet and wait for a response
response = send(tcp_packet, verbose=1)
# response = sr1(tcp_packet, verbose=1, timeout=3)

# Check if a response was received
if response:
    # Process the response
    print("Received a response:")
    response.show()
else:
    print("No response received.")