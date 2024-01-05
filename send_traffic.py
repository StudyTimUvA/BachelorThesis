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
import struct
import time

def create_byte_string(switch_id, delay):
    # Pack integers into binary data using struct.pack
    switch_id = struct.pack("i", switch_id)
    delay = struct.pack("i", delay)

    # Replace \x01 with switch_id and \x02 with delay
    modified_bytes = b"\x00\x01\x00\x00\x00\x00\x00\x02".replace(b"\x01", switch_id[:1]).replace(b"\x02", delay[:1])

    return modified_bytes

NUM_PACKETS = 20
NUM_SWITCHES = 4

# Define the target IP and port
target_ip = "127.0.0.1"
target_port = 8001
conf.iface="lo"

# Craft a TCP SYN packet
tcp = TCP(dport=target_port, sport=443, flags="S", seq=1)

options = []
for num_packet in range(NUM_PACKETS):
    switch_id = (num_packet%NUM_SWITCHES)+1
    delay = random.randint(0, 15)
    options.append((114, create_byte_string(switch_id, delay)))

options.append((114, b"\x00\x01\x00\x00\x00\x00\x00\x00"))

for option in options:
    tcp.options = [option]
    
    ip = IP(dst=target_ip, ttl=10)
    tcp_packet = ip / tcp

    # Send the packet and wait for a response
    response = send(tcp_packet, verbose=0)
    time.sleep(0.2)
# response = sr1(tcp_packet, verbose=1, timeout=3)

# Check if a response was received
if response:
    # Process the response
    print("Received a response:")
    response.show()
else:
    print("No response received.")