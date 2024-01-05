# from scapy.all import *

# def print_pkt(pkt):
#     pkt.show()
#     print("")

# pkt = sniff(filter='tcp and port 80', prn=print_pkt)

from scapy.all import *
import time

# Define the interface to listen on
conf.iface="lo"
message = ""
counter = 0
array = []

# Sniff TCP packets
def process_packet(packet):
    global message, counter, array

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        # print(f"No TCP layer, {packet[IP].src}>{packet[IP].dst}")
        return

    for option in packet.getlayer(TCP).options:
        print(option)
        if option[0] == 114:
            values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

            switch_id = int(values[0:4], 16)
            delay = int(values[4:20], 16)

            if switch_id == 0 and delay == 0:
                continue

            print(f"Switch ID: {switch_id}, delay: {delay}")
            array.append(delay)
            return

        elif option[0] == 132:
            values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])
            switch_id = int(values[0:4], 16)
            delay = int(values[12:20], 16)

            if switch_id == 0:
                continue

            print(f"Switch ID: {switch_id}, delay: {delay}")
            array.append(delay)
            return

    print(f"Received packet without INT data, {[x[0] for x in packet.getlayer(TCP).options]}")


# Start sniffing on the specified interface
# sniff(prn=process_packet, store=0)

sniffer = AsyncSniffer(prn=process_packet, store=0)
sniffer.start()

print("Started sniffing")
while(True):
    time.sleep(120)

sniffer.stop()