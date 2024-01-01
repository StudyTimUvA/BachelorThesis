"""
This script is used to send data over the network.
It parses command line arguments, and then calculates the required values to write to a config file for ITGSend.
"""

import argparse
import subprocess
import time

parser = argparse.ArgumentParser(
    prog="Data Sender",
    description="Send data over the network using ITGSend."
)

parser.add_argument(
    "-d",
    "--destination",
    type=str,
    required=True,
    help="The destination IP address."
)
parser.add_argument(
    "-p",
    "--port",
    type=int,
    help="The destination starting port, increments for each flow.",
    default=9001
)
parser.add_argument(
    "-V",
    "--verbose",
    type=bool,
    default=False,
    help="Whether to print verbose."
)
parser.add_argument(
    "-t",
    "--time",
    type=int,
    default=10,
    help="The amount of time to send data for in seconds."
)
# parser.add_argument(
#     "-z",
#     "--packets",
#     type=int,
#     default=1000,
#     help="The number of packets to send per flow."
# )
# parser.add_argument(
#     "-k",
#     "--size",
#     type=int,
#     default=1000,
#     help="The size of each packet in KB."
# )
parser.add_argument(
    "-f",
    "--flows",
    type=int,
    default=1,
    help="The number of flows to send."
)

args = parser.parse_args()

print(args)

time_between_flows = args.time / (args.flows)

address = args.destination
starting_port = args.port
starting_duration = args.time

with open("parameters.itg", "w") as config_file:
    for flow in range(args.flows):
        config_file.write(f"-a {address} -rp {starting_port + flow} -t {int((starting_duration - (time_between_flows * flow)) * 1000)} -T TCP -d {int(time_between_flows * flow * 1000)}\n")
        
print("Starting ITGSend")
process = subprocess.Popen(["ITGSend", "parameters.itg"])
process.wait()