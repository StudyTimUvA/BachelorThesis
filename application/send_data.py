"""
This script is used to send data over the network.
It parses command line arguments, and then calculates the required values to write to a config file for ITGSend.

After writing the config file, it starts the ITGSend process, and waits for it to finish.

Arguments:
    -d/--destination: The destination IP address.
    -p/--port: The destination starting port, increments for each flow.
    -V/--verbose: Whether to print verbose.
    -t/--time: The amount of time to send data for in seconds.
    -z/--packets: The number of packets to send per flow.
    -c/--rate: The rate at which to send packets in packets/sec.
    -k/--size: The size of each packet in KB.
    -f/--flows: The number of flows to send.

    Note: The most restrive of -t, -z and -c will be used.
"""

import argparse
import subprocess

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
parser.add_argument(
    "-z",
    "--packets",
    type=int,
    default=1000,
    help="The number of packets to send per flow."
)
parser.add_argument(
    "-c",
    "--rate",
    type=int,
    default=2,
    help="The rate at which to send packets in packets/sec."
)
parser.add_argument(
    "-k",
    "--size",
    type=int,
    default=100,
    help="The size of each packet in KB."
)
parser.add_argument(
    "-f",
    "--flows",
    type=int,
    default=1,
    help="The number of flows to send."
)

# Parse the arguments
args = parser.parse_args()
time_between_flows = args.time / (args.flows)
address = args.destination
starting_port = args.port
starting_duration = args.time

# Write the itg file
with open("parameters.itg", "w") as config_file:
    for flow in range(args.flows):
        duration = int((starting_duration - (time_between_flows * flow)) * 1000)
        delay = int((time_between_flows * flow) * 1000)

        config_file.write(
            f"-a {address} -rp {starting_port + flow} -t {duration} -T TCP -d {delay} -C {args.rate}\n")

# Start the ITGSend process
print("Starting ITGSend")
process = subprocess.Popen(["ITGSend", "parameters.itg"],
                           stdout=subprocess.DEVNULL if not bool(args.verbose) else None)
process.wait()

# TODO: version of script using iperf3
