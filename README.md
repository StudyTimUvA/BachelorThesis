# BachelorThesis
This is the program written for my bachelor thesis project.
The project contains an evaluation platform for In-band Network Telemetry (INT) solutions.
A full description of the project can be found in the thesis document.

## In short
The platform is used to visualize data from INT enabled switches.
It can be used to visualize data generated from these switches, but also from the network traffic itself.
This data can be used to evaluate the performance of the network and the INT solution.
The platform supports two modes: a real-time mode, and a offline mode.
The real-time mode listen to a network interface, while the offline mode reads from one or more PCAP files.

## Installation
The platform is written and tested using python 3.8.10, but supports higher versions as well.

All dependencies can be installed using the following command:
```
pip3 install -r requirements.txt
```

## Usage
The platform can be started using the following command:
```
sudo python3 main.py
```

Generating data for the platform can be done using the following command:
```
sudo python3 generate_data.py
```
Adding a `-h` flag to the command will show the available options.

In case of using the D-ITG mode, then a receiver must be started using the following command:
```
ITGRecv
```