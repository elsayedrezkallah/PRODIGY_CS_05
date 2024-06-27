import sys
from scapy.all import *
import time
import os

# Function to get network interface names
def get_interface_names():
    interfaces = []
    for iface in get_if_list():
        interfaces.append(iface)
    return interfaces

# Function to handle each packet
def handle_packet(packet, log):
    # Check if the packet contains IP layer
    if packet.haslayer(IP):
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Extract protocol
        proto = packet[IP].proto
        # Extract payload data
        payload = packet.payload
        # Write packet information to log file
        log.write(f"Packet: {src_ip} -> {dst_ip} (Protocol: {get_protocol_name(proto)})\n")
        log.write(f"Payload: {payload}\n\n")

# Funtion of protocols name
def get_protocol_name(proto_num):
    protocols = {
        1: "ICMP",
        2: "IGMP",
        3: "GGP",
        4: "IPencap",
        5: "ST",
        6: "TCP",
        7: "CBT",
        8: "EGP",
        9: "BBN-RCC-MON",
        10: "NVP-II",
        11: "PUP",
        12: "ARGUS",
        13: "EMCON",
        14: "XNET",
        15: "CHAOS",
        16: "UDP",
        17: "UDP",
        18: "MUX",
        19: "DCN-MEAS",
        20: "HMP",
        21: "PRM",
        22: "XNS-IDP",
        23: "TRUNK-1",
        24: "TRUNK-2",
        25: "LEAF-1",
        26: "LEAF-2",
        27: "RDP",
        28: "IRTP",
        29: "TP++",
        30: "DCCP",
        31: "IPV6",
        32: "SDRP",
        33: "IPV6-Route",
        34: "IPV6-Frag",
        35: "IDRP",
        36: "RSVP",
        37: "GRE",
        38: "ESP",
        39: "AH",
        40: "I-NLSP",
        41: "SCTP",
        42: "IPv6-ICMP",
        43: "IPv6-NoNxt",
        44: "IPv6-Opts",
        45: "any",
        46: "CFTP",
        47: "IL",
        48: "IPv6-NoFrag",
        49: "IPv6-RouteAll",
        50: "IPv6-FragAll",
        # Add more protocols as needed
    }
    return protocols.get(proto_num, "Unknown")

# Function to display packet sniffing statistics
def display_stats(packet_count, start_time):
    elapsed_time = time.time() - start_time
    print(f"\nPacket sniffing statistics:")
    print(f"  Packets captured: {packet_count}")
    print(f"  Elapsed time: {elapsed_time:.2f} seconds")
    print(f"  Packets per second: {packet_count / elapsed_time:.2f}")

# Function to filter the packet
def filter_packets(filter_criteria, packet):
    if filter_criteria == "":
        return True
    filter_parts = filter_criteria.split()
    filter_type = filter_parts[0]
    filter_value = filter_parts[1]
    if filter_type == 'rc':
        return packet.haslayer(IP) and packet[IP].src == filter_value
    elif filter_type == 'dst':
        return packet.haslayer(IP) and packet[IP].dst == filter_value
    elif filter_type == 'protocol':
        if filter_value.lower() == 'http':
            return packet.haslayer(TCP) and packet.dport == 80  # assuming HTTP is on port 80
        else:
            proto_layers = {
                'icmp': ICMP,
                'tcp': TCP,
                'udp': UDP,
                # Add more protocols as needed
            }
            if filter_value.lower() in proto_layers:
                return packet.haslayer(proto_layers[filter_value.lower()])
            else:
                return False
    else:
        return False

# Main function to start packet sniffing
def main(interface, filter_criteria):
    # Create log file name based on interface
    logfile_name = f"sniffer_{interface}_log.txt"
    # Open log file for writing
    with open(logfile_name, 'w') as logfile:
        print(f"Sniffing packets on interface {interface}...")
        print(f"Log file: {logfile_name}")
        start_time = time.time()
        packet_count = 0
        try:
            # Start packet sniffing on specified interface with filtering
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile) if filter_packets(filter_criteria, pkt) else None, store=0, count=10000)
            packet_count = 10000
        except KeyboardInterrupt:
            packet_count = sniff.get_packet_count()
            sys.exit(0)
        finally:
            display_stats(packet_count, start_time)
            print("Packet sniffing stopped.")

# Check if the script is being run directly
if __name__ == "__main__":
    # Get network interface names
    interfaces = get_interface_names()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    # Ask user to select an interface
    interface_num = int(input("Enter the number of the interface to sniff: "))
    interface = interfaces[interface_num - 1]

    # Ask user if they want to filter packets
    filter_packets_criteria = input("Do you want to filter packets? (y/n): ")
    if filter_packets_criteria.lower() == 'y':
        print("Select a protocol to filter:")
        print("1. ICMP")
        print("2. TCP")
        print("3. UDP")
        print("4. HTTP")
        choice = input("Enter the number of your choice: ")
        protocols = {
            '1': 'icmp',
            '2': 'tcp',
            '3': 'udp',
            '4': 'http'
        }
        if choice in protocols:
            filter_criteria = f"protocol {protocols[choice]}"
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)
    else:
        filter_criteria = ""

    # Call the main function with the specified interface and filter criteria
    main(interface, filter_criteria)
