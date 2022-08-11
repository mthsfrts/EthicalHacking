#!/usr/bin/env python3

# Libraries
from scapy.all import *
import sys


def scapy_scanner():

    """Main Method that will creat the package and sent to the host, iterating on the range of ports that you will
    set """

    # Checking Command Line
    if len(sys.argv) != 4:
        print("Usage: %s ,target ip, startport, endport" % (sys.argv[0]))
        print(" e.g : sudo python3 scanner.py 192.168.0.1 22 80")
        sys.exit(0)

    target = str(sys.argv[1])
    startport = int(sys.argv[2])
    endport = int(sys.argv[3])
    print("Scanning " + target + " for open TCP ports\n")

    # 3-way handshake
    for ports in range(startport, endport + 1):
        try:
            pkt = IP(dst=target) / TCP(dport=ports, flags='S')
            response = sr1(pkt, timeout=0.2, verbose=0)

            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print("Port " + str(ports) + " is open on your destination " + str(target) + "!")

                sr(IP(dst=target) / TCP(dport=response.sport, flags='R'), timeout=0.2, verbose=0)

        except (AttributeError, IndexError, ValueError) as error:
            print(f"The Port - {ports} / Host - {target} could not be reached!!")

    print("Scan is complete!")


if __name__ == "__main__":
    scapy_scanner()
