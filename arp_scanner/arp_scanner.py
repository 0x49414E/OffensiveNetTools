#!/usr/bin/env python3 

import signal
import scapy.all as scapy
import argparse 
from cryptography.utils import CryptographyDeprecationWarning 
import warnings 
import sys

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning) 

def ctrl_c(sig,frame):
    print("\n[!] Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Scanner")
    parser.add_argument('-t', '--target', required=True, dest='target',help='HOST / IP range to scan') 
    args = parser.parse_args()

    return args.target 

def scan(ip): 
    arp_packet = scapy.ARP(pdst=ip) 
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_packet = broadcast_packet/arp_packet # Operador composición 

    answered, unanswered = scapy.srp(arp_packet, timeout=1, verbose=False) 

    response = answered.summary() 

    if response:
        print(response)

def main():
    target = get_arguments()
    scan(target)

if __name__ == "__main__":
    main()
