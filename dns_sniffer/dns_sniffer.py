#!/usr/bin/env python3 

import scapy.all as scapy 
import sys 
from termcolor import colored

def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode()
        if domain not in domains_seen:
            domains_seen.add(domain)
            print(colored(f"\n[+] domain: {domain}", "green")

def main():
    global domains_seen
    domains_seen = set()
    interface = "ens33"
    scapy.sniff(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)

if __name__ == "__main__":
    main()
