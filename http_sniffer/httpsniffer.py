#!/usr/bin/env python3 

import scapy.all as scapy 
from scapy.layers import http

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            url = "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(packet[scapyRaw].load.decode())
            print(url)
            print("\n\n")

def sniff(interface):
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def main():
    sniff("ens33")

if __name__ == "__main__":
    main()
