#!/usr/bin/env python3

import signal
import sys
import argparse
import re
import subprocess
from termcolor import colored

def def_handler(sig,frame):
    print(colored(f"\n[!] Exiting...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT,def_handler) #CTRL + C

def get_arguments():
    parser = argparse.ArgumentParser(description="MAC Changer")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="Name of the Network Interface")
    parser.add_argument("-m", "--mac", required=True, dest="mac_address", help="New MAC Address")

    return parser.parse_args()

def validation(interface, mac_address):
    is_valid_interface = re.match(r'^[e][n|t][s|h]\d{1,2}$', interface)
    is_valid_mac = re.match(r'^([A-Fa-f0-9]{2}[:]){5}[A-Fa-f0-9]{2}$', mac_address)

    return is_valid_interface and is_valid_mac 

def change_mac_address(interface,mac_address):
    if validation(interface, mac_address):
       subprocess.run(["ifconfig", interface, "down"])
       subprocess.run(["ifconfig", interface, "hw", "ether", mac_address])
       subprocess.run(["ifconfig", interface, "up"])

       print(colored(f"\n[+] MAC Address changed to {mac_address}", "green"))
    else:
        print(colored(f"\n[!] Incorrect format.", "red"))

def main():
    args = get_arguments()
    change_mac_address(args.interface,args.mac_address) 

if __name__ == "__main__":
    main()
