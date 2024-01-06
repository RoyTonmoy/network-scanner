#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify the ip address or ip range" )
    args = parser.parse_args()

    if not args.target:
        print("[-] please specify ip range, use --help for more info")

    return args

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list =scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
       

def print_result(result_list):
    print("IP\t\t\tMac Address")
    print("------------------------------------------------")

    for client in result_list:
        print(f"{client['ip']}\t\t{client['mac']}")

args = get_arguments()

scan_result = scan(args.target)      
print_result(scan_result)  
