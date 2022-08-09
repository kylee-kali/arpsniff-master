#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            print("http://" + url.decode("utf-8"))
            print(packet.show)

sniff("eth0")
