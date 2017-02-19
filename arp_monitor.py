#! /usr/bin/python3
"""
an ARP monitor
"""

from scapy.all import sniff, ARP
from signal import signal, SIGINT
import sys

ip_and_mac ={}

def monitor_arp(pkt):
    """
    as a parameter of fuction sniff
    """
    if pkt[ARP].op == 2:
        print(
            pkt[ARP].hwsrc + 
            ' ' + 
            pkt[ARP].psrc
        )
    # Device is new.Remember it.  
    if ip_and_mac.get(pkt[ARP].psrc) == None:
        print(
            'Found new device ' + 
            pkt[ARP].hwsrc + 
            ' ' +
            pkt[ARP].psrc   
        )
        ip_and_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc
    # Device is known but has a different IP.  
    elif ip_and_mac.get(pkt[ARP].psrc) and \
         ip_and_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
        print(
            pkt[ARP].hwsrc +
            ' has got new ip ' +
            pkt[ARP].psrc + 
            ' (old ' +
            ip_and_mac[pkt[ARP].psrc] +
            ')'
        )
        ip_and_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

sniff(
    prn=monitor_arp, 
    filter='arp', 
    iface='eth0', 
    store=0
)
