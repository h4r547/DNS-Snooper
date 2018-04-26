from scapy.all import *

packets = rdpcap('dns.pcap')

for p in packets:
    if p.haslayer(DNS):
        print p[DNS].qd.qname