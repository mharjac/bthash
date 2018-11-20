#! /usr/bin/python3

import socket, struct, os, array, datetime, codecs
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU
from scapy.all import rdpcap
from scapy.layers.inet import IP
from optparse import OptionParser

class IPSniff:
    def __init__(self, interface_name):
        self.interface_name = interface_name
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))
 
    def __process_ipframe(self, pkt_type, ip_header, payload):
        # Extract the 20 bytes IP header, ignoring the IP options
        fields = struct.unpack("!BBHHHBBHII", ip_header)
        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]
        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]
        self.chk_pkt(ip_src, ip_dst, ip_frame)
 
    def recv(self):
        while True:
            pkt, sa_ll = self.ins.recvfrom(MTU)
            if len(pkt) <= 0:
                break
            eth_header = struct.unpack("!6s6sH", pkt[0:14])
            dummy_eth_protocol = socket.ntohs(eth_header[2])
            if eth_header[2] != 0x800 :
                continue
            ip_header = pkt[14:34]
            payload = pkt[14:]
            self.__process_ipframe(sa_ll[2], ip_header, payload)
            
    def chk_pkt(self, ip_src, ip_dst, ip_frame):
        try:
            pkt_str = codecs.encode(ip_frame, "hex")
            #Searching for string "BitTorrent protocol" in packet payload
            pkt_off = pkt_str.find(b"426974546f7272656e742070726f746f636f6c")
            if pkt_off > 0:
               print("{} SRC: {:15} DST: {:15} HASH: {}".format(datetime.datetime.now(), socket.inet_ntoa(ip_src), socket.inet_ntoa(ip_dst),  pkt_str[pkt_off+54:pkt_off+94].decode()))
        except:
            print("fail")

def open_dmp(filename):
    net_dmp=rdpcap(filename)
    for pkt in net_dmp:
        try:
            pkt_str = codecs.encode(pkt.load, "hex")
            #Searching for string "BitTorrent protocol" in packet payload
            pkt_off = pkt_str.find(b"426974546f7272656e742070726f746f636f6c")
            if pkt_off > 0:
                print("{} SRC: {:15} DST: {:15} HASH: {}".format(datetime.datetime.fromtimestamp(pkt.time), pkt[IP].src, pkt[IP].dst, pkt_str[pkt_off+54:pkt_off+94].decode())) 
        except:
            pass

def main():
    epilog = 'Example: ./bthash.py -i eth0'
    parser = OptionParser(epilog = epilog)
    parser.add_option("-i", "--interface", dest="interface", help="interface to monitor")
    parser.add_option("-f", "--filename", dest="filename", metavar="FILE", help="pcap FILE to analyse")
    (options, args) = parser.parse_args()

    if options.interface:
        ip_sniff = IPSniff(options.interface)
        ip_sniff.recv()
    elif options.filename:
        open_dmp(options.filename)
    else:
        parser.print_help()
            
if __name__ == "__main__": main()
