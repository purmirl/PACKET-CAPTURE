"""
Quiver Project : Simple Packet Capture Script with Python Scapy by PeTrA. 2022~
Quiver 1.0
Language : Python3.8.2 on pycharm IDE
Library : Scapy2.4.3
@quiver.py
https://github.com/purmirl/PACKET-CAPTURE/quiver
last update : 2022 MAR
"""
from scapy.all import *
from scapy.layers.l2 import Ether, ARP

""" @:packet capture
sniff parameter
    01. count (integer) : packet capture count. if 0 --> unlimited.
    02. store (integer) : store captured packet. if 0 --> no store.
    03. prn (def name) : packet operate function (def).
    04. filter (string) : user filtering.
    05. timeout (integer) : sniffing timer (seconds).
    06. iface (string) : network interface.
"""
def packet_capture(_count, _store, _prn, _filter, _timeout, _iface):
    packet = sniff(count = _count, store = _store, prn = _prn, filter = _filter, timeout = _timeout, iface = _iface)
    return packet

""" @:user function
"""
def tcp_capture_srchost(_source_ip_address, _prn):
    _filter = "src host " + _source_ip_address \
             + " tcp"
    packet = sniff(count = 1, prn = _prn, filter = _filter)
    return packet

def tcp_capture_srchost_dsthost(_source_ip_address, _destination_ip_address, _prn):
    _filter = "src host " + _source_ip_address \
              + " and dst host " + _destination_ip_address \
              + " tcp"
    packet = sniff(count = 1, prn = _prn, filter = _filter)
    return packet

def tcp_capture_srchost_dsthost_dstport(_source_ip_address, _destination_ip_address, _destination_port_number, _prn):
    _filter = "src host " + _source_ip_address \
             + " and dst host " + _destination_ip_address \
             + " and dst port " + _destination_port_number \
             + " tcp"
    packet = sniff(count = 1, prn = _prn, filter = _filter)
    return packet

def arp_capture():
    while True:
        sniff(count = 1, filter = "arp", prn = parsing_arp, store = 0)
    return

def parsing_arp(_packet):
    _packet.show()
    ethernet_src = _packet[Ether].src # source mac address
    ethernet_dst = _packet[Ether].dst # destination mac address
    hwsrc = _packet[ARP].hwsrc # sender mac address
    psrc = _packet[ARP].psrc # sender ip address
    hwdst = _packet[ARP].hwdst # target mac address, if ARP request : set "00:00:00:00:00:00"
    pdst = _packet[ARP].pdst # target ip address
    op = _packet[ARP].op # operation code, 1 : request, 2 : reply
    return


def arp_capture_(_prn):
    _filter = "arp"
    while True:
        packet = sniff(count=1, filter=_filter)

    return

def parsing_packet(_packet):
    # packet = ICMP()
    # packet.show()
    _packet.show()
    # a = _packet[Raw].load
    # a.show()
    print("break")
    # print(result)
    return

def main():
    print("??")
    arp_capture()
    # _filter = "tcp"
    # sniff(count = 1, prn = parsing_packet, filter = _filter)

    print("break")
    return

if __name__ == "__main__":
    main()