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
    sniff(count = _count, store = _store, prn = _prn, filter = _filter, timeout = _timeout, iface = _iface)
    return

def simple_packet_capture(_source_ip_address, _destination_ip_address, _destination_port_number):
    _filter = "src host " + _source_ip_address \
             + " and dst host " + _destination_ip_address \
             + " and dst port " + _destination_port_number
    _prn = ""
    sniff(count = 1, prn = _prn, filter = _filter)
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
    packet_capture(1, parsing_packet, "UDP")
    print("break")
    return

if __name__ == "__main__":
    main()