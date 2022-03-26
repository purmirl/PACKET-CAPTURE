"""
Quiver Project : Simple Packet Capture Script with Python Scapy by PeTrA. 2022~
Quiver 1.0
Language : Python3.8.2 on pycharm IDE
Library : Scapy2.4.3
@quiver.py
https://github.com/purmirl/PACKET-CAPTURE/quiver
last update : 2022 MAR
"""
# from scapy.layers.inet import ICMP
# from scapy.sendrecv import sniff
from scapy.all import *


def packet_capture(_count, _prn, _filter):
    sniff(prn = parsing_packet, filter = 'tcp')
    # sniff(count = _count, prn = _prn, filter = _filter)
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