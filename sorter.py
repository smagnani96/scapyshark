import argparse

from scapy.all import PacketList
from scapy.config import conf
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader, PcapWriter


def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        'output', help='Output pcap file', type=str)
    parser.add_argument(
        'pcaps', nargs="+", help='Pcap files', type=str)
    return parser.parse_args().__dict__


def main():
    global mod
    args = parse_arguments()
    sortedp: PacketList = []
    for pcap in args["pcaps"]:
        sortedp += PcapReader(pcap).read_all()

    sortedp = sorted(sortedp, key=lambda x: x.time)
    w = PcapWriter(args["output"])
    w.linktype = conf.l2types.layer2num[Ether]
    w.write_header(None)
    for x in sortedp:
        w.write_packet(x)


# uses tshark
if __name__ == '__main__':
    main()
