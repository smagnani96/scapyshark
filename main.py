import argparse
import atexit
import ctypes as ct
import importlib.util
import multiprocessing
import os
import sys
import threading
from typing import Any

from scapy.all import ETH_P_ALL, SOL_PACKET
from scapy.arch.linux import L2ListenSocket
from scapy.config import conf
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter

_lib = ct.CDLL(None)
mod = None


class SocketStats(ct.Structure):
    _fields_ = [
        ("tp_packets", ct.c_uint32),
        ("tp_drops", ct.c_uint32),
        ("tp_freeze_q_cnt", ct.c_uint32)]


class MySocket(L2ListenSocket):
    def __init__(self, workerId=0, fanout=False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.stats = SocketStats()
        self.workerId = workerId
        if fanout:
            # fanout type << 16 | fanout_group
            self.ins.setsockopt(SOL_PACKET, 0x12, (0x1 << 16) | 42)  # rollover

    def updateStats(self):
        stats = SocketStats()
        size = ct.c_int(ct.sizeof(stats))
        a = _lib.syscall(55, self.ins.fileno(), SOL_PACKET,
                         0x6, ct.byref(stats), ct.byref(size))
        if a >= 0:
            self.stats = SocketStats(
                self.stats.tp_packets + stats.tp_packets,
                self.stats.tp_drops + stats.tp_drops,
                self.stats.tp_freeze_q_cnt + stats.tp_freeze_q_cnt)

    def statsTimer(self):
        self.updateStats()
        print("Statistics Worker:", self.workerId, "ThreadID:", threading.get_ident(), "Rec:", self.stats.tp_packets, "Drop:",
              self.stats.tp_drops, "Freeze:", self.stats.tp_freeze_q_cnt)
        t = threading.Timer(2, self.statsTimer, args=())
        t.daemon = True
        t.start()

    def packets(self):
        pass


def thread(interface, promiscuous, filter, output="", workerId=0, isFanout=False, shared_var=None):
    global mod
    pw: PcapWriter = None
    if output:
        if output.endswith(".pcap"):
            if isFanout:
                output = output[:-5] + str(workerId) + output[-5:]
        else:
            if isFanout:
                output += str(workerId)
            output += ".pcap"
        pw = PcapWriter(output, sync=True)
        pw.linktype = conf.l2types.layer2num[Ether]
        pw.write_header(None)
        atexit.register(pw.close)

    s = MySocket(fanout=isFanout, workerId=workerId, type=ETH_P_ALL,
                 iface=interface, promisc=promiscuous, filter=filter)
    s.statsTimer()

    while True:
        cls, raw, ts = s.recv_raw()
        if output:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            pw.write_packet(raw, sec=sec, usec=usec)
        if mod:
            mod.ParseConcurrent(
                cls, raw, ts, workerId, shared_var) if isFanout else mod.Parse(cls, raw, ts, shared_var)


def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        'interface', help='Interface to sniff traffic', type=str)
    parser.add_argument('-f', '--filter', help='bpf filter',
                        type=str, default="")
    parser.add_argument('-p', '--promiscuous',
                        help='promiscuous mode', action="store_true")
    parser.add_argument(
        '-F', '--fanout', help='fanout mode', action="store_true")
    parser.add_argument(
        '-P', '--process', help='multi-process instead of multi-thread', action="store_true")
    parser.add_argument(
        '-o', '--output', help='pcap where to store packets', type=str, default="")
    parser.add_argument(
        '-m', '--module', help='load module to analyze packets', type=str, default="")
    args = parser.parse_args().__dict__
    if not args["output"] and not args["module"]:
        raise Exception("At least pcap file or module must be specified")
    return args


def main():
    global mod
    args = parse_arguments()

    if args["module"]:
        spec = importlib.util.spec_from_file_location(
            "module", os.path.abspath(args["module"]))
        mod = importlib.util.module_from_spec(spec)
        sys.modules["daje"] = mod
        spec.loader.exec_module(mod)
        if not hasattr(mod, "Parse") or not hasattr(mod, "ParseConcurrent"):
            raise Exception("Unvalid module")

    workerCount = 0
    if args["fanout"]:
        workerCount = os.cpu_count()
        shared_var = multiprocessing.Manager(
        ).dict() if args["process"] else {}
        for i in range(workerCount-1):
            if args["process"]:
                multiprocessing.Process(target=thread, args=(
                    args["interface"], args["promiscuous"], args["filter"], args["output"], i, True,), daemon=True).start()
            else:
                threading.Thread(target=thread, args=(
                    args["interface"], args["promiscuous"], args["filter"], args["output"], i, True,), daemon=True).start()
    thread(
        args["interface"], args["promiscuous"], args["filter"], args["output"], workerCount)


if __name__ == '__main__':
    main()
