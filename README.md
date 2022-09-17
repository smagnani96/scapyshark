![Linting](https://github.com/s41m0n/scapyshark/workflows/Linting/badge.svg)

# ScapyShark: Network Packet Analyzer and Monitoring

ScapyShark is a tool for capturing and analyzing network traffic. It offers the possibility to dump the traffic into pcap files and to apply custom monitoring logic on the network packet, by leveraging a plugin-architecture. Last but not least, it supports multi-core packet capture and monitoring using FANOUT groups, and it comes with a tool for sorting single pcaps into a unified capture.

## Usage

```bash
❯ python3 main.py --help
usage: main.py [-h] [-f FILTER] [-p] [-F] [-o OUTPUT] [-m MODULE] interface

positional arguments:
  interface             Interface to sniff traffic

optional arguments:
  -h, --help            show this help message and exit
  -f FILTER, --filter FILTER
                        bpf filter (default: )
  -p, --promiscuous     promiscuous mode (default: False)
  -F, --fanout          fanout mode (default: False)
  -P, --process         multi-process instead of multi-thread (default: False)
  -o OUTPUT, --output OUTPUT
                        pcap where to store packets (default: )
  -m MODULE, --module MODULE
                        load module to analyze packets (default: )
```

ScapyShark requires an **interface** to run, and at least 1 argument between **--output** and **--module**. While the former specified a pcap file where to dump the network traffic analyzed, the latter represents a path to a Python file where it is included additional monitoring logic to be applied on each network packet. ScapyShark is able to run on multi-core thanks to the **--fanout** option. To split workload between multiple processes instead of threads, specify the **--process** flag.

A Monitoring module is loaded as plugin, and it must implement the **Parse** and **ParseConcurrent** methods. A dictionary is shared among the main processed and this module accordingly, if using threads (normal dict) or processes (Manager().dict()).

An example to run such tool:

```bash
❯ sudo python3 main.py lo -o output.pcap -m examples/example.py -F -P
```

A packet sniffer for each core will spawn, dumping packets on **output{i}.cap** files (i is the number of the CPU core), and applying the additional monitoring logic described in **example.py**.

Finally, the [sorter](./sorter.py) tool is provided to aggregate packets captured from each core into a unique ordered file:

```bash
❯ python3 sorter.py unified.pcap output0.pcap output1.pcap output2.pcap output3.pcap
```
