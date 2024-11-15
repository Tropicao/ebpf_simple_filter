# Simple eBPF filter

This repository contains a very basic eBPF example dropping any incoming
ICMP packet on attached interface. It is based on libbpf.

This example has been developed to illustrate the talk "Modify your kernel
at runtime with eBPF!" given at Capitole du Libre 2024, at Toulouse, France

## Program behaviour

This very short demo exposes three features:

- the program drop any incoming ICMP traffic
- it emits a trace in ftrace buffer each time a packet is dropped
- it maintains a dropped counter packet in a dedicated map

## How to use it

- Build the program: `make`
- start a ping on the loopback interface: `ping localhost`
- on another console, start the program: `sudo ./simple_filter`
- you should observe the following:
  - the ping is not successful anymore
  - the simple_filter program starts logging the number of dropped packets
  - if you take a look at the ftrace buffer (`cat /sys/kernel/tracing/trace_pipe`), you will see raw traces emitted by the eBPF program each times it drops a packet
