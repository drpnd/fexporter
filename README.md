[![GitHub license](https://img.shields.io/github/license/drpnd/fexporter.svg)](https://github.com/drpnd/fexporter)
[![Jenkins](https://img.shields.io/jenkins/s/https/pix.jar.jp/jenkins/job/fexporter.svg)](https://img.shields.io/jenkins/s/https/pix.jar.jp/jenkins/job/fexporter.svg)

# Fexporter: IPFIX Flow Exporter

*Fexporter* is an IPFIX flow exporter implementation targeting for BSD, Linux,
and macOS.
It simply exports flows using IPFIX over UDP without packet sampling.
This software supports both IPv4 and IPv6 flows.

## Dependencies

* libpcap


## How to use

Current version of fexporter is simple and supports minimal options.
The following sections describe how to use this software.


### Compile the software

    $ cmake .
    $ make


### Run the software as root

    # ./build/fexporter <ipfix-agent-ip-address>:<port-number> <interface>

For example, the following command is used to sniff eth0 and export the flows
to `127.0.0.1:4739`.

    $ sudo ./build/fexporter 127.0.0.1:4739 eth0
