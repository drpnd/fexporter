# fexporter: Flow Exporter

This software implements the flow exporter using IPFIX (formerly known as NetFlow).

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
