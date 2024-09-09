HIRT: High-Speed Robust Tunnel leveraging Forward Erasure Correction and IPv6 Segment Routing
=========

HIRT is a network-layer Forward Erasure Correction (FEC) tunnel leveraging IPv6 Segment Routing.
HIRT transparently protects traffic going through the tunnel without user intervention.
It leverages Random Linear Coding (RLC) to create redundancy packets that will serve to recover losses.
The rate at which repair packets are generated depends on the estimated loss inside the tunnel with a simple yet efficient algorithm leveraging feedback from the decoding side to the encoding side.

HIRT is implemented usng [FastClick](https://www.fastclick.dev), an extended version of the Click Modular Router featuring an improved Netmap support and a new DPDK support.
Thanks to FastClick, HIRT can sustain and protect up to more than 50 Gbps of traffic under 3% losses, recovering all losses. With lower losses, HIRT can sustain even more traffic.
The implementation is user-space only, but requires root access because, e.g., DPDK requires access to the NIC directly.

HIRT is the result of our ICNP 2024 paper available at (TODO).

Since HIRT heavily leverages FastClick, we strongly advice to look at FastClick's [Wiki](https://github.com/tbarbette/fastclick/wiki) to get more help information.

## HIRT simulator

The source code comes alongside the [HIRT simulator](https://github.com/louisna/HIRT-simulator.git) which compares HIRT with Maelstrom.

## Installation

HIRT is implemented as FastClick modules. As such, you need the same requirements as FastClick to build HIRT.
Additionally, you may prefer to install `moepgf` to fasten the RLC processing on encoding and decoding nodes.

We provide two methods to install HIRT, depending on the use-case.

### With DPDK (CloudLab)

This installation style requires support for DPDK for high-speed links.
Typically, we used this installation for CloudLab nodes to benchmark HIRT.

TODO

### Without DPDK (Starlink)

This installaiton style does not require DPDK. We used to evaluate HIRT over the Starlink medium, which does not require up to several Gbps of throughput.

```bash
$ ./configure  CFLAGS="-O3" CXXFLAGS="-std=c++11 -O3" --enable-intel-cpu --disable-dynamic-linking --enable-bound-port-transfer --enable-flow --disable-task-stats --disable-cpu-load --enable-all-elements --enable-multithread --enable-user-multithread --enable-poll --enable-local --enable-flow --enable-cpu-load --enable-user-timestamp --enable-bound-port-transfer
```

### moepgf library

RLC uses Galois Field instructions to ensure that computation is performed in finite fields. Such instructions are costly, and HIRT leverages AVX instructions to fasten the process through the [`moepgf` library](https://github.com/moepinet/libmoepgf).

Benchmarks (e.g., Figure 5 from the paper) show that using the library provides significant improvements, compared to a "simple" software implementation of these instructions.

Please follow installation's instructions: https://github.com/moepinet/libmoepgf.

## Launch

You can launch the encoder using the following command:

```
$ hirt/bin/click hirt/mininet/switch/configs/client-fec.click nobwfec=1 nofwfec=0 noencap=0 ipv4encapsrc="A.B.C.D" ipv4encapdst="E.F.G.H" macsrc="I:J:K:L:M:N" macdst="O:P:Q:R:S:T" windowsize=200 intif="veth0" extif="eth0"
```

This will encapsulate each received packet with an IPv4 source IP A.B.C.D and destination E.F.G.H and the MAC addresses source I:J:K:L:M:N and destination O:P:Q:R:S:T. This is required because we bypass the kernel, so we must provide valid MAC addresses to forward the packets.

The window size is set to 200 packets in this example. You must also correctly set the `intif` and `extif`, respectively the input and output interfaces of the encoder.
Just to be sure, the output interface is the interface that the encoder uses to output the packets INSIDE the tunnel.

TODO: how to start the decoder also.

## Citing

The paper is currently under press. It has been accepted to ICNP 2024 but is not published yet. For the time being, please use the following citation to refer this work:

```
@inproceedings{navarre2024high,
  title={A High-Speed Robust Tunnel using Forward Erasure Correction in Segment Routing},
  author={Navarre, Louis and Michel, Fran{\c{c}}ois and Barbette, Tom},
  booktitle={2024 IEEE 32nd International Conference on Network Protocols (ICNP)},
  year={Under press, 2024},
  organization={IEEE}
}
```


Getting help
------------
Use the github issue tracker (https://github.com/louisna/hirt/issues) or contact louis.navarre at uclouvain.be if you encounter any problem with HIRT.

The github issue tracker from FastClick (https://github.com/tbarbette/fastclick/issues) may be the more appropriate option for more general issues with the toolkit.

Please do not ask FastClick-related problems on the vanilla Click mailing list.
If you are sure that your problem is Click related, post it on vanilla Click's
issue tracker (https://github.com/kohler/click/issues).

