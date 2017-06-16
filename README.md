# QUIC Channel

## Introduction

QUIC Channel streams network traffic over the QUIC routing protocol. Reasoning:

 - Typical TCP packets are not resilient to routing changes mid-stream.
 - UDP alone is not robust enough to bad conditions to serve as a VPN protocol.
 - QUIC supports multiplexed communications over UDP, and is resilient to packet loss and route changes.
 - QUIC features include bandwidth estimation, congestion control, feed-forward error correction.
 - QUIC uses end-to-end TLS encryption for security.

This repo is currently considered an experiment and is likely to change drastically over time.

## Connectivity

There are several planned interfaces to the router implementation:

 - **VPN**: a tun interface over which network packets are sent.
 - **SOCKS5**: socks proxy over which connections can be made within a desktop app.
 - **API**: go API to interface directly without an intermediate socket.

## Implementation

The concepts in this repo are summarized:

 - **Node**: implementation of a node in the network. Listener and dialer.
 - **Channel**: a QUIC session between two peers, transported over one or more circuits.
 - **Connection**: a one-hop path between two peers. In some cases, the internet is used as a single hop.
 - **Discovery**: discovers connections to peers with UDP broadcast and uses a list of target peers for STUN/TURN negotiation.
 - **Session**: a conversation over a connection, distinct between different links (WiFi, Ethernet, etc).
 - **Stream**: a two-way conversation in a session.
 - **Control Stream**: the first stream opened in a session, used for passing out-of-band messages.
 - **Circuit**: a series of streams between peers forming a path between two peers.
 - **Circuit Stream**: a stream implementing a circuit.

In-band and out-of-band control packets are encoded with Protobuf.

## Routing

The primary goals of this project vs babeld:

 - Route in user-space. Particularly important for cross-platform.
 - Accept only authenticated peers, and encrypt traffic in channels.
 - Build encrypted circuits between devices representing routes, then multiplex over those routes.

We have two choices here for design:

 1. Build full paths. Make the decision on which path to take (including forks in the road mid-way) at the terminations of the channel.
 2. Do not maintain knowledge of the full path, and allow individual nodes decide how to send traffic (this is the Babel approach).

Choice #2 here is the optimal choice for performance, but poor for security, as a rogue node can swallow packets and the system is unable to determine where in the path the blockade occurs. Choice #1 has more memory and bandwidth overhead, is slower to react to network changes, but is more secure. Choice #1 is what we're using in the approach implemented here.

The routing algorithm works like this:

 - Gossip probes through the connection graph building pending circuits outwards.
 - The memory and bandwidth overhead of maintaining a circuit is reduced due to the on-demand and short lived nature of circuits.
 - Circuits can have further probing restrictions, like avoiding different types of network partitions (entering a network pocket, for example).
 - When a probe reaches a termination (dead-end) a message is sent in the reverse direction to indicate that this link is a dead-end.
 - When all probes return with dead-end status to the originator an ICMP not-reachable state can be realized.
 - The target of the circuit establishes incoming routes.

The gossip algorithm works like:

 - Imagine the network as a graph of connections between nodes.
 - When attempting to make a connection to a peer, a node issues a route build request.
 - This request is gossiped to all connected peers.
 - Each peer adds its own identifier to the chain, and passes the request on.
 - Requests are terminated when there are no peers to gossip to that are not already in the chain.
 - When the target receives the request, it immediately establishes a channel back the opposite direction.

The general rules are:

 - Never re-transmit a route probe to a peer that appears in the probe's existing path.
 - Drop incoming probes that already contain the local peer.

In this case, the chain from `peer1` to `peer4` is the same. The metric messages from `peer4` should not be duplicated over multiple connections.

Circuits can be in the following states:

 - PENDING - The circuit path is being built, and will expire quickly if not established.
 - ESTABLISHED - The circuit path is established, and being used. Expires in a longer period of time.

In the code we have the control scheme:

 - The **Node** manages a **Discovery** that manages **Peer** in a database of last seen events and discovery events.
 - The **Node** builds a **CircuitSession** with **Peer** on the local network.
 - The **CircuitSession** manages communications with the peer, and emits **Circuit** for incoming valid circuit build operations.
 - The **CircuitBuilder** is built and managed by the **Node**.
 - The **CircuitBuilder** is responsible for emitting route probes, storing possible routes to a peer...
 - The **Channel** type is built and managed by the **Node**.
 - The **Channel** type manages multiplexing a buffered read/writer over the available circuits to a peer.
 - The **Circuit** is instantiated when a **Circuit Probe** comes back with a valid remote circuit.

The implementation of a channel / circuit:

 - Implement net.PacketConn over the circuit.
 - Make a net.PacketConn multiplexer
 - Use multiplexing over multiple Circuits with writing packets.
 - Out-of-order or dropped packets is OK! QUIC can handle it. But track packet loss and RTT.
 - Use in-band packets for statistics used for control flow. Interim steps in the Circuit will insert these packets as well.
 - Note: this might mess with the QUIC packet flow management code a bit. Ensure the difference in performance between circuits is low.

Uncategorized thoughts:

 - Pending circuits could be given an expiry timestamp, which can be used as an upper bound for latency between two hosts.
 - First task will be spitting the logic into multiple go packages so we can re-use the Quic session management code for different level sessions.
 - TURN vs STUN: over an internet route, encode information in Circuit Probes about STUN connection info. Use this as a secondary channel path.
 - Identify the interface a session is on. Make a reliable identifier for this (uint32 hash?).

Peer tracking:

 - Discovery should build a database of observed peers. Observed events should be tracked. Maybe use a BoltDB database?
 - An event would be: UDP broadcast observed, Circuit Build relay observed, etc.
 - This can be analyzed to infer potential connectivity with a peer before actually making a route request.
 - Will also be useful for visualization.
 - Can also store Routes that we can then use later.

## Packet Routing

**VPN** style routing:

 - Make a network interface on the machine (TUN)
 - Use `gopacket` to do on-demand decoding of the destination address.
 - Translate the TCP packet stages through to the SOCKS5 layer.

**Proxy** style routing:

 - Listen on a port
 - Use the destination address, use a public key derived format
 - When connecting to a target, grab the channel (uses circuits) to the target.
 - The channel is a QUIC session with the target. Each stream will be used for a different connection over that channel.


## IP Translation

An IPV6 address looks like this:

```
+--------+-+------------+-----------+----------------------------+
| 7 bits |1|  40 bits   |  16 bits  |          64 bits           |
+--------+-+------------+-----------+----------------------------+
| Prefix |L| Global ID  | Subnet ID |        Interface ID        |
+--------+-+------------+-----------+----------------------------+
| 0xfd  (2byte) | caCertH[:4]|           publicKeyH[:10]         |
+--------+-+------------+-----------+----------------------------+
```

The Prefix/L 8 bits will always be `0xfd`. The global ID is treated as a
are treated as a single 5 byte segment, and is determined by taking the
first 5 bytes of the sha256 hash of the public key of the CA
certificate. This allows multiple clusters to be joined simultaneously
by running multiple quic-channel daemons together on the same machine
with different CA certs. The first byte of the Global ID will be cc, so
the first part of the IPV6 address will always be `fdcc:`. In the demos
in this repository, the cluster ID would then be `fdcc:4593:bfc4:ca`,
forming a base address of `fdcc:4593:bfc4:ca00::`.

The interface ID is determined by taking the first 10 bytes of the sha256
hash of the public key of the node.
