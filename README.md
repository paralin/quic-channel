# QUIC Channel

## Introduction

QUIC Channel streams network traffic over the QUIC routing protocol. Reasoning:

 - Typical TCP packets are not resilient to routing changes mid-stream.
 - UDP alone is not robust enough to bad conditions to serve as a VPN protocol.
 - QUIC supports multiplexed communications over UDP, and is resilient to packet loss and route changes.
 - QUIC features include bandwidth estimation, congestion control, feed-forward error correction.
 - QUIC uses end-to-end TLS encryption for security.

This repo is currently considered an experiment and is likely to change drastically over time.

## Certificates

The daemon expects the following files to be given:

 - **ca.crt**: a single certificate, used as the root.
 - **cert.crt**: one or more certificates, first cert is the server cert, previous are intermediates.
 - **key.pem**: private key for the first certificate in the cert.crt.

## Connectivity

There are several planned interfaces to the router implementation:

 - **VPN**: a tun interface over which network packets are sent.
 - **SOCKS5**: socks proxy over which connections can be made within a desktop app.
 - **API**: go API to interface directly without an intermediate socket.

## Implementation

The concepts in this repo are summarized:

 - **Node**: implementation of a node in the network. Listener and dialer.
 - **Connection**: a one-hop path between two peers. In some cases, the internet is used as a single hop.
 - **Circuit**: a combination of multiple connections between peers to form a multi-hop path from a source to a destination.
 - **Channel**: a QUIC session between two peers, transported over a circuit.
 - **Discovery**: discovers connections to peers and uses a list of target peers for STUN/TURN negotiation.

Out-of-band control packets and headers are encoded with Protobuf.

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

 - Gossip probes through the connection graph building routes between peers.
 - Probes are kept in memory of the peers until their expiration time (on the order of seconds to minutes) and repeated to peers that have not yet seen the probe.
 - Circuits can have further probing restrictions, like avoiding different types of network partitions (entering a network pocket, for example).
 - The target of the circuit takes circuit probes and establishes the circuit with a CircuitEstablish message.
 - TURN vs STUN: over an internet route, encode information in Circuit Probes about STUN connection info. Use this as a secondary channel path.

The general rules are:

 - Never re-transmit a route probe to a peer that appears in the probe's existing path.
 - Drop incoming probes that already contain the local peer.
 - For connection quality estimation packets, track which peers have knowledge of the local link quality, and send metric messages on circuits that have best coverage of the target peers.
 - SNI should be the hash_identifier.mydomain.com - i.e. use some suffix, maybe from the CA?

Peer tracking:

 - Discovery should build a database of observed peers. Observed events should be tracked. Maybe use a BoltDB database?
 - An event would be: UDP broadcast observed, Circuit Build relay observed, etc.
 - This can be analyzed to infer potential connectivity with a peer before actually making a route request.
 - Will also be useful for visualization.
 - Can also store Routes that we can then use later.
 
## Probe Handling

When we receive a route probe, the general logic looks like:

 - Verify the probe and attempt to insert it into the probe table
 - Check to see if the probe is already in the table, if so update the expiration time
 
The probe table queries we might ask are:

 - Does this probe already exist in the table? (use a hash of the route as a uuid)
 
At startup we need to cycle through the table registering expiration timers.
 
## Failure Recovery

We must aim to minimize the number of packets sent over the network for routing. This is done by optimizing how network changes are handled:
 
 - Route probes have a expiration time
 - Route probes are kept in memory, and re-transmitted over new peer connections when they become available.
 - 
 
 
## Packet Addressing

Generally applications can be reachable through the network in the following ways:

 - In **VPN** mode, bind to the ipv6 address on the host with a given port.
 - In any mode, connect directly to the qvpn server and bind to a port. 
 - In **VPN** mode, this will also check if the port is already bound, and bind to it to prevent other applications from binding to the port.
 
This way we can advertise services to connect to even when we are not necessarily running in VPN mode.

## PeerDB Cache

The peer database should act like a write-through cache. When a peer lookup occurs, the system should:

 - Search the in-memory cache for the peer.
 - Search the BoltDB database for the peer. If found, load into cache.
 - Add the peer to the cache / db.

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
+--------|-|------------|-----------|----------------------------+
| 7 bits |1|  40 bits   |  16 bits  |          64 bits           |
+--------|-|------------|-----------|----------------------------+
| Prefix |L| Global ID  | Subnet ID |        Interface ID        |
+--------|-|------------|-----------|----------------------------+
| 0xfd  (2byte) | caCertH[:4]|           publicKeyH[:10]         |
+--------|-|------------|-----------|----------------------------+
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
hash of the public key of the node. Notice that both the interface ID and the
text-based base32 identifier are the same length (10 bytes).

When routing, we can identify a peer by a 10-32 mask of the first N bytes of the
public key hash.

This structure allows a few things:

 - **URL Routing in SOCKS**: http://faqmce7yybsswacf.fuse:8080/test-website
 - **IPv6 Routing**: optimized for Linux routing tables, use the cluster
   prefix as your routing mask. Supports multiple clusters running on
   the same machine with bridging between clusters using the IPv6
   routing table. Will need detecting the routing table to share this
   route, though.

## Gossip Replacement for Serf

QuicChannel (should be renamed) already is capable of the same features as Serf - in particular:

 - **Peer state tracking**: using observed route build packets, can
   maintain a "last seen" time for all observed peers.
 - **Network coordinates**: using observed route build packets, it's
   possible to infer/estimate the current topology of the network and
   build network coordinates in the same way as Serf.
 - **Gossip**: Serf's gossip features can easily be added to QC with a
   control packets over the control stream.

## Relay Identity Optimization

Originally, the `identity.Identity` for each hop was included in the `route.Hop`.

This makes the packet size for a route probe explode as the hops travel outwards.

Instead, a better approach is to include just the partial hash (10 bytes). If the next hop in the route does not have the peer in its PeerDb, then it will add to the PeerDb a temporary (maybe with some kind of ephemeral peer sweep in place in the future) peer entry and ping a `PeerQuery` control packet backwards to the transmitting peer over the same session.
