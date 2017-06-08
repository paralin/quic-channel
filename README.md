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

 - **Server**: implementation of a server listener.
 - **Session**: management of a remote peer session.
 - **Stream**: an encapsulated TCP/UDP connection over the wire.
 - **Controller**: a code component attached to a session for handling control messages.
 - **Router**: an implementation of routing logic to the peer.

Control packets are encoded with Protobuf, and routed to local components depending on component ID (will be rolling during development) and message ID.

Ultimately we want to be able to request a session with a specific peer and have it be established automatically, either by accepting a remote connection or dialing the remote. In this case we will accept whichever session is completely established first.

## Routing

The primary goals of this project vs babeld:

 - Route in user-space. Particularly important for cross-platform.
 - Accept only authenticated peers, and encrypt traffic in channels.
 - Build encrypted circuits between devices representing routes, then multiplex over those routes.

Most important concepts:

 - **Connection**: a one-hop link between two peers, I.E. a wifi network, a public internet link.
 - **Circuit**: a path between two peers, including 0-N peers in between, as a series of Quic streams.
 - **Channel**: a QUIC connection made through an established circuit.

The primary dilemma is that we have two choices:

 - Build full paths. Make the decision on which path to take (including forks in the road mid-way) at the terminations of the channel.
 - Do not maintain knowledge of the full path, and allow individual nodes decide how to send traffic (this is the Babel approach).

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

Route requests when arriving at the destination might look like:

```
["peer1", "peer5", "peer4", "peer8", "peer2"]
["peer1", "peer5", "peer4", "peer3", "peer2"]
```

In this case, the chain from `peer1` to `peer4` is the same. The metric messages from `peer4` should not be duplicated over multiple connections.

Channels can be in the following states:

 - PENDING - The channel path is being built, and will expire quickly if not established.
 - ESTABLISHED - The channel path is established, and being monitored. Expires in a longer period of time.
