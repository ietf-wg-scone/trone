---
title: "Transparent Rate Optimization for Network Endpoints (TRONE) Protocol"
abbrev: "TRONE Protocol"
category: info

docname: draft-thoji-scone-trone-protocol-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Web and Internet Transport"
workgroup: SCONE
keyword:
 - locomotive
 - pastry
venue:
  group: "SCONE"
  type: "Working Group"
  mail: "scone@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/scone/"
  github: "ietf-wg-scone/trone"
  latest: "https://ietf-wg-scone.github.io/trone/draft-thoji-scone-trone-protocol.html"

author:
 -
    fullname: Martin Thomson
    organization: Mozilla
    email: mt@lowentropy.net
 -
    fullname: Christian Huitema
    org: Private Octopus Inc.
    email: huitema@huitema.net
 -
    fullname:
      :: 奥 一穂
      ascii: Kazuho Oku
    org: Fastly
    email: kazuhooku@gmail.com
 -
    fullname: Matt Joras
    org: Meta
    email: matt.joras@gmail.com
 -
    fullname: Marcus Ihlar
    org: Ericsson
    email: marcus.ihlar@ericsson.com


normative:
  QUIC: RFC9000
  INVARIANTS: RFC8999

informative:


--- abstract

On-path network elements can sometimes be configured to apply rate limits to
flows that pass them.  This document describes a method for signaling to
endpoints that rate limiting policies are in force and  what that rate limit is.


--- middle

# Introduction

Many access networks limit the maximum data rate that attached devices are able
to attain.  This is often done without any indication to the applications
running on devices.  The result can be that application performance is degraded,
as the manner in which rate limits are enforced can be incompatible with the
rate estimation or congestion control algorithms used at endpoints.

Having the network indicate what its rate limiting policy is, in a way that is
accessible to endpoints, might allow applications to use this information when
adapting their send rate.

The Transparent Rate Optimization for Network Endpoints (TRONE) protocol is
negotiated by QUIC endpoints.  This protocol provides a means for network
elements to signal the maximum available sustained throughput, or rate limits,
for flows of UDP datagrams that transit that network element to a QUIC endpoint.


# Overview

QUIC endpoints can negotiate the use of TRONE by including a transport parameter
({{tp}}) in the QUIC handshake.  Endpoints then occasionally coalesce a TRONE
packet with ordinary QUIC packets that they send.

Network elements that have rate limiting policies can detect flows that include
TRONE packets.  The network element can indicate a maximum sustained throughput
by modifying the TRONE packet as it transits the network element.

~~~ aasvg
+--------+    +---------+     +----------+
|  QUIC  |    | Network |     |   QUIC   |
| Sender |    | Element |     | Receiver |
+---+----+    +----+----+     +----+-----+
    |              |               |
    +--- TRONE --->|   TRONE+rate  |
    |    +QUIC     +---- +QUIC --->|
    |              |               |  Validate QUIC packet
    |              |               |  and record rate
    |              |               |
~~~

QUIC endpoints that receive modified TRONE packets observe the indicated
version, process the QUIC packet, and then record the indicated rate.

Indicated rate limits apply only in a single direction.  Separate indications
can be sent for the client-to-server direction and server-to-client direction.
The indicated rates do not need to be the same.

Indicated rate limits only apply to the path on which they are received.  A
connection that migrates or uses multipath {{?QUIC-MP=I-D.ietf-quic-multipath}}
cannot assume that rate limit indications from one path apply to new paths.


# Applicability

This protocol only works for flows that use the TRONE packet ({{packet}}).

The protocol requires that packets are modified as they transit a
network element, which provides endpoints strong evidence that the network
element has the power to drop packets; though see {{security}} for potential
limitations on this.

The rate limit signal that this protocol carries is independent of congestion
signals, limited to a single path and UDP packet flow, unidirectional, and
strictly advisory.

## Independent of Congestion Signals

Rate limit signals are not a substitute for congestion feedback.  Congestion
signals, such as acknowledgments, provide information on loss, delay, or ECN
markings {{?ECN=RFC3168}} that indicate the real-time condition of a network
path.  Congestion signals might indicate a throughput that is different from the
signaled rate limit.

Endpoints cannot assume that a signaled rate limit is achievable if congestion
signals indicate otherwise.  Congestion could be experienced at a different
point on the network path than the network element that indicates a rate limit.
Therefore, endpoints need to respect the send rate constraints that are set by a
congestion controller.

## Unspecified Scope

Modifying a packet does not prove that the rate limit that is indicated would be
achievable.  A signal that is sent for a specific flow is likely enforced at a
different scope.  The extent of that scope is not carried in the signal.

For instance, limits might apply at a network subscription level, such
that multiple flows receive the same signal.

Endpoints can therefore be more confident in the rate limit signal as an
indication of the maximum achievable throughput than as any indication of
expected throughput.  That throughput will only be achievable when there is no
significant data flowing in the same scope.  In the presence of other flows,
congestion limits are likely to determine actual throughput.

This makes the application of signals most usefully applied to a downlink flow
in access networks, close to an endpoint. In that case, capacity is less likely
to be split between multiple active flows.

## Per-Flow Signal

The same UDP address tuple might be used for multiple QUIC connections.  A
single signal might be lost or only reach a single application endpoint.
Network elements that signal about a flow might choose to send additional
signals, using connection IDs to indicate when new connections could be
involved.

## Undirectional Signal

The endpoint that receives a rate limit signal is not the endpoint that might
adapt its sending behavior as a result of receiving the signal.  This ensures
that the rate limit signal is attached to the flow that it is mostly likely to
apply to.

An endpoint might need to communicate the value it receives to its peer in order
to ensure that the limit is respected.  This document does not define how that
signaling occurs as this is specific to the application in use.

## Advisory Signal

A signal does not prove that a higher rate would not be successful.  Endpoints
that receive this signal therefore need to treat the information as advisory.

As an advisory signal, network elements cannot assume that endpoints will
respect the signal.  Though this might reduce the need for more active rate
limiting, how rate limit enforcement is applied is a matter for network policy.

The time and scope over which a rate limit applies is not specified.  The
effective rate limit might change without being signaled.  The signaled limit
can be assumed to apply to the flow of packets on the same UDP address tuple for
the duration of that flow.  Rate limiting policies often apply on the level of a
device or subscription, but endpoints cannot assume that this is the case.  A
separate signal can be sent for each flow.


# Conventions and Definitions

{::boilerplate bcp14-tagged-bcp}


# TRONE Packet {#packet}

A TRONE packet is a QUIC long header packet that follows the QUIC invariants;
see {{Section 5.1 of INVARIANTS}}.

{{fig-trone-packet}} shows the format of the TRONE packet using the conventions
from {{Section 4 of INVARIANTS}}.

~~~ artwork
TRONE Packet {
  Header Form (1) = 1,
  Reserved (1),
  Rate Signal (6),
  Version (32) = 0xTRONE1 or 0xTRONE2,
  Destination Connection ID Length (8),
  Destination Connection ID (0..2040),
  Source Connection ID Length (8),
  Source Connection ID (0..2040),
}
~~~
{: #fig-trone-packet title="TRONE Packet Format"}

The most significant bit (0x80) of the packet indicates that this is a QUIC long
header packet.  The next bit (0x40) is reserved and can be set according to
{{!QUIC-BIT=RFC9287}}.

The low 6 bits (0x3f) of the first byte contain the Rate Signal field. Values
for this field are described in {{rate-signal}}.

This packet includes a Destination Connection ID field that is set to the same
value as other packets in the same datagram; see {{Section 12.2 of QUIC}}.

The Source Connection ID field is set to match the Source Connection ID field of
any packet that follows.  If the next packet in the datagram does not have a
Source Connection ID field, which is the case for packets with a short header
({{Section 5.2 of INVARIANTS}}), the Source Connection ID field is empty.

TRONE packets SHOULD be included as the first packet in a datagram.  This is
necessary in many cases for QUIC versions 1 and 2 because packets with a short
header cannot precede any other packets.

## Rate Signals {#rate-signal}

The Rate Signal field in TRONE uses the low 6 bits (0x3f) of the first byte.
This field is encoded as a logarithmically spaced distribution over a range
defined by the TRONE protocol version.

The Rate Signal field is set to 0x3F (63) when sent by a QUIC endpoint,
indicating no rate limit is in place or that the TRONE protocol is not supported
by network elements on the path. Vales 0x00 through 0x3E (62) represent the ceiling
of rate being advised by the network element(s) on the path.

For TRONE protocol version 0xTRONE1, the rate limits use a logarithmic scale with:
* Base rate (b_min) = 100 Kbps
* Maximum rate ≈ 125 Mbps
* Bitrate at value n = b_min * 10^(n/20)

For TRONE protocol version 0xTRONE2, the rate limits use a logarithmic scale with:
* Base rate (b_min) = 10000 Kbps (10 Mbps)
* Maximum rate ≈ 12.5 Gbps
* Bitrate at value n = b_min * 10^(n/20)

This creates two overlapping ranges:
* Version 0xTRONE1: 100 Kbps to 125 Mbps
* Version 0xTRONE2: 10 Mbps to 12.5 Gbps

Some notable values in these ranges include:

| Rate Signal | Version 0xTRONE1 Rate | Version 0xTRONE2 Rate |
|:------------|:----------------------|:----------------------|
| 0  | 100 Kbps | 10 Mbps |
| 10 | 316 Kbps | 31.6 Mbps |
| 20 | 1 Mbps | 100 Mbps |
| 30 | 3.16 Mbps | 316 Mbps |
| 40 | 10 Mbps | 1 Gbps |
| 50 | 31.6 Mbps | 3.16 Gbps |
| 60 | 100 Mbps | 10 Gbps |
| 62 | 126 Mbps | 12.6 Gbps |
| 63 | No limit | No limit |

## Endpoint Processing of TRONE Packets

Processing a TRONE packet involves reading the value from the Rate Signal field.
However, this value MUST NOT be used unless another packet from the same
datagram is successfully processed.  Therefore, a TRONE packet always needs to
be coalesced with other QUIC packets.

A TRONE packet is defined by the use of the longer header bit (0x80 in the first
byte) and the TRONE protocol version (0xTBD in the next four bytes).  A TRONE
packet MAY be discarded, along with any packets that come after it in the same
datagram, if the Source Connection ID is not consistent with those coalesced
packets, as specified in {{packet}}.

A TRONE packet MUST be discarded if the Destination Connection ID does not match
one recognized by the receiving endpoint.


# Negotiating TRONE {#tp}

A QUIC endpoint indicates that it is willing to receive TRONE packets by
including the trone_supported transport parameter (0xTBD).

This transport parameter is valid for QUIC versions 1 {{QUIC}} and 2
{{!QUICv2=RFC9369}} and any other version that recognizes the versions,
transport parameters, and frame types registries established in {{Sections 22.2,
22.3, and 22.4 of QUIC}}.


# Deployment

QUIC endpoints can enable the use of the TRONE protocol by sending TRONE packets
{{packet}}.  Network elements then apply or replace the Rate Signal field
({{apply}}) according to their policies.


## Applying Rate Limit Signals {#apply}

A network element detects a TRONE packet by observing that a packet has a QUIC
long header and one of the TRONE protocol versions (0xTRONE1 or 0xTRONE2).

A network element then conditionally replaces the Rate Signal field with
values of its choosing.

A network element might receive a packet that already includes a rate signal.
The network element replaces the rate signal if it wishes to signal a lower
rate limit; otherwise, the original values are retained, preserving the signal
from the network element with the lower policy.

The following pseudocode indicates how a network element might detect a TRONE
packet and replace an existing rate signal.

~~~ pseudocode
is_long = packet[0] & 0x80 == 0x80
packet_version = packet[1..5]
if is_long and (packet_version == TRONE1_VERSION or packet_version == TRONE2_VERSION):
  target_rate_value = convert_rate_to_signal(target_rate, packet_version)
  packet_rate_value = packet[0] & 0x3f
  if packet_rate_value == 0x3f or target_rate_value < packet_rate_value:
    packet[0] = packet[0] & 0xc0 | target_rate_value
~~~

A network element applies the same rate policy to TRONE packets of both
versions, accounting for the different scales of each version. When a
network element signals a rate limit that falls within the range of both
versions, it should signal appropriate values in each version. When the target
rate limit is outside the range of a particular version, the network element
should signal the minimum value (0) for rates below the range and preserve the
original value for rates above the range.

# Version Interaction {#version-interaction}

The TRONE protocol defines two versions (0xTRONE1 and 0xTRONE2) that cover
different but overlapping ranges of bitrates. This design allows for:

*  Support for both very low bitrates (down to 100 Kbps) and very high bitrates
   (up to 12.5 Gbps)
*  Graceful handling of network elements that might only recognize one version
   or some subset of future versions.

## Converting Between Versions

When network elements or endpoints need to compare rate signals from different
versions, they must first convert the signals to their corresponding bitrates.
The formulas for conversion are:

* For version 0xTRONE1: bitrate = 100 Kbps * 10^(signal/20)
* For version 0xTRONE2: bitrate = 10 Mbps * 10^(signal/20)

## Handling Multiple Versions

Endpoints should observe the following guidelines when sending and processing
TRONE packets:

*  When sending TRONE packets, endpoints SHOULD alternate between versions
   0xTRONE1 and 0xTRONE2 to ensure network elements can signal rate limits across
   the entire supported range.

*  When receiving TRONE packets with different versions, endpoints SHOULD:
   * Convert all signals to their corresponding bitrates
   * Use the most restrictive (lowest) effective rate limit
   * If one version's signal indicates "no limit" (value 63) but the other
     indicates a limit, use the specified limit

*  Network elements SHOULD apply appropriate rate signals to all packets that
   include a TRONE version they support.

## Example Conversions

For a target rate limit of 30 Mbps:
* In version 0xTRONE1, this corresponds to a signal value of approximately 49
* In version 0xTRONE2, this corresponds to a signal value of approximately 9

For a target rate limit of 5 Gbps:
* In version 0xTRONE1, this exceeds the range, so the signal would remain at 63
  (no limit)
* In version 0xTRONE2, this corresponds to a signal value of
  approximately 57

## Providing Opportunities to Apply Rate Limit Signals {#extra-packets}

Endpoints that wish to offer network elements the option to add rate limit
signals can send TRONE packets at any time.  This is a decision that a sender
makes when constructing datagrams. It is recommended that endpoints promptly
send an initial TRONE packet once the peer confirms its willingness to receive
them.

To support the full range of possible rate limits, endpoints SHOULD alternate
between sending TRONE packets with version 0xTRONE1 and version 0xTRONE2. This
allows network elements to signal rate limits across the entire supported range
with appropriate granularity.

When a receiver receives TRONE packets with different versions and different
rate signals, it SHOULD use the most restrictive (lowest) effective rate limit
after converting the signal values to their corresponding bitrates.

Endpoints MUST send any TRONE packet they send as the first packet in a
datagram, coalesced with additional packets. An endpoint that receives and
discards a TRONE packet without also successfully processing another packet
from the same datagram SHOULD ignore any rate limit signal. Such a datagram
might be entirely spoofed.

A network element that wishes to signal an updated rate limit waits for the
next TRONE packet in the desired direction. However, if no TRONE packet
arrives within a reasonable time, the network element MAY construct its own
TRONE packet and prepend it to a QUIC packet before forwarding. This process
requires expanding the UDP datagram containing the original QUIC packet, which
might cause the datagram to exceed the path MTU. Therefore, a network element
SHOULD NOT expand UDP datagrams if the combined payload of the TRONE packet and
the subsequent packets exceeds 1200 bytes, the smallest maximum datagram size
supported by QUIC versions 1 and 2 (see {{Section 14 of QUIC}}).

## Feedback To Sender About Signals {#feedback}

Information about rate limits is intended for the sending application.  Any
signal from network elements can be propagated to the receiving application
using an implementation-defined mechanism.

This document does not define a means for indicating what was received.
That is, the expectation is that any signal is propagated to the application
for handling, not handled automatically by the transport layer.
How a receiving application communicates the rate limit signal to a
sending application will depend on the application in use.

Different applications can choose different approaches. For example,
in an application where a receiver drives rate adaptation, it might
not be necessary to define additional signaling.

A sender can use any acknowledgment mechanism provided by the QUIC version in
use to learn whether datagrams containing TRONE packets were likely received.
This might help inform whether to send additional TRONE packets in the event
that a datagram is lost. However, rather than relying on transport signals, an
application might be better able to indicate what has been received and
processed.

TRONE packets could be stripped from datagrams in the network, which cannot be
reliably detected.  This could result in a sender falsely believing that no
network element applied a rate limit signal.


# Security Considerations {#security}

The modification of packets provides endpoints proof that a network element is
in a position to drop datagrams and thereby enforce the indicated rate limit.
{{extra-packets}} states that endpoints only accept signals if the datagram
contains a packet that it accepts to prevent an off-path attacker from inserting
spurious rate limit signals.

Some off-path attackers may be able to both
observe traffic and inject packets. Attackers with such capabilities could
observe packets sent by an endpoint, create datagrams coalescing an
arbitrary TRONE packet and the observed packet, and send these datagrams
such that they arrive at the peer endpoint before the original
packet. Spoofed packets that seek to advertise a higher limit
than might otherwise be permitted also need to bypass any
rate limiters. The attacker will thus get arbitrary TRONE packets accepted by
the peer, with the result being that the endpoint receives a false
or misleading rate limit.

The recipient of a rate limit signal therefore cannot guarantee that
the signal was generated by an on-path network element. However,
the capabilities required of an off-path attacker are substantially
similar to those of on path elements.

The actual value of the rate limit signal is not authenticated.  Any signal
might be incorrectly set in order to encourage endpoints to behave in ways that
are not in their interests.  Endpoints are free to ignore limits that they think
are incorrect.  The congestion controller employed by a sender provides
real-time information about the rate at which the network path is delivering
data.

Similarly, if there is a strong need to ensure that a rate limit is respected,
network elements cannot assume that the signaled limit will be respected by
endpoints.

# Privacy Considerations {#privacy}

The focus of this analysis is the extent to which observing TRONE
packets could be used to gain information about endpoints.
This might be leaking details of how applications using QUIC
operate or leaks of endpoint identity when using additional
privacy protection, such as a VPN.

Any network element that can observe the content of that packet can read the
rate limit that was applied.  Any signal is visible on the path, from the point
at which it is applied to the point at which it is consumed at an endpoint.
On path elements can also alter the TRONE signal to try trigger specific
reactions and gain further knowledge.

In the general case of a client connected to a server through the
Internet, we believe that TRONE does not provide much advantage to attackers.
The identities of the clients and servers are already visible through their
IP addresses. Traffic analysis tools already provide more information than
the data rate limits set by TRONE.

There are two avenues of attack that require more analysis:

* that the passive observation of TRONE packets might help identify or
  distinguish endpoints; and
* that active manipulation of TRONE signals might help reveal the
  identity of endpoints that are otherwise hidden behind VPNs or proxies.

## Passive Attacks

If only few clients and server pairs negotiate the usage of TRONE, the
occasional observation of TRONE packets will "stick out". That observation,
could be combined with observation of timing and volume of traffic to
help identify the endpoint or categorize the application that they
are using.

A variation of this issue occurs if TRONE is widely implemented, but
only used in some specific circumstances. In that case, observation of
TRONE packets reveals information about the state of the endpoint.

If multiple servers are accessed through the same front facing server,
Encrypted Client Hello (ECH) may be used to prevent outside parties to
identify which specific server a client is using. However, if only
a few of these servers use TRONE, any TRONE packets
will help identify which specific server a client is using.

This issue will be mitigated if TRONE becomes widely implemented, and
if the usage of TRONE is not limited to the type of applications
that make active use of the signal.

QUIC implementations are therefore encouraged to make the feature available
unconditionally.  Endpoints might send TRONE packets whenever a peer can accept
them.

## Active Attacks

Suppose a configuration in which multiple clients use a VPN or proxy
service to access the same server. The attacker sees the IP addresses
in the packets behind VPN and proxy and also between the users and the VPN,
but it does not know which VPN address corresponds to what user address.

Suppose now that the attacker selects a flow on the link between the
VPN/proxy and server. The attacker applies rate limit signals to TRONE packets
in that flow. The attacker chooses a bandwidth that is
lower than the "natural" bandwidth of the connection. A reduction
in the rate of flows between client and VPN/proxy might allow
the attacker to link the altered flow to the client.

~~~ aasvg
+--------+
| Client |------.
+--------+       \      +-------+
                  '---->|       |            +--------+
+--------+              |  VPN  |<==========>|        |
| Client |------------->|   /   |<==========>| Server |
+--------+              | Proxy |<==========>|        |
                  .---->|       |     ^      +--------+
+--------+       /      +-------+     |
| Client |======'                     |
+--------+      ^           Apply rate limit signal
                 \
                  \
               Observe change
~~~

An attacker that can manipulate TRONE headers can also simulate
congestion signals by dropping packets or by setting the ECN CE bit.
That will also likely result in changes in the congestion response by
the affected client.

A VPN or proxy could defend against this style of attack by removing TRONE (and
ECN) signals. There are few reasons to provide per-flow rate limit signals in
that situation.  Endpoints might also either disable this feature or ignore any
signals when they are aware of the use of a VPN or proxy.

# IANA Considerations {#iana}

This document registers a new QUIC version ({{iana-version}}) and a QUIC
transport parameter ({{iana-tp}}).


## TRONE Versions {#iana-version}

This document registers the following entries to the "QUIC Versions" registry
maintained at <https://www.iana.org/assignments/quic>, following the guidance
from {{Section 22.2 of QUIC}}.

Value:
: 0xTRONE1

Status:
: permanent

Specification:
: This document

Change Controller:
: IETF (iesg@ietf.org)

Contact:
: QUIC Working Group (quic@ietf.org)

Notes:
: TRONE Protocol - Low Range (100 Kbps - 125 Mbps)
{: spacing="compact"}

Value:
: 0xTRONE2

Status:
: permanent

Specification:
: This document

Change Controller:
: IETF (iesg@ietf.org)

Contact:
: QUIC Working Group (quic@ietf.org)

Notes:
: TRONE Protocol - High Range (10 Mbps - 12.5 Gbps)
{: spacing="compact"}


## trone_supported Transport Parameter {#iana-tp}

This document registers the trone_supported transport parameter in the "QUIC
Transport Parameters" registry maintained at
<https://www.iana.org/assignments/quic>, following the guidance from {{Section
22.3 of QUIC}}.

Value:
: 0xTBD

Parameter Name:
: trone_supported

Status:
: Permanent

Specification:
: This document

Date:
: This date

Change Controller:
: IETF (iesg@ietf.org)

Contact:
: QUIC Working Group (quic@ietf.org)

Notes:
: (none)
{: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

Jana Iyengar has made significant contributions to the original TRAIN
specification that forms the basis for a large part of this document.
