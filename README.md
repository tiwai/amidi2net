ALSA Network MIDI 2.0 UDP Server / Client Examples
==================================================

General
-------

This package contains example programs for Network MIDI 2.0 UDP server
and client with ALSA API.  The implementation is based on Network MIDI
2.0 (UDP) Transport Specification v1.0:
  https://midi.org/network-midi-2-0

The server exposes a single UMP Endpoint to the network over a UDP
port.  The Endpoint is advertised via mDNS for discovery.
The client connects to the given Network MIDI server via UDP.
Multiple clients may be connected to a single server.

Both servers and clients are backed by either ALSA sequencer API or
ALSA rawmidi UMP API to communicate with devices or applications on
the server or the client, so that they can work as a bridge.  The
actual behavior of the program depends on the selected I/O backend.

The basic invocation of a server is simple, just run like:
```
% amidi2net-server
```
As default, a free UDP port is assigned and the port number is printed
out.

On the other hand, the invocation of a client needs the server IP
address (or the host name) and the UDP port number of the server to
connect specified via the command line arguments.  For example,
```
% amidi2net-client my-server.com 5673
```

Alternatively, you can invoke a client with `--lookup` (or `-l`)
option together with the mDNS service name of the target Network MIDI
host instead of passing the address and the port manually, too.
For example,
```
% amidi2net-client -l amidi2net
```

ALSA Sequencer Hub Mode
-----------------------

As default, both amidi2net server and client programs run in the ALSA
sequencer hub mode, where a server or a client creates an ALSA
sequencer client that can be connected arbitrarily from/to other ALSA
sequencer clients, and the UMP data is transferred from/to the network
over this hub client.  Unlike the other bridge modes, the UMP Endpoint
and Function Block information aren't mirrored to the network, but it
creates own Endpoint and Function Block information.

You can explicitly specify this mode via `--hub` (or `-H`) option,
too.  The option takes the MIDI version (either 1 or 2) as the
argument for choosing the running MIDI protocol version:
```
% amidi2net-server --hub=2
```

The default MIDI version is 1, and the MIDI version cannot be changed
during the runtime.

Once after running a servier or a client, you can connect from/to this
ALSA sequencer client to any other ALSA sequencer programs or devices
as usual, e.g. via `aconnect` program.

For composing a UMP Endpoint Info, this mode needs a UMP Endpoint name
and a UMP product ID.  The program fills the default strings, but you
can specify your own favorite via `--ep-name` (or `-N`) and
`--prod-id` (or `-P`) options, respectively.

The number of UMP Groups and Function Blocks of the hub can be
specified via `--groups` (or `-G`) and `--blocks` (or `-B`) options,
respectively.  As default, a single FB containing all 16 Groups is
created.  As of this writing, the only valid configuration is a single
FB containing all Groups or multiple FBs containing each single
Group.

In the hub mode, the program tries to respond to the UMP Stream
messages for Endpoint and Function Block inquiries, based on the own
Endpoint / Function Block information.  If you would like to handle it
by the other connected application under the hub, pass `--passthrough`
option to skip the UMP Stream message handling.

ALSA Sequencer Bridge Mode
--------------------------

For running an amidi2net server or a client in ALSA sequencer bridge
mode, pass `--seq` (or `-S`) option with the ALSA sequencer client and
port as the argument, e.g:
```
% amidi2net-server --seq=128:0
```

In this mode, the amidi2net server or client program connects to the
given ALSA sequencer client and it mirrors both inputs and outputs
between the network and the specified ALSA sequencer client.  The UMP
data is copied 1:1 transparently between them.  When the connected
ALSA sequencer client exits, the amidi2net server/client program
exits, too.

The UMP Stream messages are passed through to the bridged ALSA
sequencer client unless it's connected to a legacy ALSA sequencer
client (i.e. non-UMP client).  For the legacy client, the program
tries to respond to UMP Stream messages like in the hub mode.

RawMIDI Bridge Mode
-------------------

For running an amidi2net server or client in rawmidi mode, pass
`--rawmidi` (or `-R`) option with the string to be passed to
`snd_ump_open()` API function, e.g.:
```
% amidi2net-server --rawmidi=hw:0,0
```

In this mode, the amidi2net server or client reads/writes the UMP
device directly and exclusively via ALSA rawmidi API, and the UMP data
is copied 1:1 from/to the network, including UMP Stream messages.

Network Option
--------------

The UDP port number for the server can be specified via `--port` (or
`-p`) option.  The default port is 0, which means that a free UDP port
is assigned automatically.  The assigned port number is printed at the
server invocation.

The running network host address and the UDP port can be browsed over
mDNS.  See the section below.

For enabling IPv6, pass `--ipv6` (or `-6`) option.  When this option
is set to server, both IPv4 and IPv6 sockets are created.  When this
is set to client, the client attempts to connect via IPv6 instead of
IPv4.

Authentication Options
----------------------

When you pass `--auth` option to the server, the server runs with the
standard authentication enabled.  It will ask the secret string for
the authentication on a prompt, or you can pass it with `--secret`
(or  `-x`) option.

When you pass `--user-auth` option to the server, the server will run
with the user-authentication enabled, and it will ask a user name as
well as a password for the user-authentication, instead.  You can pass
`--user` (or `-u`) for the user name and `--secret` (or `-x`) for the
password, too.

So far, you can't use two different authentication mechanisms on the
server, but enable only one of two.  Without those options above, the
server runs without authentication.

The server has also `--auth-forced` option for prohibiting the
fallback when the given authentication from a client doesn't match.
As default, the server still falls back to no authentication and
accepts the connection when the client doesn't support
authentications.

When a client receives the command "invitation reply with
authentication required" from the server, it will ask you the secret
string on a prompt.  You can pass it with `--secret` (or `-x`) option
to the client beforehand, too.

Similarly, when a client receives the command "invitation reply with
user-authentication required" from the server, it'll ask you the user
name and the password on a prompt.  You can pass them with `--user`
(or `-u`) and `--secret` (or `-x`) options to the client beforehand,
too.

Forward Error Correction (FEC)
------------------------------

Forward Error Correction (FEC) is enabled as default on both server
and client, and its default count is 3.  The FEC count number can be
changed via `--fec` (or `-f`) option.  FEC can be disabled by passing
0 to the option.

Publishing over mDNS
--------------------

The service is published and discoverable over mDNS.  The default
service name is `amidi2net`.

You can pass `--service-name` (or `-n`) option to server for
specifying a different service name string to be exposed.

For obtaining the list of the running MIDI 2.0 network services, use
`amidi2net-list` program.  Simply running this program will show the
currently running Network MIDI 2.0 services on the net:
```
% amidi2net-list
amidi2net
  Protocol: ipv6
  Host: fd00::2178:1234:5678:abcd
  Port: 5673
  Endpoint: amidi2net-server
  Product-Id: 0.1
amidi2net
  Protocol: ipv4
  Host: 192.168.178.31
  Port: 5673
  Endpoint: amidi2net-server
  Product-Id: 0.1
....
```

The services on the local host are excluded as default.  For browsing
also the services on the local host, pass `--all` (or `-a`) option.

The `amidi2net-list` program quits after a certain time out, as
default in 1.5 seconds.  You can change the time out value via
`--timeout` (or `-t`) option, specified in milli seconds.

Session Limits
--------------

The max number of sessions that can be connected at the same time to a
single host can be specified via `--sessions` (or `-s`) option.
The default value is 8.

Session Heartbeat
-----------------

For verifying whether the connected server or client is still alive,
the server or client sends a Ping command periodically to the
connected client or server.  This period is specified via
`--liveness-timeout` option, and its default is 5000 msec for servers
and 5500 msec for clients.  Clients have a slightly longer timeout as
default for avoiding doubly pings from the both sides.

When the connected host or client doesn't reply to a Ping, the sender
retries the Ping again after a certain timeout.  This timeout is
specified via `--ping-timeout` option, and its default is 100 msec.

When the connected host or client still doesn't reply and the failures
reach to the upper limit, the sender terminates the session.  This
threshold is defined via `--max-ping-retry` option, and its default is
3.

Packet Retransmit Request
-------------------------

When server or client detects one or more packets missing by checking
the seqno series, it may send a Retransmit Request command.  This
happens either when the seqno jumps too high or when the missing
packet isn't delivered after a certain period.  The former threshold
is specified via `--tolerance` option and its default is 8.
The latter timeout is specified via `--missing-pkt-timeout` option,
and its default value is 30 msec.

After a Retransmit Request command is sent, the sender waits for the
Retransmit Request Reply command.  If the reply doesn't arrive for a
certain time period, another Retransmit Request command is sent.  This
timeout is specified via `--retransmit-timeout` option, and its
default value is 100 msec.
The Retransmit Request command may repeat until the upper limit,
specified via `--max-missing-retry`, and its default is 5.

When server or client still doesn't get the missing packet even after
multiple retries, it gives up and tries to reset the session by
sending a Session Reset command.

Zero-Length UMP
---------------

Both server or client will send a zero-length UMP message when it
doesn't receive any UMP input from the I/O backend for a certain
period (hence it decides as idle).  This period is specified via
`--zerolength-ump-timeout` option, and its default value is 100 msec.
The zero-length UMP messages are repeated at least for the number of
FEC data.

Invitation Retry
----------------

After sending the Invitation Request command to the host, a client
waits for a certain period, and if there is no reply, it retries to
send another Invitation Request command.  This period is defined via
`--invitation-timeout` option, and its default is 1000 msec (1 sec).
When the client receives an Invitation Reply Pending message, it
extends the timeout, as default 10000 msec (10 sec).  This extended
timeout can be specified via `--invitation-pending-timeout` option.
When the invitation failures reach to the upper limit, client gives up
and quits.  This threshold is defined via `--max-invitation-retry`
option and its default value is 3.

Input and Output Buffer Sizes
-----------------------------

The sizes of the input pending buffer and the output cache buffer can
be specified via `--input-buffer-size` and `--output-buffer-size`
options, respectively.  The default size of the input pending buffer
is 128, while the default size of the output cache buffer is 64.

Testing Packet Failures
-----------------------

The server and client program can simulate UDP packet delivery
failures for testing purposes.  When `--fail-test` option is passed
with a positive number, a packet is dropped (or swapped) at random of
1/N probability, where N is the given number.  For example,
`--fail-test=50` will result in the drops of 2% of packets.

There are several test modes available, and it can be specified via
`--fail-test-mode` option, taking a value from 0 to 4.
- 0 is the default behavior, a single packet drop at sending.
- 1 is to drop packet(s) up to FEC size at sending, so that the
  receiver triggers a Retransmit Request.
- 2 is to swap two packets at sending.
- 3 and 4 are similarly to drop a packet and to drop FEC packets but
  applied at receiving packets.
  (There is no swap-test at receiving.)

Debugging
---------

Passing `--debug` will enable the debug outputs.
Passing the option twice (or more) will enable more verbose outputs.

On the other hand, passing `--quiet` suppresses the output messages
except for error messages.

Installation
------------

For building the programs, the usual GNU auto-tools is needed, as well
as the C compiler (only tested with gcc), ALSA library 1.2.13 or
later, openssl and avahi development packages.  For openSUSE, it can
be installed via:
```
% zypper in automake gcc glibc-devel alsa-devel libopenssl-devel libavahi-devel
```

Then run like:
```
% autoreconf -fi
% ./configure --prefix=/usr
% make
% sudo make install
```

Usage Examples
--------------

Start a network server (host) on a machine A with IPv6 enabled:
```
% amidi2net-server -6
Created sequencer client 128
assigned UDP port = 45569
```
It opened an ALSA sequencer client 128, and the assigned UDP port is
45569 on both IPv4 and IPv6.
The ALSA sequencer client can be confirmed in
`/proc/asound/seq/clients` output:

```
% cat /proc/asound/seq/clients
....
Client 128 : "amidi2net-server" [User UMP MIDI1]
  UMP Endpoint: "amidi2net-server"
  UMP Block 0: "Bridge I/O" [Active]
    Groups: 1-16
  Port   0 : "MIDI 2.0" (RWeX) [In/Out]
  Port   1 : "Group 1 (Bridge I/O)" (RWeX) [In/Out]
  Port   2 : "Group 2 (Bridge I/O)" (RWeX) [In/Out]
  ....
```

Now start a synthesizer program (e.g. fluidsynth) on this machine A:
```
% fluidsynth -siq &
% cat /proc/asound/seq/clients
....
Client 129 : "FLUID Synth (31136)" [User Legacy]
  Port   0 : "Synth input port (31136:0)" (-We-) [Out]
```

Connect the input of the UMP Group 1 of the network host to the
synthesizer program:
```
% aconnect amidi2net-server:1 "FLUID Synth:0"
```
Now the machine A exposes a UMP Network Endpoint for a synthesizer.

On another machine B, check the available network MIDI hosts via
`amidi2net-list`.  It will show both IPv4 and IPv6 ports like:
```
% amidi2net-list
amidi2net
  Protocol: ipv4
  Host: 192.168.178.31
  Port: 53794
  Endpoint: amidi2net-server
  Product-Id: 0.1
amidi2net
  Protocol: ipv6
  Host: 2001:a62:1a05:1:1234:5678:abcd:0123
  Port: 53794
  Endpoint: amidi2net-server
  Product-Id: 0.1
```

Run a network MIDI client on the machine B, and connect to the machine
A with its service name `amidi2net`:
```
% amidi2net-client -l amidi2net
host 192.168.178.31 port 53794 found for service amidi2net
Created sequencer client 130
```

If you want to connect over IPv6, try to pass `-6` option
additionally:
```
% amidi2net-client -6 -l amidi2net
host 2001:a62:1a05:1:1234:5678:abcd:0123 port 53794 found for service amidi2net
Created sequencer client 130
```

You can check the ALSA sequencer client 130 on the machine B:
```
% cat /proc/asound/seq/clients
....
Client 130 : "amidi2net-client" [User UMP MIDI1]
  UMP Endpoint: "amidi2net-client"
  UMP Block 0: "Bridge I/O" [Active]
    Groups: 1-16
  Port   0 : "MIDI 2.0" (RWeX) [In/Out]
  Port   1 : "Group 1 (Bridge I/O)" (RWeX) [In/Out]
  Port   2 : "Group 2 (Bridge I/O)" (RWeX) [In/Out]
  ....
````

On the machine B, try to play back a MIDI2 clip file, and feed it to
the UMP Group 1 of the network client above:
```
% aplaymidi2 -p amidi2net-client:1 something.midi2
```
This will deliver the UMP data to the synthesier on the machine A that
reads from the Group 1 port, and you'll hear the outputs there.
That is, it flows like:
```
aplaymidi2 -> amidi2net-client ==Network==> amidi2-server -> fluidsynth
seq xxx:0     seq 130:1                     seq 128:1        seq 129:1
      (Machine B)                                   (Machine A)
```

License
-------
MIT License
