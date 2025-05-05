ALSA Network MIDI 2.0 UDP Server / Client Examples
==================================================

General
-------

This package contains example programs for Network MIDI 2.0 UDP server
and client with ALSA API.  The implementation is based on Network MIDI
2.0 (UDP) Transport Specification v1.0.

The server exposes a single UMP Endpoint to the network over a UDP
port.  The Endpoint is advertised via mDNS using Avahi for discovery.
The client connects to the given Network MIDI server via UDP.
Multiple clients may be connected to a single server.

Both servers and clients are backed by either ALSA sequencer API or
ALSA rawmidi UMP API to communicate with devices or applications on
the server or the client, so that they can work as a bridge.  The
actual behavior of the program depends on the selected I/O backend.

The basic invocation of the server is simple, just run like:
```
% amidi2net-server
```
As default, a free UDP port is assigned and the port number is printed
in the output.

On the other hand, the invocation of a client needs the server IP
address (or the host name) and the UDP port number of the server in
the command line arguments.  For example,
```
% amidi2net-client my-server.com 5673
```

ALSA Sequencer Hub Mode
-----------------------

As default, both amidi2net server and client program run in the ALSA
sequencer hub mode, where a server or a client creates an ALSA
sequencer client that can be connected arbitrarily from/to other ALSA
sequencer clients, and the UMP data is transferred from/to the network
over this hub client.  Unlike the other bridge modes, the UMP Endpoint
and Function Block information isn't mirrored to the network, but it
creates own Endpoint and Function Block information.

You can explicitly specify this mode via `--hub` (or `-H`) option,
too.  The option takes the MIDI version (either 1 or 2) as the
argument for choosing the running MIDI version:
```
% amidi2net-server --hub=2
```

The default MIDI version is 1, and the MIDI version cannot be changed
during the runtime.

Once after running a servier or a client, you can connect from/to this
ALSA sequencer client to any other ALSA sequencer programs or devices
as usual, for example:
```
% amidi2net-server
Created sequencer client 128

% aconnect -iol
client 128: 'amidi2net-server' [type=user,UMP-MIDI1,pid=20256]
    0 'MIDI 2.0
client 129: 'Virtual Keyboard' [type=user,pid=20265]
    0 'Virtual Keyboard'

% aconnect 128:0 129:0
```

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
EP/FB info.  If you'd like to handle it by the other connected
application under the hub, pass `--passthrough` option to skip the UMP
Stream message handling.

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
`snd_ump_open` call, e.g.:
```
% amidi2net-server --rawmidi=hw:0,0
```

In this mode, the amidi2net server or client reads/writes directly and
exclusively the UMP device via ALSA rawmidi API, and the UMP data is
copied 1:1 from/to the network, including UMP Stream messages.

Network Option
--------------

The UDP port number for the server can be specified via `--port` (or
`-p`) option.  The default port is 0, and a free UDP port is assigned
automatically, and the assigned port number is printed at the server
invocation.

The running network host address and the UDP port can be browsed over
mDNS.  See the section below.

For enabling IPv6, pass `--ipv6` (or `-6`) option.  When this option
is set to server, both IPv4 and IPv6 sockets are created.  When this
is set to client, the client attempts to connect via IPv6 instead of
IPv4.

Authentication Options
----------------------

For running the server with the authentication, pass a secret string
via --secret (or `-x`) option.  (Yeah I know it's no secret at all :)

For the user authentication, pass the user name via '--user' (or `-u`)
option together with the password via `--secret` option.

So far, you can't use two different authentication mechanisms, but
enable only one of two.

Without `--secret` option, the server runs without authentication.

The server has also `--auth-forced` option to disallow the fallback
when the given authentication doesn't match.

In the client side, pass the same options (`--secret` and `--user`)
for authentication.  No prompt is implemented yet.

Disabling FEC
-------------

Forward Error Correction (FEC) is enabled as default.
If you want to disable FEC, pass `--fec` (or `-f`) option to server or
client.

Publishing over mDNS
--------------------

The service is published and discoverable over mDNS / Avahi.  The
default service name is `amidi2net`.

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
default in 3 seconds.  You can change the time out value via
`--timeout` (or `-t`) option, specified in milli seconds.

Other Options for Server
------------------------

The max number of sessions can be specified via `--sessions` (or `-s`)
option.  The default is 8.

Testing Packet Failures
-----------------------

The server and client program can simulate UDP packet delivery
failures for testing purposes.  When `--fail-test` option is passed
with a positive number, a packet is dropped (or swapped) at random of
1/N probability, where N is the given number.  For example,
`--fail-test=50` will result in the drops of 2% of packets.

There are several test modes available, and it can be specified via
`--fail-test-mode` option, taking a value from 0 to 4.
- 0 is the default behavior, a single drop packet at sending.
- 1 is to drop packet(s) up to FEC size at sending, so that the
  receiver triggers a retransmit request.
- 2 is to swap two packets at sending.
- 3 and 4 are similarly to drop a packet and to drop FEC packets but
  applied at receiving packets.
  (There is no swap-test at receiving.)

Yet More Options
----------------

Some detailed configuration options for fine tunings (such as the
timeout for zero-length UMP message) are available; see the help usage
of each program.

Debugging
---------

Passing `--debug` will enable the debug outputs.
Passing the option twice (or more) will enable more verbose outputs.

Installation
------------

For building the programs, the usual GNU auto-tools is needed, as well
as the C compiler (only tested with gcc), ALSA library 1.2.13 or
later, openssl and avahi development packages.  For openSUSE, it can
be installed via:
```
% zypper in gcc glibc-devel alsa-devel libopenssl-devel libavahi-devel
```

Then run like:
```
% autoreconf -fi
% ./configure --prefix=/usr
% make
% sudo make install
```

License
-------
MIT License
