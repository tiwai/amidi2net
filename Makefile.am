AM_CFLAGS = @ALSA_CFLAGS@ -Wall -Wno-pointer-sign
bin_PROGRAMS = amidi2net-server amidi2net-client

if SUPPORT_MDNS
bin_PROGRAMS += amidi2net-list
endif

man_MANS = amidi2net.1 amidi2net-server.1 amidi2net-client.1 amidi2net-list.1

COMMON_SOURCES = \
	common.c \
	options.c \
	packet.c \
	io-seq-common.c \
	io-seq-bridge.c \
	io-seq-hub.c \
	io-seq-stream-msg.c \
	io-rawmidi.c

if SUPPORT_AUTH
AM_CFLAGS += @OPENSSL_CFLAGS@
COMMON_SOURCES += auth.c
endif

noinst_HEADERS = amidi2net.h options.h packet.h io-seq-common.h

amidi2net_server_SOURCES = \
	amidi2net-server.c \
	$(COMMON_SOURCES)
amidi2net_server_LDADD = @ALSA_LIBS@
if SUPPORT_AUTH
amidi2net_server_LDADD += @OPENSSL_LIBS@
endif
if SUPPORT_MDNS
amidi2net_server_SOURCES += mdns-publish.c
AM_CFLAGS += @AVAHI_CFLAGS@
amidi2net_server_LDADD += @AVAHI_LIBS@
endif

amidi2net_client_SOURCES = \
	amidi2net-client.c \
	$(COMMON_SOURCES)
amidi2net_client_LDADD = @ALSA_LIBS@
if SUPPORT_AUTH
amidi2net_client_LDADD += @OPENSSL_LIBS@
endif
if SUPPORT_MDNS
amidi2net_client_SOURCES += lookup.c
AM_CFLAGS += @AVAHI_CFLAGS@
amidi2net_client_LDADD += @AVAHI_LIBS@
endif

if SUPPORT_MDNS
amidi2net_list_SOURCES = amidi2net-list.c lookup.c
amidi2net_list_LDADD = @AVAHI_LIBS@
endif

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = README.md LICENSE
