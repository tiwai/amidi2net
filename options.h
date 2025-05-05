/*
 * amidi2net configuration options
 */
#ifndef __OPTIONS_H_INC
#define __OPTIONS_H_INC

struct am2n_config {
	bool support_fec;			/* enable FEC */
	bool ipv6;				/* enable IPv6 */
	bool passthrough;			/* don't handle UMP stream messages */

	unsigned int liveness_timeout;		/* first ping timeout (in msec) */
	unsigned int missing_pkt_timeout;	/* timeout for missing packet resubmit (in msec) */
	unsigned int retransmit_timeout;	/* retransmit retry timeout (in msec) */
	unsigned int ping_timeout;		/* ping retry timeout (in msec) */
	unsigned int zerolength_ump_timeout;	/* zero-length UMP timeout (in msec) */
	unsigned int invitation_timeout;	/* timeout for invitation request (in msec) */

	unsigned int max_missing_retry;		/* max retries for missing packet recovery */
	unsigned int max_ping_retry;		/* max retries for ping connection checks */
	unsigned int max_invitation_retry;	/* max retries of invitations */

	unsigned int max_sessions;		/* max number of sessions */

	unsigned int fail_test;			/* simulate packet failure at random 1/N */
	unsigned int fail_test_mode;		/* packet failure test mode */

	unsigned int io_type;			/* I/O backend type */
	const char *seq_devname;		/* sequencer client:port string */
	const char *rawmidi_device;		/* device name string */
	unsigned int midi_version;		/* MIDI version (1 or 2) */
	const char *ep_name;			/* UMP endpoint name */
	const char *prod_id;			/* UMP product id */
	unsigned int num_groups;		/* optional: # of UMP groups */
	unsigned int num_blocks;		/* optional: # of FBs */
};

/* types used with getopt_log() */
enum {
	OPT_SEQ_BRIDGE_MODE = 'S',
	OPT_RAWMIDI_MODE = 'R',
	OPT_SEQ_HUB_MODE = 'H',
	OPT_EP_NAME = 'N',
	OPT_PROD_ID = 'P',
	OPT_GROUPS = 'G',
	OPT_BLOCKS = 'B',
	OPT_SUPPORT_FEC	= 'f',
	OPT_IPV6 = '6',
	OPT_MAX_SESSIONS = 's',
	OPT_DEBUG = 'd',
	OPT_LIVENESS_TIMEOUT = 0x1001,
	OPT_MISSING_PKT_TIMEOUT,
	OPT_RETRANSMIT_TIMEOUT,
	OPT_PING_TIMEOUT,
	OPT_ZEROLENGTH_UMP_TIMEOUT,
	OPT_INVITATION_TIMEOUT,
	OPT_MAX_MISSING_RETRY,
	OPT_MAX_PING_RETRY,
	OPT_MAX_INVITATION_RETRY,
	OPT_FAIL_TEST,
	OPT_FAIL_TEST_MODE,
	OPT_PASSTHROUGH,
};

#define SERVER_CONFIG_GETOPT	"S:R:H:E:P:G:B:f6s:d"

#define SERVER_CONFIG_GETOPT_LONG					\
	{"seq", 1, 0, OPT_SEQ_BRIDGE_MODE},				\
	{"rawmidi", 1, 0, OPT_RAWMIDI_MODE},				\
	{"hub", 1, 0, OPT_SEQ_HUB_MODE},				\
	{"ep-name", 1, 0, OPT_EP_NAME},					\
	{"prod-id", 1, 0, OPT_PROD_ID},					\
	{"groups", 1, 0, OPT_GROUPS},					\
	{"blocks", 1, 0, OPT_BLOCKS},					\
	{"fec", 0, 0, OPT_SUPPORT_FEC},					\
	{"ipv6", 0, 0, OPT_IPV6},					\
	{"liveness-timeout", 1, 0, OPT_LIVENESS_TIMEOUT},		\
	{"ping-timeout", 1, 0, OPT_PING_TIMEOUT},			\
	{"max-ping-retry", 1, 0, OPT_MAX_PING_RETRY},			\
	{"missing-pkt-timeout", 1, 0, OPT_MISSING_PKT_TIMEOUT},		\
	{"retransmit-timeout", 1, 0, OPT_RETRANSMIT_TIMEOUT},		\
	{"max-missing-retry", 1, 0, OPT_MAX_MISSING_RETRY},		\
	{"zerolength-ump-timeout", 1, 0, OPT_ZEROLENGTH_UMP_TIMEOUT},	\
	{"sessions", 1, 0, OPT_MAX_SESSIONS},				\
	{"fail-test", 1, 0, OPT_FAIL_TEST},				\
	{"fail-test-mode", 1, 0, OPT_FAIL_TEST_MODE},			\
	{"passthrough", 0, 0, OPT_PASSTHROUGH},				\
	{"debug", 0, 0, OPT_DEBUG}

#define CLIENT_CONFIG_GETOPT	"S:R:H:E:P:G:B:f6s:d"

#define CLIENT_CONFIG_GETOPT_LONG					\
	{"fec", 0, 0, OPT_SUPPORT_FEC},					\
	{"missing-pkt-timeout", 1, 0, OPT_MISSING_PKT_TIMEOUT},		\
	{"retransmit-timeout", 1, 0, OPT_RETRANSMIT_TIMEOUT},		\
	{"max-missing-retry", 1, 0, OPT_MAX_MISSING_RETRY},		\
	{"zerolength-ump-timeout", 1, 0, OPT_ZEROLENGTH_UMP_TIMEOUT},	\
	{"invitation-timeout", 1, 0, OPT_INVITATION_TIMEOUT},		\
	{"max-invitation-retry", 1, 0, OPT_MAX_INVITATION_RETRY},	\
	{"fail-test", 1, 0, OPT_FAIL_TEST},				\
	{"fail-test-mode", 1, 0, OPT_FAIL_TEST_MODE},			\
	{"passthrough", 0, 0, OPT_PASSTHROUGH},				\
	{"debug", 0, 0, OPT_DEBUG}

#define SERVER_CONFIG_USAGE	    \
	"  -S,--seq=<SEQ:PORT>: run in sequencer bridge mode\n" \
	"  -R,--rawmidi=<DEVICE>: run in rawmidi bridge mode\n" \
	"  -H,--hub=<MIDIVERSION>: run in sequencer hub mode\n" \
	"  -N,--ep-name=<NAME>: UMP Endpoint name (for hub mode)\n" \
	"  -P,--prod-id=<NAME>: UMP Product Id (for hub mode)\n" \
	"  -G,--groups=<NUM>: number of UMP Groups (for hub mode)\n" \
	"  -B,--blocks=<NUM>: number of UMP Function Blocks (for hub mode)\n" \
	"  -f,--fec: disable FEC\n"			\
	"  -6,--ipv6: enable IPv6\n"			\
	"  -s,--sessions=<N>: max number of sessions\n" \
	"  --liveness-timeout=<MSEC>: first ping timeout (in msec)\n" \
	"  --ping-timeout=<MSEC>: ping retry timeout (in msec)\n" \
	"  --max-ping-retry=<NUM>: max retries for ping connection checks\n" \
	"  --missing-pkt-timeout=<MSEC>: timeout for missing packet resubmit (in msec)\n" \
	"  --retransmit-timeout=<MSEC>: retransmit retry timeout (in msec)\n" \
	"  --max-missing-retry=<NUM>: max retries for missing packet recovery\n" \
	"  --zerolength-ump-timeout=<MSEC>: zero-length UMP timeout (in msec)\n" \
	"  --fail-test=<N>: simulate packet failure at random 1/N\n" \
	"  --fail-test-mode=<MODE>: packet failure test mode (0-4)\n" \
	"  --passthrough: don't handle UMP stream messages\n" \
	"  -d,--debug: enable debug\n"

#define CLIENT_CONFIG_USAGE \
	"  -S,--seq=<SEQ:PORT>: run in sequencer bridge mode\n" \
	"  -R,--rawmidi=<DEVICE>: run in rawmidi bridge mode\n" \
	"  -H,--hub=<MIDIVERSION>: run in sequencer hub mode\n" \
	"  -N,--ep-name=<NAME>: UMP Endpoint name (for hub mode)\n" \
	"  -P,--prod-id=<NAME>: UMP Product Id (for hub mode)\n" \
	"  -G,--groups=<NUM>: number of UMP Groups (for hub mode)\n" \
	"  -B,--blocks=<NUM>: number of UMP Function Blocks (for hub mode)\n" \
	"  -f,--fec: disable FEC\n"			\
	"  -6,--ipv6: enable IPv6\n"			\
	"  --missing-pkt-timeout=<MSEC>: timeout for missing packet resubmit (in msec)\n" \
	"  --retransmit-timeout=<MSEC>: retransmit retry timeout (in msec)\n" \
	"  --max-missing-retry=<NUM>: max retries for missing packet recovery\n" \
	"  --zerolength-ump-timeout=<MSEC>: zero-length UMP timeout (in msec)\n" \
	"  --invitation-timeout=<MSEC>: timeout for invitation request (in msec)\n" \
	"  --max-invitation-retry=<NUM:> max retries of invitations\n" \
	"  --fail-test=<N>: simulate packet failure at random 1/N\n" \
	"  --fail-test-mode=<MODE>: packet failure test mode (0-4)\n" \
	"  --passthrough: don't handle UMP stream messages\n" \
	"  -d,--debug: enable debug\n"

/* Configuration setup */
void am2n_config_init(struct am2n_config *config);
int am2n_config_parse_option(struct am2n_config *config,
			     bool server, int c, const char *arg);
void am2n_config_debug_print(const struct am2n_config *config, bool server);

#endif /* __OPTIONS_H_INC */
