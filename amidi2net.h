/*
 * amidinet2: Network MIDI2 server / client implementations
 */

#ifndef __AMIDI2NET_H_INC
#define __AMIDI2NET_H_INC

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <netinet/in.h>
#include "config.h"

struct ump_sock;
struct ump_output_cache;
struct ump_session;
struct am2n_ctx;
struct am2n_server_ctx;
struct am2n_mdns_ctx;
struct am2n_config;

/* just for convenience */
typedef union {
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} sock_addr_t;

/* client running state */
enum ump_client_state {
	STATE_INVITATION,
	STATE_RUNNING,
	STATE_QUIT,
};

/*
 * ring-buffer for pending UMP inputs;
 * used for correcting missing packets via FEC
 */
#define PENDING_BUFFER_SIZE	128

struct ump_pending_buffer {
	int filled;
	uint32_t buffer[PENDING_BUFFER_SIZE];
};

/*
 * ring-buffer for output UMP data;
 * used for FEC and retransmit requests
 */
#define MAX_OUTPUT_CACHE	32

struct ump_output_cache_entry {
	unsigned char len;
	unsigned char data[16];	/* storing byte-swapped data for network */
};

struct ump_output_cache {
	unsigned short index;
	unsigned short cached;
	unsigned short cache_size;
	struct ump_output_cache_entry entries[];
};

/*
 * Session object: 1:1 for client, N:1 for server
 */
struct ump_session {
	struct am2n_ctx *ctx;		/* assigned server/client */
	struct ump_sock *sock;		/* assigned socket */
	sock_addr_t addr;		/* address of recipient */
	unsigned int addr_size;		/* address size */
	unsigned short seqno_sent;	/* the last sent seqno */
	unsigned short seqno_recv;	/* the last received seqno */
	unsigned short seqno_recv_highest; /* highest received seqno */
	unsigned short fec_count;	/* available FEC count */
	bool ump_recv;			/* UMP data received */
	unsigned int missing;		/* UMP input packet missing? */
	unsigned int ping_req;		/* # of ping that have been requested */
	uint64_t missing_timeout;	/* next timeout of retransmit request */
	uint64_t ping_timeout;		/* next timeout of ping */
	enum ump_client_state state;	/* running state of client */

	struct ump_pending_buffer pending_buffer; /* input pending ring buffer */
	struct ump_output_cache *output_cache; /* output cache buffer */
#ifdef SUPPORT_AUTH
	unsigned char crypto_nonce[16];	/* generated crypto nonce for authentication */
#endif

	struct ump_session *prev, *next;	/* linked list of sessions */
};

/*
 * I/O ops
 */
enum {
	UMP_IO_BACKEND_SEQ_BRIDGE,
	UMP_IO_BACKEND_SEQ_HUB,
	UMP_IO_BACKEND_RAWMIDI,
};

struct ump_io_ops {
	/* set up poll descriptor(s) */
	int (*setup_poll)(struct am2n_ctx *ctx, struct pollfd *pfds);
	/* return matching poll events, 0 = none */
	int (*poll_revents)(struct am2n_ctx *ctx, struct pollfd *pfds);
	/* read a single UMP packet and store on the given buffer */
	int (*read_ump_packet)(struct am2n_ctx *ctx, void *buf);
	/* write UMP packet(s) from the given buffer */
	int (*write_ump_packet)(struct am2n_ctx *ctx, const void *buf, int len);
	/* free the instance */
	void (*free)(struct am2n_ctx *ctx);
};

struct ump_io_backend {
	int type;		/* UMP_IO_BACKEND_* */
	const struct ump_io_ops *ops; /* I/O ops */
	void *data;		/* private data */
	/* configuration passed from server / client programs */
	bool handle_stream_msg;	/* process UMP stream messages by itself */
	int seq_client;		/* target sequencer client number */
};

/* Network socket, polld, etc */
struct ump_sock {
	struct am2n_ctx *ctx;	/* assigned context */
	int sockfd;		/* socket file descriptor */
	int port;		/* opened UDP port */
	bool ipv6;		/* is ipv6 socket? */
	struct pollfd pfd;	/* poll fd for this socket */
};

enum am2n_role {
	ROLE_SERVER,
	ROLE_CLIENT,
};

/* test mode; passed via --fail-test-mode option */
enum fail_test_mode {
	FAIL_TEST_DROP_SENDER,		/* drop a packet at sending */
	FAIL_TEST_DROP_FEC_SENDER,	/* drop packet(s) at sending, let retransmit */
	FAIL_TEST_SWAP_SENDER,		/* swap packets at sending */
	FAIL_TEST_DROP_RECEIVER,	/* drop a packet at receiving */
	FAIL_TEST_DROP_FEC_RECEIVER,	/* drop packet(s) at receiving, let retransmit */
};

/*
 * Common context
 */
struct am2n_ctx {
	time_t base_time;	/* base seconds to be subtracted */
	uint64_t tstamp;	/* current wallclock timestamp */

	const struct am2n_config *config;	/* configuration */

	enum am2n_role role;	/* either ROLE_SERVER or ROLE_CLIENT */

	struct ump_io_backend io;	/* I/O backend */

	unsigned int zerolength_ump;	/* # of zero-length UMP msgs sent */
	uint64_t zerolength_ump_timeout; /* next timeout of zero-length UMP msg */

	char ep_name[128];	/* UMP endpoint name */
	char prod_id[128];	/* UMP product id */

#ifdef SUPPORT_AUTH
	/* Authentication: FIXME: support only a single user*/
	const unsigned char *auth_secret;
	const unsigned char *auth_username;
	unsigned int auth_support;
	bool auth_forced;
#endif

	/* open / close session callbacks */
	struct ump_session *(*open_session)(struct am2n_ctx *ctx,
					    struct ump_sock *sock,
					    const sock_addr_t *addr,
					    unsigned int addr_size);
	void (*close_session)(struct am2n_ctx *_ctx,
			      struct ump_session *session);
	/* Submission of a single UMP packet*/
	void (*submit_ump)(struct am2n_ctx *ctx, const void *data, int plen);
};

/*
 * Server
 */
struct am2n_server_ctx {
	struct am2n_ctx core;

	int sessions;		/* current number of sessions */
	int max_sessions;	/* max number of sessions */
	bool quit;		/* to be terminated? */
	struct ump_session *first_session, *last_session; /* linked list head for sessions */
	struct ump_output_cache *output_cache;	/* shared output cache */

	struct ump_sock ipv4;	/* IPV4 socket info */
	struct ump_sock ipv6;	/* IPV6 socket info */
};

/*
 * Client
 */
struct am2n_client_ctx {
	struct am2n_ctx core;
	struct ump_session *session;	/* assigned session */
	struct ump_output_cache *output_cache;	/* output cache */

	struct ump_sock sock;
};

/*
 * Conditions
 */

#define NSEC		1000000000	/* 10^9 */
#define MSEC_TO_NSEC	1000000		/* 10^6 */

#define MAX_FEC_COUNT		2	/* number of FEC data to be filled */

#define MAX_SERVER_POLL_TIMEOUT	10	/* in seconds */

/*
 * Server API
 */
struct am2n_server_ctx *am2n_server_init(const struct am2n_config *config);
void am2n_server_free(struct am2n_server_ctx *ctx);
int am2n_server_open_socket(struct am2n_server_ctx *ctx, int port, bool ipv6);
int am2n_server_loop(struct am2n_server_ctx *ctx);

/*
 * Server mDNS publisher
 */
struct am2n_mdns_ctx *am2n_server_publish_mdns(struct am2n_server_ctx *server,
					       const char *service);
void am2n_server_quit_mdns(struct am2n_mdns_ctx *ctx);

/*
 * Client API
 */
struct am2n_client_ctx *am2n_client_init(const void *addr,
					 const struct am2n_config *config);
void am2n_client_free(struct am2n_client_ctx *ctx);
int am2n_client_handshake(struct am2n_client_ctx *ctx);
int am2n_client_loop(struct am2n_client_ctx *ctx);

/*
 * Server I/O ops initialization
 */
int am2n_io_init(struct am2n_ctx *ctx);

/*
 * Authentication
 */
#ifdef SUPPORT_AUTH
void am2n_set_auth(struct am2n_ctx *ctx, const char *username,
		   const char *secret, bool forced);
void generate_crypto_nonce(unsigned char *buf);
int auth_sha256_digest(unsigned char *buf,
		       const unsigned char *nonce,
		       const unsigned char *secret,
		       int secret_len);
int user_auth_sha256_digest(unsigned char *buf,
			    const unsigned char *nonce,
			    const unsigned char *user,
			    int user_len,
			    const unsigned char *passwd,
			    int passwd_len);
#endif

/*
 * Debug
 */
extern int enable_debug;

#define log(fmt, args...) fprintf(stderr, fmt "\n", ##args)
#define error(fmt, args...) fprintf(stderr, "ERROR: " fmt "\n", ##args)
#define __debug(level, fmt, args...) do {		\
	if (enable_debug >= level) \
		fprintf(stderr, fmt "\n", ##args); \
	} while (0)
#define debug(fmt, args...) __debug(1, fmt, ##args)
#define debug2(fmt, args...) __debug(2, fmt, ##args)

#endif /* __AMIDI2NET_H_INC */
