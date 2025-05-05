/*
 * amidi2net common code
 */

#include "amidi2net.h"
#include "packet.h"
#include "options.h"
#include <assert.h>

int enable_debug = 0;

static int submit_ump_data(struct ump_session *session,
			   int step_back, unsigned short seqno);
static int do_fail_test(struct ump_sock *sock, const void *addr,
			unsigned int addr_size, const unsigned char *buf,
			int size);

/* Send a UDP message of the given buffer for the given byte size */
static int send_msg(struct ump_sock *sock, const void *addr,
		    unsigned int addr_size, const unsigned char *buf, int size)
{
	int n;

	if (sock->ctx->config->fail_test_mode < FAIL_TEST_DROP_RECEIVER) {
		n = do_fail_test(sock, addr, addr_size, buf, size);
		if (n)
			return n;
	}

	debug2("send_msg: size=%d, %02x:%02x:%02x:%02x",
	       size, buf[4], buf[5], buf[6], buf[7]);
	return sendto(sock->sockfd, buf, size, 0, addr, addr_size);
}

/* Send a UDP message for the session */
static int send_session_msg(struct ump_session *session,
			    const unsigned char *buf, int size)
{
	return send_msg(session->sock, &session->addr, session->addr_size,
			buf, size);
}

/* Send "Bye" message */
static int send_bye(struct ump_sock *sock, const void *addr,
		    unsigned int addr_size, unsigned char reason)
{
	unsigned char buf[8];

	add_signature(buf);
	cmd_fill_bye(buf + 4, reason, NULL);

	return send_msg(sock, addr, addr_size, buf, 8);
}

/* Send "Invitation Reply: Accepted" message */
static int send_invitation_reply_accept(struct ump_session *session)
{
	struct am2n_ctx *ctx = session->ctx;
	unsigned char buf[256];
	int len = 1;

	add_signature(buf);
	len += cmd_fill_invitation_reply_accept(buf + 4,
						ctx->ep_name, ctx->prod_id);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Send "Session Reset Reply" message */
static int send_session_reset_reply(struct ump_session *session)
{
	unsigned char buf[8];

	add_signature(buf);
	cmd_fill_session_reset_reply(buf + 4);
	return send_session_msg(session, buf, 8);
}

/* Send "Session Ping Reply" message */
static int send_ping_reply(struct ump_sock *sock, const void *addr,
			   unsigned int addr_size,
			   const unsigned char *ping_id)
{
	unsigned char buf[12];

	add_signature(buf);
	cmd_fill_ping_reply(buf + 4, ping_id);
	return send_msg(sock, addr, addr_size, buf, 12);
}

/* Send "NAK" message; text can be NULL */
static int send_nak(struct ump_sock *sock, const void *addr,
		    unsigned int addr_size, unsigned char reason,
		    const unsigned char *cmd, const char *text)
{
	unsigned char buf[256];
	int len = 1;

	add_signature(buf);
	len += cmd_fill_nak(buf + 4, reason, cmd, text);
	assert(len * 4 <= sizeof(buf));
	return send_msg(sock, addr, addr_size, buf, len * 4);
}

/* Send "Bye Reply" message */
static int send_bye_reply(struct ump_sock *sock, const void *addr,
			  unsigned int addr_size)
{
	unsigned char buf[8];

	add_signature(buf);
	cmd_fill_bye_reply(buf + 4);
	return send_msg(sock, addr, addr_size, buf, 8);
}

/* Send "Retransmit Request" message */
static int send_retransmit_req(struct ump_session *session,
			       unsigned short seqno)
{
	unsigned char buf[16];
	int len = 1;

	add_signature(buf);
	len += cmd_fill_retransmit_req(buf + 4, seqno);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Send "Ping" message */
static int send_ping(struct ump_session *session)
{
	unsigned char buf[16];
	unsigned int ping_id = session->seqno_sent;
	int len = 1;

	add_signature(buf);
	len += cmd_fill_ping(buf + 4, (unsigned char *)&ping_id);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Send "Invitation" message -- only for client */
static int send_invitation(struct am2n_client_ctx *ctx)
{
	struct ump_session *session = ctx->session;
	unsigned char buf[256];
	unsigned char auth = 0;
	int len = 1;

#ifdef SUPPORT_AUTH
	auth = ctx->core.auth_support;
#endif

	add_signature(buf);
	len += cmd_fill_invitation(buf + 4, auth,
				   ctx->core.ep_name, ctx->core.prod_id);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

#ifdef SUPPORT_AUTH
/* Send "Invitation Reply: Authentication Required" message */
static int send_invitation_reply_auth_req(struct ump_session *session,
					  unsigned char state)
{
	struct am2n_ctx *ctx = session->ctx;
	unsigned char buf[256];
	int len = 1;

	add_signature(buf);
	len += cmd_fill_invitation_reply_auth_req(buf + 4,
						  state,
						  session->crypto_nonce,
						  ctx->ep_name,
						  ctx->prod_id);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Send "Invitation Reply: User Authentication Required" message */
static int send_invitation_reply_user_auth_req(struct ump_session *session,
					       unsigned char state)
{
	struct am2n_ctx *ctx = session->ctx;
	unsigned char buf[256];
	int len = 1;

	add_signature(buf);
	len += cmd_fill_invitation_reply_user_auth_req(buf + 4,
						       state,
						       session->crypto_nonce,
						       ctx->ep_name,
						       ctx->prod_id);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Send "Invitation with Authentication" message */
static int send_invitation_with_auth(struct ump_session *session,
				     const unsigned char *cmd)
{
	struct am2n_ctx *ctx = session->ctx;
	char buf[64];
	unsigned char digest[32];
	int len = 1;

	if (auth_sha256_digest(digest, session->crypto_nonce, ctx->auth_secret,
			       strlen((const char *)ctx->auth_secret))) {
		error("SHA256 digest creation error");
		return -1;
	}

	add_signature(buf);
	len += cmd_fill_invitation_with_auth(buf + 4, digest);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Send "Invitation with User Authentication" message */
static int send_invitation_with_user_auth(struct ump_session *session,
					  const unsigned char *cmd)
{
	struct am2n_ctx *ctx = session->ctx;
	char buf[256];
	unsigned char digest[32];
	int len = 1;

	if (user_auth_sha256_digest(digest, session->crypto_nonce,
				    ctx->auth_username,
				    strlen(ctx->auth_username),
				    ctx->auth_secret,
				    strlen(ctx->auth_secret))) {
		error("SHA256 digest creation error");
		return -1;
	}

	add_signature(buf);
	len += cmd_fill_invitation_with_user_auth(buf + 4, digest,
						 ctx->auth_username);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/* Try to authenticate (for server) */
static int try_session_auth(struct ump_session *session,
			    const unsigned char *cmd)
{
	struct am2n_ctx *ctx = session->ctx;
	unsigned char digest[32];

	auth_sha256_digest(digest, session->crypto_nonce, ctx->auth_secret,
			   strlen(ctx->auth_secret));
	if (!memcmp(digest, cmd + 4, 32))
		return 0; /* OK */
	else
		return AUTH_STATE_RETRY;
}

/* Try to authenticate with user (for server) */
static int try_session_user_auth(struct ump_session *session,
				 const unsigned char *cmd,
				 int cmd_len)
{
	struct am2n_ctx *ctx = session->ctx;
	const char *user = cmd + 36;
	int user_len = strnlen(user, cmd_len - 36);
	unsigned char digest[32];
	int s;

	s = strncmp(user, ctx->auth_username, user_len);
	if (s && s != user_len)
		return AUTH_STATE_USER_NOT_FOUND;

	user_auth_sha256_digest(digest, session->crypto_nonce,
				ctx->auth_username, strlen(ctx->auth_username),
				ctx->auth_secret,
				strlen(ctx->auth_secret));
	if (!memcmp(digest, cmd + 4, 32))
		return 0; /* OK */
	else
		return AUTH_STATE_RETRY;
}

/* Set up the auth config */
void am2n_set_auth(struct am2n_ctx *ctx, const char *username,
		   const char *secret, bool forced)
{
	if (username && secret)
		ctx->auth_support = UMP_NET_CAPS_INVITATION_USER_AUTH;
	else if (secret)
		ctx->auth_support = UMP_NET_CAPS_INVITATION_AUTH;
	ctx->auth_forced = forced;
	ctx->auth_username = username;
	ctx->auth_secret = secret;
	if (ctx->auth_support) {
		debug("* server setup auth support: %s",
		      (ctx->auth_support & UMP_NET_CAPS_INVITATION_USER_AUTH) ?
		      "user-auth" : "auth");
	}
}
#endif /* SUPPORT_AUTH */

/*
 * Handle retransmit request
 */
static int retransmit_ump(struct ump_session *session,
			  unsigned short seqno,
			  unsigned char num_ump)
{
	unsigned char buf[24];
	int len, num;

	debug("retransmit requested, seqno = %d", seqno);

	/* A non-existing (future) seqno is requested? */
	if (seqno_diff(session->seqno_sent, seqno) < 0)
		goto error;

	/* Try to send a UMP data from the output cache */
	for (num = 0; !num_ump || num < num_ump; num++, seqno++) {
		if (seqno > session->seqno_sent)
			break;
		if (submit_ump_data(session, session->seqno_sent - seqno,
				    session->seqno_sent) <= 0)
			goto error;
	}
	return 0;

 error:
	debug("retransmitting error, no data available");
	len = 1;
	add_signature(buf);
	len += cmd_fill_retransmit_err(buf + 4, seqno,
				       UMP_NET_RETRANSMIT_ERR_REASON_NO_DATA);
	assert(len * 4 <= sizeof(buf));
	return send_session_msg(session, buf, len * 4);
}

/*
 * Helpers for wallclock time and timeouts
 */

/* Set base time; called at server / client init phase */
static void set_base_time(struct am2n_ctx *ctx)
{
	struct timeval tv;
#ifdef CLOCK_MONOTONIC
	struct timespec tspec;

	if (!clock_gettime(CLOCK_MONOTONIC, &tspec)) {
		ctx->base_time = tspec.tv_sec;
		return;
	}
#endif
	gettimeofday(&tv, NULL);
	ctx->base_time = tspec.tv_sec;
}

/* Update wallclock timestamp */
static void update_timestamp(struct am2n_ctx *ctx)
{
	struct timeval tv;
#ifdef CLOCK_MONOTONIC
	struct timespec tspec;

	if (!clock_gettime(CLOCK_MONOTONIC, &tspec)) {
		ctx->tstamp = (tspec.tv_sec - ctx->base_time) * NSEC +
			tspec.tv_nsec;
		return;
	}
#endif
	gettimeofday(&tv, NULL);
	ctx->tstamp = (tv.tv_sec - ctx->base_time) * NSEC +
		tv.tv_usec * 1000;
}

/* Calculate the tstamp with the given timeout */
static uint64_t get_timeout_msec(struct am2n_ctx *ctx, unsigned int msec)
{
	return ctx->tstamp + msec * (uint64_t)MSEC_TO_NSEC;
}

/* Get the poll timeout in msec from the given nsec wallclock timestamp */
static int get_poll_timeout(struct am2n_ctx *ctx, uint64_t tstamp)
{
	tstamp -= ctx->tstamp;
	if (tstamp > MAX_SERVER_POLL_TIMEOUT * (uint64_t)NSEC)
		return MAX_SERVER_POLL_TIMEOUT * 1000;
	return (tstamp + MSEC_TO_NSEC - 1) / MSEC_TO_NSEC;
}

/*
 * Output cache management
 *
 * output_cache keeps the UMP packets that have been sent, and it's used for
 * FEC and retransmit requests.
 *
 * index points to the last written data, and the previous data is kept
 * at data[index - 1], the one before is data[index - 2], etc
 *
 * Both server/client always put the data to this output cache once before
 * writing to the device.  That's the reason submit_ump_data() is called
 * step_back=0 for writing the incoming UMP.
 *
 * A caveat is that it assumes only a single UMP packet (up to 16 bytes).
 */

/* Initialize the output cache buffer */
static struct ump_output_cache *
ump_output_cache_init(unsigned int cache_size)
{
	struct ump_output_cache *cache;

	cache = malloc(sizeof(*cache) +
		       cache_size * sizeof(struct ump_output_cache_entry));
	if (!cache)
		return cache;
	cache->index = 0;
	cache->cache_size = cache_size;
	cache->cached = 0;
	return cache;
}

/* Release the output cache buffer */
static void ump_output_cache_free(struct ump_output_cache *cache)
{
	free(cache);
}

/* Append a UMP packet to the output cache buffer */
static void ump_output_cache_add(struct ump_output_cache *cache,
				 const void *buf,
				 unsigned char packet_len)
{
	const uint32_t *ump = buf;
	uint32_t *p;

	if (cache->cached > 0)
		cache->index = (cache->index + 1) % cache->cache_size;
	cache->entries[cache->index].len = packet_len;
	p = (uint32_t *)cache->entries[cache->index].data;
	for (; packet_len > 0; packet_len--, p++, ump++)
		*p = htonl(*ump);
	if (cache->cached < cache->cache_size)
		cache->cached++;
}

/* Read out a UMP packet from the output buffer;
 * the read position goes back with the given step (0 for the latest).
 * Return -1 if it's beyond the buffer
 */
static int ump_output_cache_read(const struct ump_output_cache *cache,
				 unsigned char *buf,
				 unsigned short seqno_base,
				 unsigned short step_back)
{
	unsigned int index;

	if (step_back > cache->cached)
		return -1;
	index = (cache->index + cache->cache_size - step_back) % cache->cache_size;
	return cmd_fill_ump_data(buf, cache->entries[index].data,
				 cache->entries[index].len,
				 seqno_base - step_back);
}

/*
 * Input pending buffer management
 *
 * When a UMP packet from the network isn't the next seqno, it's kept in
 * the input pending buffer and picked up after the expected seqno arrives.
 *
 * FIXME: the buffer management is very simple, just keep the data in the
 * byte array without tree or hash.  The pending data is supposed to be
 * very few, so I kept as is for now.
 */

/* Clear pending buffer */
static void clear_pending_buffer(struct ump_session *session)
{
	session->pending_buffer.filled = 0;
}

/* Get seqno from pending buffer entry */
static inline unsigned short pb_seqno(uint32_t v)
{
	return (unsigned short)((v) & 0xffff);
}

/* Get packet length from pending buffer entry */
static inline unsigned char pb_len(uint32_t v)
{
	return ((v) >> 16) & 0xff;
}

/* Reduce the old entries in the pending buffer until the given size freed */
static void reduce_pending_buffer(struct ump_session *session,
				  int size)
{
	struct ump_pending_buffer *pb = &session->pending_buffer;
	int delsize = size - (PENDING_BUFFER_SIZE - pb->filled);
	unsigned char head;
	unsigned char len;
	uint32_t *p;

	for (head = 0; head < pb->filled; head += len + 1) {
		p = pb->buffer + head;
		if (delsize <= 0) {
			pb->filled -= head;
			memmove(pb->buffer, p, pb->filled * 4);
			return;
		}
		len = pb_len(*p);
		delsize -= len + 1;
	}
}

/* Purge pending buffer if all filled events are expired */
static void purge_pending_buffer(struct ump_session *session,
				 unsigned short seqno)
{
	struct ump_pending_buffer *pb = &session->pending_buffer;
	unsigned char head, len;
	uint32_t *p;

	if (!pb->filled)
		return;

	for (head = 0; head < pb->filled; head += len + 1) {
		p = pb->buffer + head;
		if (seqno_diff(pb_seqno(*p), seqno) > 0)
			return;
		len = pb_len(*p);
	}

	pb->filled = 0;
}

/* Push a UMP packet to the pending buffer with the given seqno */
static int push_pending_buffer(struct ump_session *session,
			       unsigned short seqno,
			       const uint32_t *ump,
			       int len)
{
	struct ump_pending_buffer *pb = &session->pending_buffer;
	uint32_t *p;

	if (len + 1 > PENDING_BUFFER_SIZE)
		return -1;

	if (PENDING_BUFFER_SIZE - pb->filled < len + 1) {
		reduce_pending_buffer(session, len + 1);
		if (PENDING_BUFFER_SIZE - pb->filled < len + 1)
			return -1;
	}

	p = pb->buffer + pb->filled;
	pb->filled += len + 1;
	*p++ = seqno | (len << 16);
	while (len-- > 0)
		*p++ = *ump++;
	return 0;
}

/* Get UMP data of the given seqno from the pending buffer;
 * return NULL if not found
 */
static uint32_t *peek_pending_buffer(struct ump_pending_buffer *pb,
				     unsigned short seqno,
				     int *lenp)
{
	unsigned char head, len;
	uint32_t *p;

	for (head = 0; head < pb->filled; head += len + 1) {
		p = pb->buffer + head;
		len = pb_len(*p);
		if (pb_seqno(*p) == seqno) {
			*lenp = len;
			return p + 1;
		}
		head += len + 1;
	}
	return NULL;
}

/* Drop the previously peeked UMP data from the pending buffer */
static void drop_pending_buffer(struct ump_pending_buffer *pb,
				uint32_t *p, int len)
{
	int rest = pb->filled - len - (p - pb->buffer);

	pb->filled -= len + 1;
	if (rest <= 0)
		return;
	memmove(p - 1, p + len, rest * 4);
}

/*
 * Session management
 */

/* Find the session of the given address */
static struct ump_session *
find_session(struct am2n_server_ctx *ctx, struct ump_sock *sock,
	     const void *addr, unsigned int addr_size)
{
	struct ump_session *session;

	for (session = ctx->first_session; session; session = session->next) {
		if (session->sock != sock)
			continue;
		if (session->addr_size != addr_size)
			continue;
		if (!memcmp(addr, &session->addr, addr_size))
			return session;
	}
	return NULL;
}

/* Reset the session, used for init and Reset command */
static void reset_session(struct ump_session *session)
{
	struct am2n_ctx *ctx = session->ctx;

	session->seqno_recv = -1;
	session->ump_recv = false;
	session->fec_count = 0;
	session->missing = 0;
	session->ping_req = 0;
	if (ctx->role == ROLE_SERVER)
		session->ping_timeout =
			get_timeout_msec(ctx,
					 ctx->config->liveness_timeout);
	else
		session->ping_timeout = (uint64_t)-1;
	clear_pending_buffer(session);
}

/* Open a session (for server) */
static struct ump_session *
open_server_session(struct am2n_ctx *core, struct ump_sock *sock,
		    const sock_addr_t *addr, unsigned int addr_size)
{
	struct am2n_server_ctx *ctx = (struct am2n_server_ctx *)core;
	struct ump_session *session;

	debug("open server session (%s)", sock->ipv6 ? "ipv6" : "ipv4");
	if (ctx->sessions >= ctx->core.config->max_sessions)
		return NULL;
	session = calloc(1, sizeof(*session));
	if (!session)
		return NULL;
	session->ctx = core;
	session->sock = sock;
	session->output_cache = ctx->output_cache; // share among all sessions
	memcpy(&session->addr, addr, addr_size);
	session->addr_size = addr_size;
	reset_session(session);
	srandom((unsigned int)core->tstamp);
#ifdef SUPPORT_AUTH
	generate_crypto_nonce(session->crypto_nonce);
#endif
	/* hook to the server */
	session->prev = ctx->last_session;
	if (ctx->last_session)
		ctx->last_session->next = session;
	else
		ctx->first_session = session;
	ctx->last_session = session;
	ctx->sessions++;
	return session;
}

/* Close the session (for server) */
static void close_server_session(struct am2n_ctx *_ctx,
				 struct ump_session *session)
{
	struct am2n_server_ctx *ctx = (struct am2n_server_ctx *)_ctx;

	debug("close server session");
	ctx->sessions--;
	if (session->prev)
		session->prev->next = session->next;
	else
		ctx->first_session = session->next;
	if (session->next)
		session->next->prev = session->prev;
	else
		ctx->last_session = session->prev;
}

/*
 * Handle UMP data input from the network
 */
/* wrapper */
static int write_ump_packet(struct am2n_ctx *ctx, const void *ump, int plen)
{
	if (plen > 0 && ctx->io.ops->write_ump_packet(ctx, ump, plen) < 0)
		return -1;
	return 0;
}

/* Swap data bytes of the given UMP data between network and host */
static void swap_ump_bytes(void *buf, int words)
{
	uint32_t *ump = buf;

	for (; words; words--, ump++)
		*ump = htonl(*ump);
}

/* Parse UMP data packet(s) read from the network and process it;
 * input is the UMP data in host byte-order
 */
static int session_read_ump(struct ump_session *session,
			    unsigned short seqno, unsigned char plen,
			    const void *input)
{
	struct am2n_ctx *ctx = session->ctx;
	const uint32_t *ump = input;
	signed short diff;
	uint32_t *p;
	int len;

	debug2("ump: seqno=%d/%d/%d, plen=%d",
	       seqno, session->seqno_recv, session->seqno_recv_highest, plen);
	/* Is this the first incoming UMP data? */
	if (!session->ump_recv) {
		/* yes, then write to the device and store state */
		session->ump_recv = true;
		if (write_ump_packet(ctx, ump, plen) < 0)
			return -1;
		session->seqno_recv = seqno;
		session->seqno_recv_highest = seqno;
		purge_pending_buffer(session, seqno);
		return 0;
	}

	diff = seqno_diff(seqno, session->seqno_recv);
	/* If it's uninteresting FEC UMP data, just skip */
	if (diff <= 0)
		return 0;

	if (diff == 1) {
		/* Next packet, moving forward */
		if (write_ump_packet(ctx, ump, plen) < 0)
			return -1;

		session->seqno_recv = seqno;
		session->missing = 0;
		/* If this is the latest packet, go out gracefully */
		if (seqno_diff(seqno, session->seqno_recv_highest) >= 0) {
			session->seqno_recv_highest = seqno;
			purge_pending_buffer(session, seqno);
			return 0;
		}

		/* Try to handle pending inputs as much as possible */
		while ((p = peek_pending_buffer(&session->pending_buffer,
						++seqno, &len)) != NULL) {
			if (write_ump_packet(ctx, p, len) < 0)
				return -1;
			drop_pending_buffer(&session->pending_buffer, p, len);
			session->seqno_recv = seqno;
			if (seqno == session->seqno_recv_highest)
				return 0; /* all done */
		}

		/* Still missing packet present, set up the timeout for resubmit request */
		session->missing = 1;
		session->missing_timeout =
			get_timeout_msec(ctx, ctx->config->missing_pkt_timeout);
		return 0;
	}

	/* One of packets missing */
	/* If this the highest seqno, record it */
	if (seqno_diff(seqno, session->seqno_recv_highest) > 0)
		session->seqno_recv_highest = seqno;
	push_pending_buffer(session, seqno, ump, plen);

	/* Set the timeout if not set up yet */
	if (!session->missing) {
		session->missing = 1;
		session->missing_timeout =
			get_timeout_msec(ctx, ctx->config->missing_pkt_timeout);
	}

	return 0;
}

/* Minimal / max command length */
struct ump_net_cmd_len {
	unsigned char min, max, set;
};

static struct ump_net_cmd_len ump_net_cmd_lens[256] = {
	[UMP_NET_INVITATION] = { 2, 36, 1 },
	[UMP_NET_INVITATION_WITH_AUTH] = { 8, 8, 1 },
	[UMP_NET_INVITATION_WITH_USER_AUTH] = { 8, 255, 1 },
	[UMP_NET_INVITATION_REPLY_ACCEPT] = { 2, 36, 1 },
	[UMP_NET_INVITATION_REPLY_PENDING] = { 2, 36, 1 },
	[UMP_NET_INVITATION_REPLY_AUTH_REQ] = { 6, 40, 1 },
	[UMP_NET_INVITATION_REPLY_USER_AUTH_REQ] = { 6, 40, 1 },
	[UMP_NET_PING] = { 1, 1, 1 },
	[UMP_NET_PING_REPLY] = { 1, 1, 1 },
	[UMP_NET_RETRANSMIT_REQ] = { 1, 1, 1 },
	[UMP_NET_RETRANSMIT_ERR] = { 1, 1, 1 },
	[UMP_NET_SESSION_RESET] = { 0, 0, 1 },
	[UMP_NET_SESSION_RESET_REPLY] = { 0, 0, 1 },
	[UMP_NET_NAK] = { 1, 255, 1 },
	[UMP_NET_BYE] = { 0, 255, 1 },
	[UMP_NET_BYE_REPLY] = { 0, 0, 1 },
	[UMP_NET_UMP_DATA] = { 0, 64, 1 },
};

/* Check whether the command has valid length; return the NAK reason */
static int check_cmd_len(const unsigned char *cmd)
{
	unsigned char min_len, max_len;

	if (!ump_net_cmd_lens[cmd[0]].set)
		return UMP_NET_NAK_REASON_CMD_NOT_SUPPORTED;
	min_len = ump_net_cmd_lens[cmd[0]].min;
	max_len = ump_net_cmd_lens[cmd[0]].max;
	if (cmd[1] < min_len || cmd[1] > max_len)
		return UMP_NET_NAK_REASON_CMD_MALFORMED;
	return 0;
}

/* A helper wrapper for a common NAK */
static int nak_not_expected(struct ump_sock *sock, const void *addr,
			    unsigned int addr_size,
			    const unsigned char *cmd)
{
	if (send_nak(sock, addr, addr_size, UMP_NET_NAK_REASON_CMD_NOT_EXPECTED,
		     cmd, NULL) < 0)
		return -1;
	return 0;
}

/* Process a UDP packet;
 * The data might be modified for UMP byte swaps
 */
static int process_session_cmd(struct am2n_ctx *ctx,
			       struct ump_session *session,
			       struct ump_sock *sock,
			       const sock_addr_t *addr,
			       unsigned int addr_size,
			       unsigned char *cmd, int len)
{
	unsigned short seqno;
	int cmd_len, err;

	for (; len > 0; len -= cmd_len, cmd += cmd_len) {
		debug2("UDP in: %02x:%02x:%02x:%02x",
		       cmd[0], cmd[1], cmd[2], cmd[3]);
		cmd_len = (cmd[1] + 1) * 4;
		if (len < cmd_len) {
			debug("UDP cmd truncated, remaining = %d/%d",
			      len, cmd_len);
			break;
		}

		err = check_cmd_len(cmd);
		if (err) {
			send_nak(sock, addr, addr_size, err, cmd, NULL);
			break;
		}

		switch (*cmd) {
		case UMP_NET_INVITATION:
			debug("received invitation");
			if (ctx->role != ROLE_SERVER) {
				if (nak_not_expected(sock, addr, addr_size, cmd))
					return -1;
				break;
			}
			if (cmd[2] > 0)
				debug("  ep_name = %s", cmd + 4);
			if (cmd_len > cmd[2] + 1)
				debug("  prod_id = %s", cmd + 4 + (cmd[2] * 4));
			debug("  caps = auth:%s, user-auth:%s",
			      cmd[3] & UMP_NET_CAPS_INVITATION_AUTH ? "yes" : "no",
			      cmd[3] & UMP_NET_CAPS_INVITATION_USER_AUTH ? "yes" : "no");
			if (session && session->state != STATE_INVITATION) {
				if (nak_not_expected(sock, addr, addr_size, cmd))
					return -1;
				break;
			}
			if (!session) {
				session = ctx->open_session(ctx, sock, addr, addr_size);
				if (!session) {
					if (send_bye(sock, addr, addr_size,
						     UMP_NET_BYE_REASON_INV_FAILED_TOO_MANY_SESSIONS) < 0)
						return -1;
					return 0;
				}
			}
#ifdef SUPPORT_AUTH
			if (ctx->auth_support & cmd[3] &
			    UMP_NET_CAPS_INVITATION_AUTH) {
				debug("send invitation reply with auth req");
				if (send_invitation_reply_auth_req(session, 0) < 0)
					return -1;
				return 0;
			} else if (ctx->auth_support & cmd[3] &
				   UMP_NET_CAPS_INVITATION_USER_AUTH) {
				debug("send invitation reply with user-auth req");
				if (send_invitation_reply_user_auth_req(session, 0) < 0)
					return -1;
				return 0;
			} else if (ctx->auth_forced) {
				send_bye(sock, addr, addr_size,
					 UMP_NET_BYE_REASON_NO_MATCHING_AUTH);
				return 0;
			}
#endif
			debug("invitation accepted");
			session->state = STATE_RUNNING;
			send_invitation_reply_accept(session);
			break;

		case UMP_NET_INVITATION_WITH_AUTH:
#ifdef SUPPORT_AUTH
			if (ctx->role == ROLE_SERVER &&
			    (ctx->auth_support & UMP_NET_CAPS_INVITATION_AUTH) &&
			    session && session->state == STATE_INVITATION) {
				int state;

				debug("try authentication");
				state = try_session_auth(session, cmd);
				if (state < 0)
					return -1;
				else if (state == 0) {
					debug("auth accepted");
					session->state = STATE_RUNNING;
					send_invitation_reply_accept(session);
				} else {
					/* TODO: delay for repeated requests */
					debug("asking retry auth...");
					if (send_invitation_reply_auth_req(session, state) < 0)
						return -1;
				}
				break;
			}
#endif /* SUPPORT_AUTH */
			if (nak_not_expected(sock, addr, addr_size, cmd))
				return -1;
			break;
		case UMP_NET_INVITATION_WITH_USER_AUTH:
#ifdef SUPPORT_AUTH
			if (ctx->role == ROLE_SERVER &&
			    (ctx->auth_support & UMP_NET_CAPS_INVITATION_USER_AUTH) &&
			    session && session->state == STATE_INVITATION) {
				int state;

				debug("try user authentication");
				state = try_session_user_auth(session, cmd, cmd_len);
				if (state < 0)
					return -1;
				else if (state == 0) {
					debug("auth accepted");
					session->state = STATE_RUNNING;
					send_invitation_reply_accept(session);
				} else {
					/* TODO: delay for repeated requests */
					debug("asking retry auth...");
					if (send_invitation_reply_user_auth_req(session, state) < 0)
						return -1;
				}
				break;
			}
#endif /* SUPPORT_AUTH */
			if (nak_not_expected(sock, addr, addr_size, cmd))
				return -1;
			break;
		case UMP_NET_INVITATION_REPLY_ACCEPT:
			if (!session || ctx->role != ROLE_CLIENT) {
				if (nak_not_expected(sock, addr, addr_size, cmd))
					return -1;
				break;
			}
			if (session->state != STATE_INVITATION) {
				if (nak_not_expected(sock, addr, addr_size, cmd))
					return -1;
				break;
			}
			debug("invitation accepted");
			session->state = STATE_RUNNING;
			break;
		case UMP_NET_INVITATION_REPLY_PENDING:
			debug("invitation reply pending");
			if (ctx->role != ROLE_CLIENT) {
				if (nak_not_expected(sock, addr, addr_size, cmd))
					return -1;
			}
			break;
		case UMP_NET_INVITATION_REPLY_AUTH_REQ:
#ifdef SUPPORT_AUTH
			if (ctx->role == ROLE_CLIENT &&
			    ctx->auth_support & UMP_NET_CAPS_INVITATION_AUTH) {
				if (cmd[3]) {
					error("Invalid auth: state = %d", cmd[3]);
					return -1;
				}
				debug("retry invitation with auth");
				memcpy(session->crypto_nonce, cmd + 4, 16);
				if (send_invitation_with_auth(session, cmd) < 0)
					return -1;
				break;
			}
#endif /* SUPPORT_AUTH */
			if (nak_not_expected(sock, addr, addr_size, cmd))
				return -1;
			break;
		case UMP_NET_INVITATION_REPLY_USER_AUTH_REQ:
#ifdef SUPPORT_AUTH
			if (ctx->role == ROLE_CLIENT &&
			    ctx->auth_support & UMP_NET_CAPS_INVITATION_USER_AUTH) {
				if (cmd[3]) {
					error("Invalid user auth: state = %d", cmd[3]);
					return -1;
				}
				debug("retry invitation with user-auth");
				memcpy(session->crypto_nonce, cmd + 4, 16);
				if (send_invitation_with_user_auth(session, cmd) < 0)
					return -1;
				break;
			}
#endif /* SUPPORT_AUTH */
			if (nak_not_expected(sock, addr, addr_size, cmd))
				return -1;
			break;
		case UMP_NET_SESSION_RESET:
			debug("received session reset");
			if (!session) {
				if (send_bye(sock, addr, addr_size,
					     UMP_NET_BYE_REASON_SESSION_NOT_ESTABLISHED) < 0)
					return -1;
				break;
			}
			reset_session(session);
			if (send_session_reset_reply(session) < 0)
				return -1;
			break;

		case UMP_NET_SESSION_RESET_REPLY:
			// nothing to do
			break;

		case UMP_NET_PING:
			debug2("ping: id=%02x:%02x:%02x:%02x",
			       cmd[4], cmd[5], cmd[6], cmd[7]);
			if (send_ping_reply(sock, addr, addr_size, cmd + 4) < 0)
				return -1;
			break;

		case UMP_NET_PING_REPLY:
			debug2("ping reply: id=%02x:%02x:%02x:%02x",
			       cmd[4], cmd[5], cmd[6], cmd[7]);
			// TODO: check ping id
			break;

		case UMP_NET_RETRANSMIT_REQ:
			if (session) {
				seqno = (cmd[2] << 8) | cmd[3];
				if (retransmit_ump(session, seqno,
						   (cmd[4] << 8) | cmd[5]) < 0)
					return -1;
			}
			break;

		case UMP_NET_RETRANSMIT_ERR:
			if (session && session->missing > 1) {
				debug("can't receive retransmission, quitting");
				send_bye(sock, addr, addr_size,
					 UMP_NET_BYE_REASON_PACKET_MISSING);
				ctx->close_session(ctx, session);
				session = NULL;
			}
			break;

		case UMP_NET_NAK:
			// ignore
			break;

		case UMP_NET_BYE:
			debug("received bye message, quitting");
			send_bye_reply(sock, addr, addr_size);
			if (session) {
				ctx->close_session(ctx, session);
				session = NULL;
			}
			break;

		case UMP_NET_BYE_REPLY:
			if (session) {
				ctx->close_session(ctx, session);
				session = NULL;
			}
			break;

		case UMP_NET_UMP_DATA:
			if (!session) {
				if (send_bye(sock, addr, addr_size,
					     UMP_NET_BYE_REASON_SESSION_NOT_ESTABLISHED) < 0)
					return -1;
				break;
			}
			seqno = (cmd[2] << 8) | cmd[3];
			swap_ump_bytes(cmd + 4, cmd[1]);
			if (session_read_ump(session, seqno, cmd[1], cmd + 4) < 0)
				return -1;
			break;

		default:
			if (send_nak(sock, addr, addr_size,
				     UMP_NET_NAK_REASON_CMD_NOT_SUPPORTED,
				     cmd, NULL) < 0)
				return -1;
			break;
		}
	}

	return 0;
}

/* Receive a UDP packet; return number of received bytes */
static int receive_msg(struct ump_sock *sock, unsigned char *buf,
		       unsigned int size, sock_addr_t *addr,
		       socklen_t *addr_size)
{
	int n, test;

	*addr_size = sizeof(*addr);
	n = recvfrom(sock->sockfd, buf, size, 0,
		     (struct sockaddr *)addr, addr_size);

	if (n < 4 || n % 4) {
		debug("invalid packet size %d", n);
		return 0;
	}
	if (!check_signature(buf)) {
		debug("invalid packet signature");
		return 0;
	}

	if (sock->ctx->config->fail_test_mode >= FAIL_TEST_DROP_RECEIVER) {
		test = do_fail_test(sock, addr, *addr_size, buf, n);
		if (test)
			return 0; /* dropped */
	}

	return n;
}

/* Set up a UDP packet for a UMP data;
 * the data must have been already put to the output cache beforehand.
 * If FEC is enabled, fill FEC from the output cache, too.
 * If step_back is non-zero, this function is used for retransmit request.
 */
static int submit_ump_data(struct ump_session *session,
			   int step_back, unsigned short seqno)
{
	unsigned char buf[UMP_NET_MAX_BUF_SIZE];
	int i, ret, len;

	add_signature(buf);
	len = 1;
	for (i = step_back + session->fec_count; i >= step_back; i--) {
		ret = ump_output_cache_read(session->output_cache,
					    buf + len * 4,
					    seqno, i);
		if (ret > 0) {
			len += ret;
			assert(len * 4 <= sizeof(buf));
		}
	}
	if (len == 1)
		return 0; // no data to send
	return send_session_msg(session, buf, len * 4);
}

/*
 * Handle session timeout
 */
static void process_session_timeout(struct ump_session *session)
{
	struct am2n_ctx *ctx = session->ctx;
	unsigned short seqno;

	/* A packet was missing and its timeout is expired? */
	if (session->missing &&
	    session->missing_timeout >= ctx->tstamp) {
		if (session->missing > ctx->config->max_missing_retry) {
			debug("missing packet, unrecoverable, bye");
			send_bye(session->sock, &session->addr,
				 session->addr_size,
				 UMP_NET_BYE_REASON_PACKET_MISSING);
			ctx->close_session(ctx, session);
			return;
		}

		/* Try to recover with retransmit request */
		seqno = session->seqno_recv + 1;
		debug("missing packet, retransmit request #%d, seqno = %d",
		      session->missing - 1, seqno);
		session->missing++;
		send_retransmit_req(session, seqno);
		session->missing_timeout =
			get_timeout_msec(ctx, ctx->config->retransmit_timeout);
		return;
	}

	/* Is ping needed? */
	if (ctx->tstamp < session->ping_timeout)
		return;
	if (session->ping_req >= ctx->config->max_ping_retry) {
		debug("timeout, ping over, bye");
		send_bye(session->sock, &session->addr, session->addr_size,
			 UMP_NET_BYE_REASON_SESSION_TERMINATED);
		ctx->close_session(ctx, session);
		return;
	}

	/* Session invitation timeout */
	if (session->state == STATE_INVITATION) {
		ctx->close_session(ctx, session);
		return;
	}

	/* Try to send a ping for heartbeat */
	session->ping_req++;
	debug("ping #%d", session->ping_req);
	send_ping(session);
	session->ping_timeout =
		get_timeout_msec(ctx, ctx->config->ping_timeout);
}

/* Process UMP input */
static int process_ump_in(struct am2n_ctx *ctx)
{
	uint32_t ump[4];
	int plen;

	while ((plen = ctx->io.ops->read_ump_packet(ctx, ump)) > 0) {
		debug2("send ump: %08x", *ump);
		ctx->submit_ump(ctx, ump, plen);
		/* Set zero-length UMP timeout */
		ctx->zerolength_ump = 1;
		ctx->zerolength_ump_timeout =
			get_timeout_msec(ctx, ctx->config->zerolength_ump_timeout);
	}

	return plen;
}

/* Handle zero-length UMP */
static void process_zerolength_ump_timeout(struct am2n_ctx *ctx)
{
	if (!ctx->zerolength_ump ||
	    ctx->tstamp < ctx->zerolength_ump_timeout)
		return;

	debug2("send zero-length UMP #%d", ctx->zerolength_ump);
	ctx->submit_ump(ctx, NULL, 0);

	if (ctx->zerolength_ump > MAX_FEC_COUNT) {
		ctx->zerolength_ump = 0;
	} else {
		ctx->zerolength_ump++;
		ctx->zerolength_ump_timeout =
			get_timeout_msec(ctx, ctx->config->zerolength_ump_timeout);
	}
}

/*
 * Server API
 */

/* Process netowrk input for server */
static void process_server_cmd(struct am2n_server_ctx *ctx,
			       struct ump_sock *sock)
{
	struct ump_session *session;
	unsigned char buf[UMP_NET_MAX_BUF_SIZE];
	sock_addr_t addr;
	socklen_t addr_size;
	int n;

	n = receive_msg(sock, buf, sizeof(buf), &addr, &addr_size);
	if (n <= 0)
		return;

	session = find_session(ctx, sock, &addr, addr_size);
	if (session) {
		session->ping_req = 0;
		session->ping_timeout =
			get_timeout_msec(&ctx->core,
					 ctx->core.config->liveness_timeout);
	}

	process_session_cmd(&ctx->core, session, sock, &addr, addr_size,
			    buf + 4, n - 4);
}

/* Callback for submitting UMP data commands including FEC (for server) */
static void submit_server_output_ump(struct am2n_ctx *_ctx,
				     const void *ump, int plen)
{
	struct am2n_server_ctx *ctx = (struct am2n_server_ctx *)_ctx;
	struct ump_session *session;

	assert(plen < 4);
	ump_output_cache_add(ctx->output_cache, ump, plen);

	for (session = ctx->first_session; session; session = session->next) {
		session->seqno_sent++;
		submit_ump_data(session, 0, session->seqno_sent);
		if (ctx->core.config->support_fec &&
		    session->fec_count < MAX_FEC_COUNT)
			session->fec_count++;
	}
}

/* Process UMP input for server */
static void process_server_ump_in(struct am2n_server_ctx *ctx)
{
	if (process_ump_in(&ctx->core) < 0) {
		debug("terminated by I/O");
		ctx->quit = true;
	}
}

/* Calculate the next poll timeout in msec (for server) */
static int calculate_server_timeout(struct am2n_server_ctx *ctx)
{
	struct ump_session *session;
	uint64_t tstamp = ctx->core.tstamp;
	uint64_t timeout = (uint64_t)-1;

	if (ctx->core.zerolength_ump &&
	    ctx->core.zerolength_ump_timeout >= tstamp)
		timeout = ctx->core.zerolength_ump_timeout;

	for (session = ctx->first_session; session; session = session->next) {
		if (session->missing &&
		    session->missing_timeout >= tstamp &&
		    session->missing_timeout < timeout)
			timeout = session->missing_timeout;
		if (session->ping_timeout >= tstamp &&
		    session->ping_timeout < timeout)
			timeout = session->ping_timeout;
	}

	return get_poll_timeout(&ctx->core, timeout);
}

/* Handle timeouts of all connected sessions (for server) */
static void process_server_timeouts(struct am2n_server_ctx *ctx)
{
	struct ump_session *session, *next;

	process_zerolength_ump_timeout(&ctx->core);

	for (session = ctx->first_session; session; session = next) {
		next = session->next;
		process_session_timeout(session);
	}
}

/* Initialize server */
struct am2n_server_ctx *am2n_server_init(const struct am2n_config *config)
{
	struct am2n_server_ctx *ctx;

	am2n_config_debug_print(config, true);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->core.role = ROLE_SERVER;
	ctx->core.config = config;
	ctx->core.open_session = open_server_session;
	ctx->core.close_session = close_server_session;
	ctx->core.submit_ump = submit_server_output_ump;

	ctx->ipv4.sockfd = -1;
	ctx->ipv6.sockfd = -1;
	ctx->ipv6.ipv6 = true;

	ctx->output_cache = ump_output_cache_init(MAX_OUTPUT_CACHE);
	if (!ctx->output_cache) {
		free(ctx);
		return NULL;
	}

	set_base_time(&ctx->core);

	return ctx;
}

/* Free server */
void am2n_server_free(struct am2n_server_ctx *ctx)
{
	if (ctx->core.io.ops && ctx->core.io.ops->free)
		ctx->core.io.ops->free(&ctx->core);
	if (ctx->ipv4.sockfd >= 0)
		close(ctx->ipv4.sockfd);
	if (ctx->ipv6.sockfd >= 0)
		close(ctx->ipv6.sockfd);
	ump_output_cache_free(ctx->output_cache);
	free(ctx);
}

/* Create a UDP socket with the given port for server */
int am2n_server_open_socket(struct am2n_server_ctx *ctx, int port, bool ipv6)
{
	struct ump_sock *sock = ipv6 ? &ctx->ipv6 : &ctx->ipv4;
	sock_addr_t servaddr;
	int optval, fd, err;

	debug("open %s socket for port %d", ipv6 ? "ipv6" : "ipv4", port);
	if (sock->sockfd >= 0)
		return -EBUSY;

	fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -errno;
	}

	optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
		   (const void *)&optval , sizeof(int));

	memset(&servaddr, 0, sizeof(servaddr));
	if (ipv6) {
		servaddr.in6.sin6_family = AF_INET6;
		servaddr.in6.sin6_addr = in6addr_any;
		servaddr.in6.sin6_port = htons(port);
		err = bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	} else {
		servaddr.in.sin_family = AF_INET;
		servaddr.in.sin_addr.s_addr = htonl(INADDR_ANY);
		servaddr.in.sin_port = htons(port);
		err = bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	}

	if (err < 0) {
		perror("bind");
		return -errno;
	}

	if (!port) {
		socklen_t len = sizeof(servaddr);

		if (getsockname(fd, (struct sockaddr *)&servaddr, &len) < 0) {
			perror("getsockname");
			return -errno;
		}
		if (ipv6)
			port = ntohs(servaddr.in6.sin6_port);
		else
			port = ntohs(servaddr.in.sin_port);
		log("assigned UDP port = %d", port);
	}
	sock->ctx = &ctx->core;
	sock->sockfd = fd;
	sock->port = port;
	sock->pfd.fd = fd;
	sock->pfd.events = POLLIN;
	sock->ipv6 = ipv6;

	return 0;
}

/* Main loop for server */
int am2n_server_loop(struct am2n_server_ctx *ctx)
{
	struct pollfd *io_poll, *ipv4_poll, *ipv6_poll;
	struct pollfd pollfds[4]; // FIXME: more flexible size
	int timeout, num_pfds;

	debug("server main loop starting");
	ipv6_poll = NULL;
	io_poll = NULL;
	while (!ctx->quit) {
		num_pfds = 0;
		if (ctx->core.io.ops) {
			io_poll = pollfds;
			num_pfds += ctx->core.io.ops->setup_poll(&ctx->core, pollfds);
		}

		ipv4_poll = &pollfds[num_pfds];
		pollfds[num_pfds++] = ctx->ipv4.pfd;

		if (ctx->ipv6.sockfd >= 0) {
			ipv6_poll = &pollfds[num_pfds];
			pollfds[num_pfds++] = ctx->ipv6.pfd;
		}

		timeout = calculate_server_timeout(ctx);

		if (poll(pollfds, num_pfds, timeout) < 0) {
			perror("poll");
			break;
		}

		update_timestamp(&ctx->core);

		if (io_poll && ctx->core.io.ops->poll_revents(&ctx->core, io_poll))
			process_server_ump_in(ctx);
		if (ipv4_poll->revents & POLLIN)
			process_server_cmd(ctx, &ctx->ipv4);
		if (ipv6_poll && (ipv6_poll->revents & POLLIN))
			process_server_cmd(ctx, &ctx->ipv6);

		process_server_timeouts(ctx);
	}

	return 0;
}

/*
 * Client API
 */

/* close_session callback - just change the state to quit the loop */
static void close_client_session(struct am2n_ctx *ctx,
				 struct ump_session *session)
{
	session->state = STATE_QUIT;
}

/* Callback for submitting UMP data commands including FEC (for client) */
static void submit_client_output_ump(struct am2n_ctx *_ctx,
				     const void *ump, int plen)
{
	struct am2n_client_ctx *ctx = (struct am2n_client_ctx *)_ctx;
	struct ump_session *session = ctx->session;

	assert(plen < 4);
	ump_output_cache_add(session->output_cache, ump, plen);

	session->seqno_sent++;
	submit_ump_data(session, 0, session->seqno_sent);
	if (ctx->core.config->support_fec &&
	    session->fec_count < MAX_FEC_COUNT)
		session->fec_count++;
}

/* Initialize client */
struct am2n_client_ctx *am2n_client_init(const void *addr,
					 const struct am2n_config *config)
{
	struct am2n_client_ctx *ctx;
	struct ump_session *session;
	unsigned int addr_size = config->ipv6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	debug("initializing client, ipv6=%d", config->ipv6);
	am2n_config_debug_print(config, false);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->core.role = ROLE_CLIENT;
	ctx->core.config = config;
	ctx->core.close_session = close_client_session;
	ctx->core.submit_ump = submit_client_output_ump;

	ctx->sock.sockfd = socket(config->ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (ctx->sock.sockfd < 0) {
		perror("socket");
		goto error;
	}

	ctx->sock.ctx = &ctx->core;
	ctx->sock.ipv6 = config->ipv6;
	ctx->sock.pfd.fd = ctx->sock.sockfd;
	ctx->sock.pfd.events = POLLIN;

	session = calloc(1, sizeof(*session));
	if (!session)
		goto error;

	ctx->session = session;
	session->sock = &ctx->sock;
	memcpy(&session->addr, addr, addr_size);
	session->addr_size = addr_size;
	session->ctx = &ctx->core;
	session->state = STATE_INVITATION;

	session->output_cache = ump_output_cache_init(MAX_OUTPUT_CACHE);
	if (!session->output_cache)
		goto error;

	reset_session(session);

	set_base_time(&ctx->core);

	return ctx;

 error:
	am2n_client_free(ctx);
	return NULL;
}

/* Free client */
void am2n_client_free(struct am2n_client_ctx *ctx)
{
	if (ctx->sock.sockfd >= 0)
		close(ctx->sock.sockfd);
	if (ctx->session) {
		if (ctx->session->output_cache)
			ump_output_cache_free(ctx->session->output_cache);
		free(ctx->session);
	}
	free(ctx);
}

/* Calculate the next poll timeout in msec (for client) */
static int calculate_client_timeout(struct am2n_client_ctx *ctx)
{
	struct ump_session *session = ctx->session;
	uint64_t tstamp = ctx->core.tstamp;
	uint64_t timeout = (uint64_t)-1;

	if (ctx->core.zerolength_ump &&
	    ctx->core.zerolength_ump_timeout >= tstamp)
		timeout = ctx->core.zerolength_ump_timeout;

	if (session->missing &&
	    session->missing_timeout >= tstamp &&
	    session->missing_timeout < timeout)
		timeout = session->missing_timeout;

	return get_poll_timeout(&ctx->core, timeout);
}

/* Handle timeouts for client */
static void process_client_timeouts(struct am2n_client_ctx *ctx)
{
	process_zerolength_ump_timeout(&ctx->core);
	process_session_timeout(ctx->session);
}

/* Process UDP input for client */
static void process_client_ump_in(struct am2n_client_ctx *ctx)
{
	if (process_ump_in(&ctx->core) < 0) {
		debug("terminated by I/O");
		ctx->session->state = STATE_QUIT;
	}
}

/* Process netowrk input for client */
static void process_client_cmd(struct am2n_client_ctx *ctx)
{
	unsigned char buf[UMP_NET_MAX_BUF_SIZE];
	sock_addr_t addr;
	socklen_t addr_size;
	int n;

	n = receive_msg(&ctx->sock, buf, sizeof(buf), &addr, &addr_size);
	if (n <= 0)
		return;

	process_session_cmd(&ctx->core, ctx->session, &ctx->sock, &addr,
			    addr_size, buf + 4, n - 4);
}

/* Start invitation and connection to the server */
int am2n_client_handshake(struct am2n_client_ctx *ctx)
{
	int retry = 0;
	uint64_t timeout;

	debug("client handshake starting");
	update_timestamp(&ctx->core);
	srandom((unsigned int)ctx->core.tstamp);
	if (send_invitation(ctx) < 0) {
		error("Send invitation failed");
		return -1;
	}

	update_timestamp(&ctx->core);
	timeout = get_timeout_msec(&ctx->core, ctx->core.config->invitation_timeout);

	while (ctx->session->state == STATE_INVITATION) {
		struct pollfd pollfd = ctx->sock.pfd;

		if (poll(&pollfd, 1, get_poll_timeout(&ctx->core, timeout)) < 0) {
			perror("poll");
			return -1;
		}
		update_timestamp(&ctx->core);
		if (pollfd.revents & POLLIN)
			process_client_cmd(ctx);
		if (ctx->core.tstamp > timeout) {
			if (++retry >= ctx->core.config->max_invitation_retry) {
				error("Too many invitation retries");
				return -1;
			}
			debug("timeout, retrying invitation #%d", retry);
			if (send_invitation(ctx) < 0) {
				error("Send invitation failed");
				return -1;
			}
			timeout = get_timeout_msec(&ctx->core,
						   ctx->core.config->invitation_timeout);
		}
	}

	if (ctx->session->state != STATE_RUNNING)
		return -1;

	return 0;
}

/* Client main loop */
int am2n_client_loop(struct am2n_client_ctx *ctx)
{
	struct pollfd pollfds[4]; // FIXME: more flexible size
	int timeout, num_pfds;
	struct pollfd *io_poll, *ip_poll;

	debug("client main loop starting");
	io_poll = NULL;
	while (ctx->session->state == STATE_RUNNING) {
		num_pfds = 0;
		if (ctx->core.io.ops) {
			io_poll = pollfds;
			num_pfds += ctx->core.io.ops->setup_poll(&ctx->core, pollfds);
		}
		ip_poll = &pollfds[num_pfds];
		pollfds[num_pfds++] = ctx->sock.pfd;

		timeout = calculate_client_timeout(ctx);

		if (poll(pollfds, num_pfds, timeout) < 0) {
			perror("poll");
			return -1;
		}

		update_timestamp(&ctx->core);

		if (io_poll && ctx->core.io.ops->poll_revents(&ctx->core, io_poll))
			process_client_ump_in(ctx);
		if (ip_poll->revents & POLLIN)
			process_client_cmd(ctx);

		process_client_timeouts(ctx);
	}

	return 0;
}

/*
 * I/O backend initialization
 */
extern int am2n_io_rawmidi_init(struct am2n_ctx *ctx);
extern int am2n_io_seq_bridge_init(struct am2n_ctx *ctx);
extern int am2n_io_seq_hub_init(struct am2n_ctx *ctx);

/* Set up the backend I/O based on the current configuration */
int am2n_io_init(struct am2n_ctx *ctx)
{
	debug("initializing I/O backend:");
	ctx->io.type = ctx->config->io_type;
	switch (ctx->io.type) {
	case UMP_IO_BACKEND_RAWMIDI:
		debug("* UMP rawmidi mode");
		return am2n_io_rawmidi_init(ctx);
	case UMP_IO_BACKEND_SEQ_BRIDGE:
		debug("* ALSA sequencer bridge mode");
		return am2n_io_seq_bridge_init(ctx);
	case UMP_IO_BACKEND_SEQ_HUB:
		debug("* ALSA sequencer hub mode");
		return am2n_io_seq_hub_init(ctx);
	default:
		error("Invalid I/O backend type %d", ctx->io.type);
		return -1;
	}
}

/*
 * Simulate packet failures
 */
static int do_fail_test(struct ump_sock *sock, const void *addr,
			unsigned int addr_size, const unsigned char *buf,
			int size)
{
	unsigned int n = sock->ctx->config->fail_test;
	/* FIXME: should be stored in am2n_ctx? */
	static int prev_buf_size = 0;
	static int prev_sockfd, prev_addr_size;
	static sock_addr_t prev_addr;
	static unsigned char prev_buf[UMP_NET_MAX_BUF_SIZE];
	static int drop_count = 0;
	int ret;

	if (!n || !size)
		return 0;

	switch (sock->ctx->config->fail_test_mode) {
	case FAIL_TEST_DROP_SENDER:
	case FAIL_TEST_DROP_RECEIVER:
		if (random() % n)
			return 0;
		debug("simulate packet drop: size=%d, %02x:%02x:%02x:%02x",
		      size, buf[4], buf[5], buf[6], buf[7]);
		return size;
	case FAIL_TEST_DROP_FEC_SENDER:
	case FAIL_TEST_DROP_FEC_RECEIVER:
		if (drop_count) {
			drop_count++;
			debug("simulate packet drop #%d: size=%d, %02x:%02x:%02x:%02x",
			      drop_count, size, buf[4], buf[5], buf[6], buf[7]);
			if (drop_count > MAX_FEC_COUNT)
				drop_count = 0;
			return size;
		}
		if (random() % n)
			return 0;
		debug("simulate packet drop #1: size=%d, %02x:%02x:%02x:%02x",
		      size, buf[4], buf[5], buf[6], buf[7]);
		if (sock->ctx->config->support_fec)
			drop_count = 1;
		return size;
	case FAIL_TEST_SWAP_SENDER:
		if (prev_buf_size) {
			debug("simulate packet swap-B: size=%d, %02x:%02x:%02x:%02x",
			      size, prev_buf[4], prev_buf[5], prev_buf[6], prev_buf[7]);
			ret = sendto(sock->sockfd, buf, size, 0,
				     addr, addr_size);
			if (ret < 0) {
				prev_buf_size = 0;
				return ret;
			}
			ret = sendto(prev_sockfd, prev_buf, prev_buf_size, 0,
				     (void *)&prev_addr, prev_addr_size);
			prev_buf_size = 0;
			return ret;
		}
		if (random() % n)
			return 0;
		debug("simulate packet swap-A: size=%d, %02x:%02x:%02x:%02x",
		      size, buf[4], buf[5], buf[6], buf[7]);
		memcpy(prev_buf, buf, size);
		prev_buf_size = size;
		prev_sockfd = sock->sockfd;
		memcpy(&prev_addr, addr, addr_size);
		prev_addr_size = addr_size;
		return size;
	default:
		return 0;
	}
}
