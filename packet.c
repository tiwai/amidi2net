/*
 * Network MIDI packet helpers
 *
 * Each function returns the number of filled words
 */

#include "amidi2net.h"
#include "packet.h"

/* number of words for the given string (including terminator) */
static int str_word_len(const char *s)
{
	int len;

	if (!s)
		return 0;
	len = strlen(s);
	if (!len)
		return 0;
	return (len + 4) / 4; // including terminator
}

/* fill the string on the buffer, aligned to words */
static void fill_string(unsigned char *buf, const char *str)
{
	int n;

	if (!str)
		return;
	n = strlen(str) + 1;
	memcpy(buf, str, n);
	if (n % 4)
		memset(buf + n, 0, 4 - (n % 4));
}

static int __cmd_fill_invitation(unsigned char *buf,
				 unsigned char cmd, unsigned char caps,
				 const char *ep_name, const char *prod_id)
{
	int ep_name_len = str_word_len(ep_name);
	int prod_id_len = str_word_len(prod_id);
	int len = 1 + ep_name_len + prod_id_len;

	buf[0] = cmd;
	buf[1] = len - 1;
	buf[2] = ep_name_len;
	buf[3] = caps;
	fill_string(buf + 4, ep_name);
	fill_string(buf + 4 + ep_name_len * 4, prod_id);
	return len;
}

/* "Invitation" command */
int cmd_fill_invitation(unsigned char *buf,
			unsigned char ump_caps,
			const char *ump_ep_name,
			const char *ump_prod_id)
{
	return __cmd_fill_invitation(buf, UMP_NET_INVITATION, ump_caps,
				     ump_ep_name, ump_prod_id);
}

/* "Invitation Reply: Accepted" command */
int cmd_fill_invitation_reply_accept(unsigned char *buf,
				     const char *ump_ep_name,
				     const char *ump_prod_id)
{
	return __cmd_fill_invitation(buf, UMP_NET_INVITATION_REPLY_ACCEPT, 0,
				     ump_ep_name, ump_prod_id);
}

/* "Invitation Reply: Pending" command */
int cmd_fill_invitation_reply_pending(unsigned char *buf,
				      const char *ump_ep_name,
				      const char *ump_prod_id)
{
	return __cmd_fill_invitation(buf, UMP_NET_INVITATION_REPLY_PENDING, 0,
				     ump_ep_name, ump_prod_id);
}

static int __cmd_fill_invitation_reply_auth_req(unsigned char *buf,
						unsigned char cmd,
						unsigned char state,
						const unsigned char *crypto,
						const char *ep_name,
						const char *prod_id)
{
	int ep_name_len = str_word_len(ep_name);
	int prod_id_len = str_word_len(prod_id);
	int len = 1 + 4 + ep_name_len + prod_id_len;

	buf[0] = cmd;
	buf[1] = len - 1;
	buf[2] = ep_name_len;
	buf[3] = state;
	memcpy(buf + 4, crypto, 16);
	fill_string(buf + 20, ep_name);
	fill_string(buf + 20 + ep_name_len * 4, prod_id);
	return len;
}

/* "Invitation Reply: Authentication Required" command */
int cmd_fill_invitation_reply_auth_req(unsigned char *buf,
				       unsigned char state,
				       const unsigned char *crypto,
				       const char *ep_name,
				       const char *prod_id)
{
	return __cmd_fill_invitation_reply_auth_req(buf,
						    UMP_NET_INVITATION_REPLY_AUTH_REQ,
						    state, crypto,
						    ep_name, prod_id);
}

/* "Invitation Reply: User Authentication Required" command */
int cmd_fill_invitation_reply_user_auth_req(unsigned char *buf,
					    unsigned char state,
					    const unsigned char *crypto,
					    const char *ep_name,
					    const char *prod_id)
{
	return __cmd_fill_invitation_reply_auth_req(buf,
						    UMP_NET_INVITATION_REPLY_USER_AUTH_REQ,
						    state, crypto,
						    ep_name, prod_id);
}

/* "Invitation with Authentication" command */
int cmd_fill_invitation_with_auth(unsigned char *buf,
				  const unsigned char *digest)
{
	buf[0] = UMP_NET_INVITATION_WITH_AUTH;
	buf[1] = 8;
	buf[2] = 0;
	buf[3] = 0;
	memcpy(buf + 4, digest, 32);
	return 9;
}

/* "Invitation with User Authentication" command */
int cmd_fill_invitation_with_user_auth(unsigned char *buf,
				       const unsigned char *digest,
				       const char *user_name)
{
	int len = 9 + str_word_len(user_name);

	buf[0] = UMP_NET_INVITATION_WITH_USER_AUTH;
	buf[1] = len - 1;
	buf[2] = 0;
	buf[3] = 0;
	memcpy(buf + 4, digest, 32);
	fill_string(buf + 36, user_name);
	return len;
}

/* "Session Reset" command */
int cmd_fill_session_reset(unsigned char *buf)
{
	buf[0] = UMP_NET_SESSION_RESET;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	return 1;
}

/* "Session Reset Reply" command */
int cmd_fill_session_reset_reply(unsigned char *buf)
{
	buf[0] = UMP_NET_SESSION_RESET_REPLY;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	return 1;
}

/* "Ping" command */
int cmd_fill_ping(unsigned char *buf, const unsigned char *ping_id)
{
	buf[0] = UMP_NET_PING;
	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 0;
	memcpy(buf + 4, ping_id, 4);
	return 2;
}

/* "Ping Reply" command */
int cmd_fill_ping_reply(unsigned char *buf, const unsigned char *ping_id)
{
	buf[0] = UMP_NET_PING_REPLY;
	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 0;
	memcpy(buf + 4, ping_id, 4);
	return 2;
}

/* "NAK" command */
int cmd_fill_nak(unsigned char *buf, unsigned char reason,
		 const unsigned char *nak_cmd_header,
		 const char *text_msg)
{
	int len = 2 + str_word_len(text_msg);

	buf[0] = UMP_NET_NAK;
	buf[1] = len - 1;
	buf[2] = reason;
	buf[3] = 0;
	memcpy(buf + 4, nak_cmd_header, 4);
	fill_string(buf + 8, text_msg);
	return len;
}

/* "Bye" command */
int cmd_fill_bye(unsigned char *buf, unsigned char reason,
		 const char *text_msg)
{
	int len = 1 + str_word_len(text_msg);

	buf[0] = UMP_NET_BYE;
	buf[1] = len - 1;
	buf[2] = reason;
	buf[3] = 0;
	fill_string(buf + 4, text_msg);
	return len;
}

/* "Bye Reply" command */
int cmd_fill_bye_reply(unsigned char *buf)
{
	buf[0] = UMP_NET_BYE_REPLY;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	return 1;
}

/* "Retransmit Request" command */
int cmd_fill_retransmit_req(unsigned char *buf, unsigned short seqno)
{
	buf[0] = UMP_NET_RETRANSMIT_REQ;
	buf[1] = 1;
	buf[2] = seqno >> 8;
	buf[3] = seqno & 0xff;
	memset(buf + 4, 0, 4);
	return 2;
}

/* "Retransmit Error" command */
int cmd_fill_retransmit_err(unsigned char *buf, unsigned short seqno,
			    unsigned char reason)
{
	buf[0] = UMP_NET_RETRANSMIT_ERR;
	buf[1] = 1;
	buf[2] = reason;
	buf[3] = 0;
	buf[4] = seqno >> 8;
	buf[5] = seqno & 0xff;
	buf[6] = 0;
	buf[7] = 0;
	return 2;
}

/* "UMP Data" command */
int cmd_fill_ump_data(unsigned char *buf, const void *ump,
		      unsigned char ump_len, unsigned short seqno)
{
	buf[0] = UMP_NET_UMP_DATA;
	buf[1] = ump_len;
	buf[2] = seqno >> 8;
	buf[3] = seqno & 0xff;
	memcpy(buf + 4, ump, ump_len * 4);
	return ump_len + 1;
}
