/*
 * Helpers for UDP packet handling
 */

#ifndef __PACKET_H_INC
#define __PACKET_H_INC

#define UMP_NET_SIGNATURE	{ 'M', 'I', 'D', 'I' }

/* add MIDI packet signature on the buffer */
static inline void add_signature(unsigned char *buf)
{
	static unsigned char signature[4] = UMP_NET_SIGNATURE;

	memcpy(buf, signature, 4);
}

/* check whether the buffer has the MIDI packet signature */
static inline bool check_signature(const unsigned char *buf)
{
	static unsigned char signature[4] = UMP_NET_SIGNATURE;

	return memcmp(buf, signature, 4) == 0;
}

/* compare two sequencer numbers */
static inline int seqno_diff(unsigned short a, unsigned short b)
{
	return (signed short)(a - b);
}

/*
 * UDP packet:
 * | signature - 4 bytes |
 * | command-code | payload-words | data (16bit) |
 */

/* UDP packet command code */
enum {
	UMP_NET_INVITATION = 0x01,
	UMP_NET_INVITATION_WITH_AUTH = 0x02,
	UMP_NET_INVITATION_WITH_USER_AUTH = 0x03,
	UMP_NET_INVITATION_REPLY_ACCEPT = 0x10,
	UMP_NET_INVITATION_REPLY_PENDING = 0x11,
	UMP_NET_INVITATION_REPLY_AUTH_REQ = 0x12,
	UMP_NET_INVITATION_REPLY_USER_AUTH_REQ = 0x13,
	UMP_NET_PING = 0x20,
	UMP_NET_PING_REPLY = 0x21,
	UMP_NET_RETRANSMIT_REQ = 0x80,
	UMP_NET_RETRANSMIT_ERR = 0x81,
	UMP_NET_SESSION_RESET = 0x82,
	UMP_NET_SESSION_RESET_REPLY = 0x83,
	UMP_NET_NAK = 0x7f,
	UMP_NET_BYE = 0xf0,
	UMP_NET_BYE_REPLY = 0xf1,
	UMP_NET_UMP_DATA = 0xff,
};

/* Invitation capabilities */
#define UMP_NET_CAPS_INVITATION_AUTH		(1U << 0)
#define UMP_NET_CAPS_INVITATION_USER_AUTH	(1U << 1)

/* Authentication state */
enum {
	AUTH_STATE_FIRST = 0,
	AUTH_STATE_RETRY = 1,
	AUTH_STATE_USER_NOT_FOUND = 2,
};

/* NAK reasons */
enum {
	UMP_NET_NAK_REASON_OTHER = 0x00,
	UMP_NET_NAK_REASON_CMD_NOT_SUPPORTED = 0x01,
	UMP_NET_NAK_REASON_CMD_NOT_EXPECTED = 0x02,
	UMP_NET_NAK_REASON_CMD_MALFORMED = 0x03,
	UMP_NET_NAK_REASON_BAD_PING_REPLY = 0x20,
};

/* Bye reasons */
enum {
	UMP_NET_BYE_REASON_UNKNOWN = 0x00,
	UMP_NET_BYE_REASON_SESSION_TERMINATED = 0x01,
	UMP_NET_BYE_REASON_POWER_DOWN = 0x02,
	UMP_NET_BYE_REASON_PACKET_MISSING = 0x03,
	UMP_NET_BYE_REASON_TIMEOUT = 0x04,
	UMP_NET_BYE_REASON_SESSION_NOT_ESTABLISHED = 0x05,
	UMP_NET_BYE_REASON_NO_PENDING_SESSION = 0x06,
	UMP_NET_BYE_REASON_PROTOCOL_ERROR = 0x07,
	UMP_NET_BYE_REASON_INV_FAILED_TOO_MANY_SESSIONS = 0x40,
	UMP_NET_BYE_REASON_INV_AUTH_REJECTED_NO_AUTH = 0x41,
	UMP_NET_BYE_REASON_INV_REJECTED_NO_SESSION_ACCEPT = 0x42,
	UMP_NET_BYE_REASON_INV_REJECTED_ANUH_FAILED = 0x43,
	UMP_NET_BYE_REASON_INV_REJECTED_USER_NOT_FOUND = 0x44,
	UMP_NET_BYE_REASON_NO_MATCHING_AUTH = 0x45,
	UMP_NET_BYE_REASON_INV_CANCELED = 0x80,
};

/* Retransmit reasons */
enum {
	UMP_NET_RETRANSMIT_ERR_REASON_UKNOWN = 0,
	UMP_NET_RETRANSMIT_ERR_REASON_NO_DATA = 1,
};

/* max UDP packet size in bytes */
#define UMP_NET_MAX_BUF_SIZE	1400

/*
 * Helpers to fill UDP commands
 */
int cmd_fill_invitation(unsigned char *buf,
			unsigned char ump_caps,
			const char *ump_ep_name,
			const char *ump_prod_id);
int cmd_fill_invitation_reply_accept(unsigned char *buf,
				     const char *ump_ep_name,
				     const char *ump_prod_id);
int cmd_fill_invitation_reply_pending(unsigned char *buf,
				      const char *ump_ep_name,
				      const char *ump_prod_id);
int cmd_fill_invitation_reply_auth_req(unsigned char *buf,
				       unsigned char state,
				       const unsigned char *crypto,
				       const char *ep_name,
				       const char *prod_id);
int cmd_fill_invitation_reply_user_auth_req(unsigned char *buf,
					    unsigned char state,
					    const unsigned char *crypto,
					    const char *ep_name,
					    const char *prod_id);
int cmd_fill_invitation_with_auth(unsigned char *buf,
				  const unsigned char *digest);
int cmd_fill_invitation_with_user_auth(unsigned char *buf,
				       const unsigned char *digest,
				       const char *user_name);
int cmd_fill_session_reset(unsigned char *buf);
int cmd_fill_session_reset_reply(unsigned char *buf);
int cmd_fill_ping(unsigned char *buf, const unsigned char *ping_id);
int cmd_fill_ping_reply(unsigned char *buf, const unsigned char *ping_id);
int cmd_fill_nak(unsigned char *buf, unsigned char reason,
		 const unsigned char *nak_cmd_header,
		 const char *text_msg);
int cmd_fill_bye(unsigned char *buf, unsigned char reason,
		 const char *text_msg);
int cmd_fill_bye_reply(unsigned char *buf);
int cmd_fill_retransmit_req(unsigned char *buf, unsigned short seqno);
int cmd_fill_retransmit_err(unsigned char *buf, unsigned short seqno,
			    unsigned char reason);
int cmd_fill_ump_data(unsigned char *buf, const void *ump,
		      unsigned char ump_len, unsigned short seqno);

#endif /* __PACKET_H_INC */
