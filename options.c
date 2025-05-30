/*
 * amidi2net configuration options
 */

#include "amidi2net.h"
#include "options.h"
#include "packet.h"

/* set up the config with the default values */
void am2n_config_init(struct am2n_config *config, bool server)
{
	config->fec_count = 3;			/* default FEC enablement */
	config->input_buffer_size = 128;
	config->output_buffer_size = 64;
	config->tolerance = 8;
	config->liveness_timeout = 5000;	/* default server ping timeout */
	/* a bit longer than server for avoiding unnecessarily ping */
	if (!server)
		config->liveness_timeout += 500;
	config->missing_pkt_timeout = 30;	/* timeout for missing packet */
	config->retransmit_timeout = 100;	/* timeout for retransmit request */
	config->ping_timeout = 100;		/* timeout for ping retry */
	config->zerolength_ump_timeout = 100;	/* timeout for zero-length UMP */
	config->invitation_timeout = 1000;	/* timeout for invitation request */
	config->invitation_pending_timeout = 10000;	/* longer timeout for invitation pending */
	config->max_missing_retry = 5;		/* max retries for missing packet recovery */
	config->max_ping_retry = 3;		/* max retries for ping connection checks */
	config->max_invitation_retry = 3;	/* max retries of invitations */
	config->max_sessions = 8;		/* max number of sessions */

	config->io_type = UMP_IO_BACKEND_SEQ_HUB;
	config->midi_version = 1;
	config->num_blocks = 1;
	config->num_groups = 16;
}

/* print out the current config setup */
void am2n_config_debug_print(const struct am2n_config *config, bool server)
{
	debug("configuration:");
	debug("* FEC: %d", config->fec_count);
	if (server) {
		debug("* liveness ping timeout: %d", config->liveness_timeout);
		debug("* ping retry timeout: %d", config->ping_timeout);
		debug("* max ping retry: %d", config->max_ping_retry);
	}
	debug("* missing packet tolerance: %d", config->tolerance);
	debug("* missing packet timeout: %d", config->missing_pkt_timeout);
	debug("* retransmit timeout: %d", config->retransmit_timeout);
	debug("* zero-length UMP timeout: %d", config->zerolength_ump_timeout);
	debug("* max retries for packet recovery: %d", config->max_missing_retry);
	if (server) {
		debug("* max number of sessions: %d", config->max_sessions);
	} else {
		debug("* invitation timeout: %d", config->invitation_timeout);
		debug("* invitation pending timeout: %d", config->invitation_pending_timeout);
		debug("* max invitation retry: %d", config->max_invitation_retry);
	}

	if (config->fail_test)
		debug("* packet fail test: mode = %d, rate = 1/%d",
		      config->fail_test_mode, config->fail_test);
}

/* called for processing getopt() about config */
int am2n_config_parse_option(struct am2n_config *config,
			     bool server, int c, const char *arg)
{
	switch (c) {
	case OPT_SEQ_BRIDGE_MODE:
		config->io_type = UMP_IO_BACKEND_SEQ_BRIDGE;
		config->seq_devname = arg;
		return 1;
	case OPT_RAWMIDI_MODE:
		config->io_type = UMP_IO_BACKEND_RAWMIDI;
		config->rawmidi_device = arg;
		return 1;
	case OPT_SEQ_HUB_MODE:
		config->io_type = UMP_IO_BACKEND_SEQ_HUB;
		config->midi_version = atoi(arg);
		if (config->midi_version != 1 &&
		    config->midi_version != 2) {
			error("Invalid midi version specified");
			return -1;
		}
		return 1;
	case OPT_EP_NAME:
		config->ep_name = arg;
		return 1;
	case OPT_PROD_ID:
		config->prod_id = arg;
		return 1;
	case OPT_GROUPS:
		config->num_groups = atoi(arg);
		if (config->num_groups < 1 || config->num_groups > 16) {
			error("Invalid num_groups specified");
			return -1;
		}
		return 1;
	case OPT_BLOCKS:
		config->num_blocks = atoi(arg);
		if (config->num_blocks < 1 || config->num_blocks > 32) {
			error("Invalid num_groups specified");
			return -1;
		}
		return 1;
	case OPT_FEC_COUNT:
		config->fec_count = atoi(arg);
		if (config->fec_count > 32) {
			error("Too many FEC count %d", config->fec_count);
			return -1;
		}
		return 1;
	case OPT_IPV6:
		config->ipv6 = true;
		return 1;
	case OPT_MISSING_PKT_TIMEOUT:
		config->missing_pkt_timeout = atoi(arg);
		return 1;
	case OPT_RETRANSMIT_TIMEOUT:
		config->retransmit_timeout = atoi(arg);
		return 1;
	case OPT_MAX_MISSING_RETRY:
		config->max_missing_retry = atoi(arg);
		return 1;
	case OPT_ZEROLENGTH_UMP_TIMEOUT:
		config->zerolength_ump_timeout = atoi(arg);
		return 1;
	case OPT_FAIL_TEST:
		config->fail_test = atoi(arg);
		return 1;
	case OPT_FAIL_TEST_MODE:
		config->fail_test_mode = atoi(arg);
		if (config->fail_test_mode > FAIL_TEST_DROP_FEC_RECEIVER) {
			error("Invalid fail test mode: %d",
			      config->fail_test_mode);
			return -1;
		}
		return 1;
	case OPT_PASSTHROUGH:
		config->passthrough = true;
		return 1;
	case OPT_INPUT_BUFFER_SIZE:
		config->input_buffer_size = atoi(arg);
		if (config->input_buffer_size < 2) {
			error("Invalid input buffer size %d",
			      config->input_buffer_size);
			return -1;
		}
		return 1;
	case OPT_OUTPUT_BUFFER_SIZE:
		config->output_buffer_size = atoi(arg);
		if (config->output_buffer_size < config->fec_count + 1) {
			error("Invalid output buffer size %d",
			      config->output_buffer_size);
			return -1;
		}
		return 1;
	case OPT_TOLERANCE:
		config->tolerance = atoi(arg);
		return 1;
#ifdef SUPPORT_AUTH
	case OPT_AUTH_USER:
		config->auth_username = arg;
		return 1;
	case OPT_AUTH_SECRET:
		config->auth_secret = arg;
		return 1;
#endif
	case OPT_VERSION:
		printf("v%s\n", VERSION);
		exit(0);
	case OPT_QUIET:
		verbosity = 0;
		return 1;
	case OPT_DEBUG:
		verbosity++;
		return 1;
	}

	if (server) {
		switch (c) {
		case OPT_MAX_SESSIONS:
			config->max_sessions = atoi(arg);
			if (config->max_sessions < 1 ||
			    config->max_sessions > 128) {
				error("Too many max sessions %d",
				      config->max_sessions);
				return -1;
			}
			return 1;
		case OPT_LIVENESS_TIMEOUT:
			config->liveness_timeout = atoi(arg);
			return 1;
		case OPT_PING_TIMEOUT:
			config->ping_timeout = atoi(arg);
			return 1;
		case OPT_MAX_PING_RETRY:
			config->max_ping_retry = atoi(arg);
			return 1;
#ifdef SUPPORT_AUTH
		case OPT_SUPPORT_AUTH:
			config->auth_support |= UMP_NET_CAPS_INVITATION_AUTH;
			return 1;
		case OPT_SUPPORT_USER_AUTH:
			config->auth_support |= UMP_NET_CAPS_INVITATION_USER_AUTH;
			return 1;
		case OPT_SUPPORT_AUTH_FORCED:
			config->auth_forced = true;
			return 1;
#endif
		}
	} else {
		switch (c) {
		case OPT_INVITATION_TIMEOUT:
			config->invitation_timeout = atoi(arg);
			return 1;
		case OPT_MAX_INVITATION_RETRY:
			config->max_invitation_retry = atoi(arg);
			return 1;
		}
	}

	return 0;
}
