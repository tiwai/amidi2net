/*
 * I/O ops with ALSA sequencer API bridge
 */

#include "io-seq-common.h"

static int adjust_attributes(struct am2n_seq_common *rs,
			     int midi_version, int num_groups)
{
	snd_seq_port_info_t *pinfo;
	unsigned int caps;
	int i, err;

	/* set no-conversion flag for UMP-to-UMP connection */
	if (midi_version != SND_SEQ_CLIENT_LEGACY_MIDI) {
		snd_seq_client_info_t *info;

		snd_seq_client_info_alloca(&info);
		err = snd_seq_get_client_info(rs->seq, info);
		if (err < 0) {
			error("cannot get sequencer client info");
			return err;
		}

		snd_seq_client_info_set_ump_conversion(info, false);
		err = snd_seq_set_client_info(rs->seq, info);
		if (err < 0) {
			error("cannot set sequencer client info");
			return err;
		}
	}

	/* drop subscriber port caps; we don't expose the client to others */
	snd_seq_port_info_alloca(&pinfo);
	for (i = 0; i <= num_groups; i++) {
		err = snd_seq_get_port_info(rs->seq, i, pinfo);
		if (err < 0) {
			error("cannot get sequencer port info");
			return err;
		}
		caps = snd_seq_port_info_get_capability(pinfo);
		caps &= ~(SND_SEQ_PORT_CAP_SUBS_READ | SND_SEQ_PORT_CAP_SUBS_WRITE);
		snd_seq_port_info_set_capability(pinfo, caps);
		err = snd_seq_set_port_info(rs->seq, i, pinfo);
		if (err < 0) {
			error("cannot set sequencer port info");
			return err;
		}
	}

	return 0;
}

#define DEFAULT_PROD_ID		"amidi2net-io-seq-bridge"

int am2n_io_seq_bridge_init(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs;
	snd_seq_addr_t addr;
	snd_seq_client_info_t *info;
	snd_ump_endpoint_info_t *ep;
	int midi_version, midi_version_target;
	int num_groups;
	char my_ep_name[128];
	const char *ep_name;
	const char *prod_id;
	int err;

	if (!ctx->config->seq_devname) {
		error("No sequencer client/port specified");
		return -EINVAL;
	}

	rs = am2n_seq_common_alloc();
	if (!rs)
		return -ENOMEM;

	err = snd_seq_open(&rs->seq, "default", SND_SEQ_OPEN_DUPLEX, 0);
	if (err < 0) {
		error("Cannot open sequencer");
		return err;
	}

	err = snd_seq_parse_address(rs->seq, &addr, ctx->config->seq_devname);
	if (err < 0) {
		error("Invalid client/port %s", ctx->config->seq_devname);
		goto error;
	}
	ctx->io.seq_client = addr.client;

	snd_seq_poll_descriptors(rs->seq, &rs->pfd, 1, POLLIN);
	snd_seq_nonblock(rs->seq, 1);

	snd_seq_client_info_alloca(&info);
	err = snd_seq_get_any_client_info(rs->seq, addr.client, info);
	if (err < 0) {
		error("Cannot get the target client info for %d", addr.client);
		goto error;
	}

	snd_ump_endpoint_info_alloca(&ep);

	midi_version = snd_seq_client_info_get_midi_version(info);
	if (midi_version != SND_SEQ_CLIENT_LEGACY_MIDI &&
	    snd_seq_get_ump_endpoint_info(rs->seq, addr.client, ep) >= 0) {
		ep_name = snd_ump_endpoint_info_get_name(ep);
		prod_id = snd_ump_endpoint_info_get_product_id(ep);
	} else {
		ep_name = snd_seq_client_info_get_name(info);
		prod_id = DEFAULT_PROD_ID;
		if (!ctx->config->passthrough)
			ctx->io.handle_stream_msg = true;
	}
	snprintf(my_ep_name, sizeof(my_ep_name), "Bridge-%s", ep_name);

	if (midi_version == SND_SEQ_CLIENT_LEGACY_MIDI) {
		midi_version_target = SND_SEQ_CLIENT_UMP_MIDI_1_0;
		num_groups = 1;
	} else {
		midi_version_target = midi_version;
		num_groups = 16;
	}

	err = am2n_seq_common_setup_endpoint(ctx, rs, midi_version_target,
					     num_groups, 1, my_ep_name, prod_id);
	if (err < 0)
		goto error;

	err = am2n_seq_common_setup_blocks(ctx, rs, num_groups, 1);
	if (err < 0)
		goto error;

	err = adjust_attributes(rs, midi_version, num_groups);
	if (err < 0)
		goto error;

	/* restore the original ep name */
	strlcpy(ctx->ep_name, ep_name, sizeof(ctx->ep_name));

	err = snd_seq_connect_from(rs->seq, 0, addr.client, addr.port);
	if (err < 0) {
		error("Failed to connect from %d:%d", addr.client, addr.port);
		goto error;
	}

	err = snd_seq_connect_to(rs->seq, 0, addr.client, addr.port);
	if (err < 0) {
		error("Failed to connect to %d:%d", addr.client, addr.port);
		goto error;
	}

	am2n_seq_common_setup_io(ctx, rs);
	return 0;

 error:
	am2n_seq_common_free(rs);
	return err;
}
