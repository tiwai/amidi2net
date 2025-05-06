/*
 * Common helpers for I/O ops with ALSA sequencer API
 */

#include "io-seq-common.h"

static int seq_common_setup_poll(struct am2n_ctx *ctx, struct pollfd *pfds)
{
	struct am2n_seq_common *rs = ctx->io.data;

	*pfds = rs->pfd;
	return 1;
}

static int seq_common_poll_revents(struct am2n_ctx *ctx, struct pollfd *pfds)
{
	return pfds->revents & POLLIN;
}

static int seq_common_read_ump_packet(struct am2n_ctx *ctx, void *buf)
{
	struct am2n_seq_common *rs = ctx->io.data;
	snd_seq_ump_event_t *ev;
	int len;

	while ((snd_seq_ump_event_input(rs->seq, &ev)) >= 0) {
		if (!snd_seq_ev_is_ump(ev)) {
			/* check the exit of the connected sequencer port;
			 * this means the exit of the client, too
			 */
			if (ctx->io.type == UMP_IO_BACKEND_SEQ_BRIDGE &&
			    ev->type == SND_SEQ_EVENT_PORT_UNSUBSCRIBED &&
			    ev->data.connect.sender.client == ctx->io.seq_client) {
				debug("io-seq-bridge: bridged client is gone");
				return -1;
			}
			continue;
		}

		/* if it's a UMP stream message, process inside */
		if (ctx->io.handle_stream_msg) {
			assert(ctx->submit_ump);
			if (am2n_seq_process_ump_stream_msg(ctx, ev->ump))
				continue;
		}

		len = snd_ump_packet_length(snd_ump_msg_hdr_type(*ev->ump));
		memcpy(buf, ev->ump, len * 4);
		return len;
	}
	return 0;
}

static int seq_common_write_ump_packet(struct am2n_ctx *ctx, const void *buf,
				       int len)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const uint32_t *ump = buf;
	snd_seq_ump_event_t ev;
	int plen, err;

	if (len <= 0)
		return 0;
	snd_seq_ump_ev_clear(&ev);
	snd_seq_ev_set_subs(&ev);
	snd_seq_ev_set_direct(&ev);
	snd_seq_ev_set_ump(&ev);
	while (len > 0) {
		plen = snd_ump_packet_length(snd_ump_msg_hdr_type(*ump));
		if (len < plen)
			break;
		debug2("write ump: %08x, len=%d", *ump, plen);
		snd_seq_ev_set_ump_data(&ev, (void *)ump, plen * 4);
		err = snd_seq_ump_event_output(rs->seq, &ev);
		if (err < 0)
			break;
		ump += plen;
		len -= plen;
	}
	return snd_seq_drain_output(rs->seq);
}

static void seq_common_free(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs = ctx->io.data;

	am2n_seq_common_free(rs);
}

static struct ump_io_ops seq_common_ops = {
	.setup_poll = seq_common_setup_poll,
	.poll_revents = seq_common_poll_revents,
	.read_ump_packet = seq_common_read_ump_packet,
	.write_ump_packet = seq_common_write_ump_packet,
	.free = seq_common_free,
};

void am2n_seq_common_setup_io(struct am2n_ctx *ctx,
			      struct am2n_seq_common *rs)
{
	ctx->io.ops = &seq_common_ops;
	ctx->io.data = rs;
	log("Created sequencer client %d", snd_seq_client_id(rs->seq));
}

int am2n_seq_common_setup_endpoint(struct am2n_ctx *ctx,
				   struct am2n_seq_common *rs,
				   int midi_version, int num_groups,
				   int num_blocks, const char *ep_name,
				   const char *prod_id)
{
	snd_ump_endpoint_info_t *ep;
	int err;

	if (snd_ump_endpoint_info_malloc(&ep))
		return -ENOMEM;
	rs->ep_info = ep;
	snd_ump_endpoint_info_set_name(ep, ep_name);
	snd_ump_endpoint_info_set_product_id(ep, prod_id);
	if (midi_version == 1) {
		snd_ump_endpoint_info_set_protocol_caps(ep, SND_UMP_EP_INFO_PROTO_MIDI1);
		snd_ump_endpoint_info_set_protocol(ep, SND_UMP_EP_INFO_PROTO_MIDI1);
	} else {
		snd_ump_endpoint_info_set_protocol_caps(ep, SND_UMP_EP_INFO_PROTO_MIDI2);
		snd_ump_endpoint_info_set_protocol(ep, SND_UMP_EP_INFO_PROTO_MIDI2);
	}
	snd_ump_endpoint_info_set_num_blocks(ep, num_blocks);

	if (!*ctx->ep_name)
		strlcpy(ctx->ep_name, ep_name, sizeof(ctx->ep_name));
	if (!*ctx->prod_id)
		strlcpy(ctx->prod_id, prod_id, sizeof(ctx->prod_id));
	err = snd_seq_create_ump_endpoint(rs->seq, ep, num_groups);
	if (err < 0)
		return err;

#if SND_LIB_SUBMINOR < 14
	/* fix up the missing UMP port info bit */
	{
		unsigned int caps;

		snd_seq_port_info_alloca(&pinfo);
		snd_seq_get_port_info(rs->seq, 0, pinfo);
		caps = snd_seq_port_info_get_capability(pinfo);
		snd_seq_port_info_set_capability(pinfo, caps |
						 SND_SEQ_PORT_CAP_UMP_ENDPOINT);
		snd_seq_set_port_info(rs->seq, 0, pinfo);
	}
#endif /* < 1.2.14 */
	return 0;
}

int am2n_seq_common_setup_blocks(struct am2n_ctx *ctx,
				 struct am2n_seq_common *rs,
				 int num_groups, int num_blocks)
{
	snd_ump_block_info_t *blk;
	char name[32];
	int i, err;

	rs->num_blocks = num_blocks;
	for (i = 0; i < num_blocks; i++) {
		if (snd_ump_block_info_malloc(&blk))
			return -ENOMEM;
		rs->blk_infos[i] = blk;
		if (num_blocks > 1) {
			sprintf(name, "Bridge I/O %d", i);
			snd_ump_block_info_set_name(blk, name);
		} else {
			snd_ump_block_info_set_name(blk, "Bridge I/O");
		}
		snd_ump_block_info_set_direction(blk, SND_UMP_DIR_BIDIRECTION);
		snd_ump_block_info_set_first_group(blk, i);
		if (num_blocks > 1)
			snd_ump_block_info_set_num_groups(blk, 1);
		else
			snd_ump_block_info_set_num_groups(blk, num_groups);
		snd_ump_block_info_set_ui_hint(blk, SND_UMP_BLOCK_UI_HINT_BOTH);
		err = snd_seq_create_ump_block(rs->seq, i, blk);
		if (err < 0)
			return err;
	}
	return 0;
}

void am2n_seq_common_free(struct am2n_seq_common *rs)
{
	int i;

	snd_seq_close(rs->seq);
	for (i = 0; i < SND_UMP_MAX_BLOCKS; i++)
		snd_ump_block_info_free(rs->blk_infos[i]);
	snd_ump_endpoint_info_free(rs->ep_info);
	free(rs);
}
