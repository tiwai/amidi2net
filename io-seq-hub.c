/*
 * I/O ops with ALSA sequencer API hub
 */

#include "io-seq-common.h"

static int check_parameters(struct am2n_ctx *ctx)
{
	if (!ctx->config->ep_name) {
		error("No ep_name specified");
		return -1;
	}
	if (!ctx->config->prod_id) {
		error("No prod_id specified");
		return -1;
	}
	if (ctx->config->num_blocks > 1 &&
	    ctx->config->num_blocks != ctx->config->num_groups) {
		error("Invalid number of blocks/groups");
		return -1;
	}
	return 0;
}

int am2n_io_seq_hub_init(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs;
	int err;

	if (check_parameters(ctx) < 0)
		return -EINVAL;

	rs = am2n_seq_common_alloc();
	if (!rs)
		return -ENOMEM;

	err = snd_seq_open(&rs->seq, "default", SND_SEQ_OPEN_DUPLEX, 0);
	if (err < 0) {
		error("Cannot open sequencer");
		free(rs);
		return err;
	}

	snd_seq_poll_descriptors(rs->seq, &rs->pfd, 1, POLLIN);
	snd_seq_nonblock(rs->seq, 1);

	if (!ctx->config->passthrough)
		ctx->io.handle_stream_msg = true;

	err = am2n_seq_common_setup_endpoint(ctx, rs,
					     ctx->config->midi_version,
					     ctx->config->num_groups,
					     ctx->config->num_blocks,
					     ctx->config->ep_name,
					     ctx->config->prod_id);
	if (err < 0)
		goto error;

	err = am2n_seq_common_setup_blocks(ctx, rs,
					   ctx->config->num_groups,
					   ctx->config->num_blocks);
	if (err < 0)
		goto error;

	am2n_seq_common_setup_io(ctx, rs);
	return 0;

 error:
	am2n_seq_common_free(rs);
	return err;
}
