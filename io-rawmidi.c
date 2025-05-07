/*
 * I/O ops with ALSA UMP rawMIDI API
 */

#include "amidi2net.h"
#include "options.h"
#include <alsa/asoundlib.h>
#include <alsa/ump_msg.h>

struct am2n_rawmidi {
	snd_ump_t *ump_in;
	snd_ump_t *ump_out;
	struct pollfd ump_in_pfd;
	struct pollfd ump_out_pfd;
	snd_ump_endpoint_info_t *ep_info;
};

static int rawmidi_setup_poll(struct am2n_ctx *ctx, struct pollfd *pfds)
{
	struct am2n_rawmidi *ru = ctx->io.data;

	*pfds = ru->ump_in_pfd;
	return 1;
}

static int rawmidi_poll_revents(struct am2n_ctx *ctx, struct pollfd *pfds)
{
	return pfds->revents & POLLIN;
}

static int rawmidi_read_ump_packet(struct am2n_ctx *ctx, void *buf)
{
	struct am2n_rawmidi *ru = ctx->io.data;
	unsigned int *ump = buf;
	int len, plen;

	len = snd_ump_read(ru->ump_in, ump, 4);
	if (len != 4)
		return 0;
	plen = snd_ump_packet_length(snd_ump_msg_hdr_type(*ump));
	if (plen > 1) {
		len = (plen - 1) * 4;
		if (snd_ump_read(ru->ump_in, ump + 1, len) != len)
			return 0;
	}
	return plen;
}

static int rawmidi_write_ump_packet(struct am2n_ctx *ctx, const void *buf,
				   int len)
{
	struct am2n_rawmidi *ru = ctx->io.data;

	if (len > 0)
		return snd_ump_write(ru->ump_out, buf, len * 4);
	return 0;
}

static void rawmidi_free(struct am2n_ctx *ctx)
{
	struct am2n_rawmidi *ru = ctx->io.data;

	snd_ump_close(ru->ump_in);
	snd_ump_close(ru->ump_out);
	free(ru->ep_info);
	free(ru);
}

static struct ump_io_ops rawmidi_ops = {
	.setup_poll = rawmidi_setup_poll,
	.poll_revents = rawmidi_poll_revents,
	.read_ump_packet = rawmidi_read_ump_packet,
	.write_ump_packet = rawmidi_write_ump_packet,
	.free = rawmidi_free,
};

int am2n_io_rawmidi_init(struct am2n_ctx *ctx)
{
	struct am2n_rawmidi *ru;
	int err;

	if (!ctx->config->rawmidi_device) {
		error("No rawmidi device specified");
		return -1;
	}

	ru = calloc(1, sizeof(*ru));
	if (!ru)
		return -ENOMEM;

	if (snd_ump_endpoint_info_malloc(&ru->ep_info) < 0) {
		error("Cannot allocate\n");
		free(ru);
		return -ENOMEM;
	}

	err = snd_ump_open(&ru->ump_in, &ru->ump_out,
			   ctx->config->rawmidi_device, 0);
	if (err < 0) {
		error("Cannot open rawmidi %s", ctx->config->rawmidi_device);
		free(ru->ep_info);
		free(ru);
		return err;
	}

	err = snd_ump_endpoint_info(ru->ump_in, ru->ep_info);
	if (err < 0) {
		error("Cannot get EP info\n");
		rawmidi_free(ctx);
		return err;
	}

	strlcpy(ctx->ep_name, snd_ump_endpoint_info_get_name(ru->ep_info),
		sizeof(ctx->ep_name));
	strlcpy(ctx->prod_id, snd_ump_endpoint_info_get_product_id(ru->ep_info),
		sizeof(ctx->prod_id));

	ctx->io.ops = &rawmidi_ops;
	ctx->io.data = ru;
	snd_ump_poll_descriptors(ru->ump_in, &ru->ump_in_pfd, 1);
	snd_ump_poll_descriptors(ru->ump_out, &ru->ump_out_pfd, 1);
	snd_ump_nonblock(ru->ump_in, 1);
	snd_ump_nonblock(ru->ump_out, 1);
	log("Opened UMP rawmidi %s", ctx->config->rawmidi_device);
	return 0;
}
