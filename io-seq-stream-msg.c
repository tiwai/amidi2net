/*
 * Handle UMP stream messages with ALSA sequencer API
 */

#include "io-seq-common.h"

/* UMP Stream Message: Endpoint Info Notification (128bit) */
struct snd_ump_stream_msg_ep_info {
#ifdef __BIG_ENDIAN_BITFIELD
	/* 0 */
	uint32_t type:4;
	uint32_t format:2;
	uint32_t status:10;
	uint32_t ump_version_major:8;
	uint32_t ump_version_minor:8;
	/* 1 */
	uint32_t static_function_block:1;
	uint32_t num_function_blocks:7;
	uint32_t reserved:8;
	uint32_t protocol:8;
	uint32_t reserved2:6;
	uint32_t jrts:2;
	/* 2-3 */
	uint32_t reserved3[2];
#else
	/* 0 */
	uint32_t ump_version_minor:8;
	uint32_t ump_version_major:8;
	uint32_t status:10;
	uint32_t format:2;
	uint32_t type:4;
	/* 1 */
	uint32_t jrts:2;
	uint32_t reserved2:6;
	uint32_t protocol:8;
	uint32_t reserved:8;
	uint32_t num_function_blocks:7;
	uint32_t static_function_block:1;
	/* 2-3 */
	uint32_t reserved3[2];
#endif
} __attribute((packed));

/* UMP Stream Message: Device Info Notification (128bit) */
struct snd_ump_stream_msg_device_info {
#ifdef __BIG_ENDIAN_BITFIELD
	/* 0 */
	uint32_t type:4;
	uint32_t format:2;
	uint32_t status:10;
	uint32_t reserved:16;
	/* 1 */
	uint32_t manufacture_id;
	/* 2 */
	uint8_t family_lsb;
	uint8_t family_msb;
	uint8_t model_lsb;
	uint8_t model_msb;
	/* 3 */
	uint32_t sw_revision;
#else
	/* 0 */
	uint32_t reserved:16;
	uint32_t status:10;
	uint32_t format:2;
	uint32_t type:4;
	/* 1 */
	uint32_t manufacture_id;
	/* 2 */
	uint8_t model_msb;
	uint8_t model_lsb;
	uint8_t family_msb;
	uint8_t family_lsb;
	/* 3 */
	uint32_t sw_revision;
#endif
} __attribute((packed));

/* UMP Stream Message: Stream Config Request / Notification (128bit) */
struct snd_ump_stream_msg_stream_cfg {
#ifdef __BIG_ENDIAN_BITFIELD
	/* 0 */
	uint32_t type:4;
	uint32_t format:2;
	uint32_t status:10;
	uint32_t protocol:8;
	uint32_t reserved:6;
	uint32_t jrts:2;
	/* 1-3 */
	uint32_t reserved2[3];
#else
	/* 0 */
	uint32_t jrts:2;
	uint32_t reserved:6;
	uint32_t protocol:8;
	uint32_t status:10;
	uint32_t format:2;
	uint32_t type:4;
	/* 1-3 */
	uint32_t reserved2[3];
#endif
} __attribute((packed));

/* UMP Stream Message: Function Block Discovery (128bit) */
struct snd_ump_stream_msg_fb_discovery {
#ifdef __BIG_ENDIAN_BITFIELD
	/* 0 */
	uint32_t type:4;
	uint32_t format:2;
	uint32_t status:10;
	uint32_t function_block_id:8;
	uint32_t filter:8;
	/* 1-3 */
	uint32_t reserved[3];
#else
	/* 0 */
	uint32_t filter:8;
	uint32_t function_block_id:8;
	uint32_t status:10;
	uint32_t format:2;
	uint32_t type:4;
	/* 1-3 */
	uint32_t reserved[3];
#endif
} __attribute((packed));

/* UMP Stream Message: Function Block Info Notification (128bit) */
struct snd_ump_stream_msg_fb_info {
#ifdef __BIG_ENDIAN_BITFIELD
	/* 0 */
	uint32_t type:4;
	uint32_t format:2;
	uint32_t status:10;
	uint32_t active:1;
	uint32_t function_block_id:7;
	uint32_t reserved:2;
	uint32_t ui_hint:2;
	uint32_t midi_10:2;
	uint32_t direction:2;
	/* 1 */
	uint32_t first_group:8;
	uint32_t num_groups:8;
	uint32_t midi_ci_version:8;
	uint32_t sysex8_streams:8;
	/* 2-3 */
	uint32_t reserved2[2];
#else
	/* 0 */
	uint32_t direction:2;
	uint32_t midi_10:2;
	uint32_t ui_hint:2;
	uint32_t reserved:2;
	uint32_t function_block_id:7;
	uint32_t active:1;
	uint32_t status:10;
	uint32_t format:2;
	uint32_t type:4;
	/* 1 */
	uint32_t sysex8_streams:8;
	uint32_t midi_ci_version:8;
	uint32_t num_groups:8;
	uint32_t first_group:8;
	/* 2-3 */
	uint32_t reserved2[2];
#endif
} __attribute((packed));

/* UMP Stream Message: Function Block Name Notification (128bit) */
struct snd_ump_stream_msg_fb_name {
#ifdef __BIG_ENDIAN_BITFIELD
	/* 0 */
	uint16_t type:4;
	uint16_t format:2;
	uint16_t status:10;
	uint8_t function_block_id;
	uint8_t name0;
	/* 1-3 */
	uint8_t name[12];
#else
	/* 0 */
	uint8_t name0;
	uint8_t function_block_id;
	uint16_t status:10;
	uint16_t format:2;
	uint16_t type:4;
	/* 1-3 */
	uint8_t name[12]; // FIXME: byte order
#endif
} __attribute((packed));

static inline void reply_ep(struct am2n_ctx *ctx, const void *buf, int len)
{
	ctx->submit_ump(ctx, buf, len / 4);
}

/* reply a UMP stream EP info */
static void reply_ump_stream_ep_info(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_endpoint_info_t *ep = rs->ep_info;
	struct snd_ump_stream_msg_ep_info rep = {
		.type = SND_UMP_MSG_TYPE_STREAM,
		.status = SND_UMP_STREAM_MSG_STATUS_EP_INFO,
		.ump_version_major = 0x01,
		.ump_version_minor = 0x01,
	};

	rep.num_function_blocks = snd_ump_endpoint_info_get_num_blocks(ep);
	rep.static_function_block = !!(snd_ump_endpoint_info_get_flags(ep) & SND_UMP_EP_INFO_STATIC_BLOCKS);
	rep.protocol = snd_ump_endpoint_info_get_protocol(ep) >> 8;
	reply_ep(ctx, &rep, sizeof(rep));
}

/* reply a UMP EP device info */
static void reply_ump_stream_ep_device(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_endpoint_info_t *ep = rs->ep_info;
	struct snd_ump_stream_msg_device_info rep = {
		.type = SND_UMP_MSG_TYPE_STREAM,
		.status = SND_UMP_STREAM_MSG_STATUS_DEVICE_INFO,
	};

	rep.manufacture_id = snd_ump_endpoint_info_get_manufacturer_id(ep);
	rep.family_lsb = snd_ump_endpoint_info_get_family_id(ep) & 0xff;
	rep.family_msb = (snd_ump_endpoint_info_get_family_id(ep) >> 8) & 0xff;
	rep.model_lsb = snd_ump_endpoint_info_get_model_id(ep) & 0xff;
	rep.model_msb = (snd_ump_endpoint_info_get_model_id(ep) >> 8) & 0xff;
	memcpy(&rep.sw_revision, snd_ump_endpoint_info_get_sw_revision(ep), 4);
	reply_ep(ctx, &rep, sizeof(rep));
}

#define UMP_STREAM_EP_STR_OFF	2	/* offset of name string for EP info */
#define UMP_STREAM_FB_STR_OFF	3	/* offset of name string for FB info */

/* Helper to reply a string */
static void reply_ump_stream_string(struct am2n_ctx *ctx, const uint8_t *name,
				    unsigned int type, unsigned int extra,
				    unsigned int start_ofs)
{
	unsigned int pos;
	snd_ump_msg_stream_t buf;
	int length;

	if (!*name)
		return;

	length = 0;
	pos = start_ofs;
	for (;;) {
		if (pos == start_ofs) {
			memset(&buf, 0, sizeof(buf));
			buf.hdr.type = type;
			buf.raw[0] |= extra;
		}
		buf.raw[pos / 4] |= *name++ << ((3 - (pos % 4)) * 8);
		if (!*name) {
			if (length)
				buf.gen.format = SND_UMP_STREAM_MSG_FORMAT_END;
			else
				buf.gen.format = SND_UMP_STREAM_MSG_FORMAT_SINGLE;
			reply_ep(ctx, &buf, sizeof(buf));
			break;
		}
		if (++pos == sizeof(buf)) {
			if (!length)
				buf.gen.format = SND_UMP_STREAM_MSG_FORMAT_START;
			else
				buf.gen.format = SND_UMP_STREAM_MSG_FORMAT_CONTINUE;
			reply_ep(ctx, &buf, sizeof(buf));
			length++;
			pos = start_ofs;
		}
	}
}

/* Reply a UMP EP name string */
static void reply_ump_stream_ep_name(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_endpoint_info_t *ep = rs->ep_info;

	reply_ump_stream_string(ctx, snd_ump_endpoint_info_get_name(ep),
				SND_UMP_STREAM_MSG_STATUS_EP_NAME, 0,
				UMP_STREAM_EP_STR_OFF);
}

/* Reply a UMP EP product ID string */
static void reply_ump_stream_ep_pid(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_endpoint_info_t *ep = rs->ep_info;

	reply_ump_stream_string(ctx, snd_ump_endpoint_info_get_product_id(ep),
				SND_UMP_STREAM_MSG_STATUS_PRODUCT_ID, 0,
				UMP_STREAM_EP_STR_OFF);
}

/* Reply a UMP EP stream config */
static void reply_ump_stream_ep_config(struct am2n_ctx *ctx)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_endpoint_info_t *ep = rs->ep_info;
	struct snd_ump_stream_msg_stream_cfg rep = {
		.type = SND_UMP_MSG_TYPE_STREAM,
		.status = SND_UMP_STREAM_MSG_STATUS_STREAM_CFG,
	};

	rep.protocol = snd_ump_endpoint_info_get_protocol(ep) >> 8;
	reply_ep(ctx, &rep, sizeof(rep));
}

/* Reply a UMP FB info */
static void reply_ump_stream_fb_info(struct am2n_ctx *ctx, int blk)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_block_info_t *b = rs->blk_infos[blk];
	struct snd_ump_stream_msg_fb_info rep = {
		.type = SND_UMP_MSG_TYPE_STREAM,
		.status = SND_UMP_STREAM_MSG_STATUS_FB_INFO,
	};
	unsigned int flags;

	rep.active = !!snd_ump_block_info_get_active(b);
	rep.function_block_id = blk;
	rep.ui_hint = snd_ump_block_info_get_ui_hint(b);
	flags = snd_ump_block_info_get_flags(b);
	if (flags < 2)
		rep.midi_10 = flags;
	else
		rep.midi_10 = 2;
	rep.direction = snd_ump_block_info_get_direction(b);
	rep.first_group = snd_ump_block_info_get_first_group(b);
	rep.num_groups = snd_ump_block_info_get_num_groups(b);
	rep.midi_ci_version = snd_ump_block_info_get_midi_ci_version(b);
	rep.sysex8_streams = snd_ump_block_info_get_sysex8_streams(b);
	reply_ep(ctx, &rep, sizeof(rep));
}

/* Reply a FB name string */
static void reply_ump_stream_fb_name(struct am2n_ctx *ctx, unsigned int blk)
{
	struct am2n_seq_common *rs = ctx->io.data;
	const snd_ump_block_info_t *b = rs->blk_infos[blk];

	reply_ump_stream_string(ctx, snd_ump_block_info_get_name(b),
				SND_UMP_STREAM_MSG_STATUS_FB_NAME, blk << 8,
				UMP_STREAM_FB_STR_OFF);
}

bool am2n_seq_process_ump_stream_msg(struct am2n_ctx *ctx, const uint32_t *data)
{
	const snd_ump_msg_stream_t *s = (const snd_ump_msg_stream_t *)data;
	struct am2n_seq_common *rs = ctx->io.data;
	unsigned int blk;

	if (s->hdr.type != SND_UMP_MSG_TYPE_STREAM)
		return false;

	switch (s->gen.status) {
	case SND_UMP_STREAM_MSG_STATUS_EP_DISCOVERY:
		if (s->gen.format)
			return true; // invalid
		if (data[1] & SND_UMP_STREAM_MSG_REQUEST_EP_INFO)
			reply_ump_stream_ep_info(ctx);
		if (data[1] & SND_UMP_STREAM_MSG_REQUEST_DEVICE_INFO)
			reply_ump_stream_ep_device(ctx);
		if (data[1] & SND_UMP_STREAM_MSG_REQUEST_EP_NAME)
			reply_ump_stream_ep_name(ctx);
		if (data[1] & SND_UMP_STREAM_MSG_REQUEST_PRODUCT_ID)
			reply_ump_stream_ep_pid(ctx);
		if (data[1] & SND_UMP_STREAM_MSG_REQUEST_STREAM_CFG)
			reply_ump_stream_ep_config(ctx);
		return true;
	case SND_UMP_STREAM_MSG_STATUS_STREAM_CFG_REQUEST:
		return true;
	case SND_UMP_STREAM_MSG_STATUS_FB_DISCOVERY:
		if (s->gen.format)
			return true; // invalid
		blk = (*data >> 8) & 0xff;
		if (blk == 0xff) {
			/* inquiry for all blocks */
			for (blk = 0; blk < rs->num_blocks; blk++) {
				if (*data & SND_UMP_STREAM_MSG_REQUEST_FB_INFO)
					reply_ump_stream_fb_info(ctx, blk);
				if (*data & SND_UMP_STREAM_MSG_REQUEST_FB_NAME)
					reply_ump_stream_fb_name(ctx, blk);
			}
		} else if (blk < rs->num_blocks) {
			/* only the specified block */
			if (*data & SND_UMP_STREAM_MSG_REQUEST_FB_INFO)
				reply_ump_stream_fb_info(ctx, blk);
			if (*data & SND_UMP_STREAM_MSG_REQUEST_FB_NAME)
				reply_ump_stream_fb_name(ctx, blk);
		}
		return true;
	}

	return false;
}
