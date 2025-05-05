/*
 * Common helpers for I/O ops with ALSA sequencer API
 */

#ifndef __IO_SEQ_COMMON_H_INC
#define __IO_SEQ_COMMON_H_INC

#include "amidi2net.h"
#include "options.h"
#include <alsa/asoundlib.h>

struct am2n_seq_common {
	snd_seq_t *seq;
	struct pollfd pfd;
	unsigned int num_blocks;
	snd_ump_endpoint_info_t *ep_info;
	snd_ump_block_info_t *blk_infos[SND_UMP_MAX_BLOCKS];
};

static inline struct am2n_seq_common *
am2n_seq_common_alloc(void)
{
	return calloc(1, sizeof(struct am2n_seq_common));
}

void am2n_seq_common_free(struct am2n_seq_common *rs);
int am2n_seq_common_setup_endpoint(struct am2n_ctx *ctx,
				   struct am2n_seq_common *rs,
				   int midi_version, int num_groups,
				   int num_blocks, const char *ep_name,
				   const char *prod_id);
int am2n_seq_common_setup_blocks(struct am2n_ctx *ctx,
				 struct am2n_seq_common *rs,
				 int num_groups, int num_blocks);
void am2n_seq_common_setup_io(struct am2n_ctx *ctx,
			      struct am2n_seq_common *rs);

bool am2n_seq_process_ump_stream_msg(struct am2n_ctx *ctx,
				     const uint32_t *data);

#endif /* __IO_SEQ_COMMON_H_INC */
