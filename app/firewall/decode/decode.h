#ifndef _M_DECODE_H_
#define _M_DECODE_H_

#include "../module.h"

int decoder_init(__rte_unused void *config);
mod_ret_t decoder_proc(__rte_unused void *config, struct rte_mbuf *mbuf,
                       mod_hook_t hook);

#endif

// file format utf-8
// ident using space