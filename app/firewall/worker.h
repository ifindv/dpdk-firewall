#ifndef _M_WORKER__H_
#define _M_WORKER__H_

#include "config.h"

int worker_init(config_t *config);

int RX(__rte_unused config_t *config);
int TX(__rte_unused config_t *config);
int RTX(config_t *config);
int WORKER(config_t *config);
int RTX_WORKER(config_t *config);

#endif

// file-format utf-8
// ident using space