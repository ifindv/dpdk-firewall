#include "config.h"
#include "module.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

config_t config_a =
             {
                 .pktmbuf_pool = NULL,
                 .cli_def = NULL,
                 .cli_show = NULL,
                 .cli_sockfd = 0,
                 .itf_cfg = NULL,
                 .acl_ctx = NULL,
                 .promiscuous = 1,
                 .worker_num = 0,
                 .port_num = 0,
                 .mgt_core = -1,
                 .rx_core = -1,
                 .tx_core = -1,
                 .rtx_core = -1,
                 .rtx_worker_core = -1,
                 .rx_queues = {0},
                 .tx_queues = {{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}},
                 .rxq_num = 0,
                 .txq_num = 0,
                 .reload_mark = 0,
                 .switch_mark = 0,
},
         config_b;

int config_index_for_mgmt = 0;
int config_index_for_worker[MAX_WORKER_NUM] = {-1, -1, -1, -1, -1, -1, -1, -1};

int config_reload(config_t *c) {
  config_t *new = (c == &config_a) ? &config_b : &config_a;

  memcpy(new, c, sizeof(config_t));
  modules_conf(new);
  new->reload_mark = 0;
  new->switch_mark = 0;
  config_index_for_mgmt =
      (config_index_for_mgmt <= 0) ? 1 : config_index_for_mgmt + 1;
  return 1;
}

config_t *config_switch(config_t *c, int lcore_id) {
  if (lcore_id == -1) {
    int i;
    while (1) {
      usleep(50000);

      for (i = 0; i < MAX_WORKER_NUM; i++) {
        if (config_index_for_worker[i] == -1)
          continue;
        if (config_index_for_worker[i] != config_index_for_mgmt)
          break;
      }

      if (i == MAX_WORKER_NUM) {
        c->switch_mark = 0;
        break;
      }
    }

    modules_free(c);
  } else {
    config_index_for_worker[lcore_id] =
        (config_index_for_worker[lcore_id] <= 0)
            ? 1
            : config_index_for_worker[lcore_id] + 1;
  }

  return (c == &config_a) ? &config_b : &config_a;
}

// file format utf-8
// ident using space