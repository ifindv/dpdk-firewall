#ifndef _M_CONFIG_H_
#define _M_CONFIG_H_

#include <stdbool.h>

#define MAX_FILE_PATH 256
#define MAX_WORKER_NUM 8
#define MAX_PORT_NUM 32
#define MAX_QUEUE_NUM MAX_WORKER_NUM
#define MAX_PKT_BURST 32

#define CONFIG_PATH "/opt/firewall/config"
#define BINARY_PATH "/opt/firewall/bin"
#define SCRIPT_PATH "/opt/firewall/script"

typedef struct {
  struct rte_mempool *pktmbuf_pool;
  int promiscuous;
  int worker_num;
  int port_num;
  int mgt_core;
  int rx_core;
  int tx_core;
  int rtx_core;
  int rtx_worker_core;
  void *cli_def;
  void *cli_show;
  int cli_sockfd;
  void *rx_queues[MAX_WORKER_NUM];
  void *tx_queues[MAX_PORT_NUM][MAX_QUEUE_NUM];
  int rxq_num;
  int txq_num;
  void *itf_cfg;
  void *acl_ctx;
  int reload_mark; /** mark for configuration reload */
  int switch_mark; /** mark for configuration switch */
} config_t;

int config_reload(config_t *c);
config_t *config_switch(config_t *c, int lcore_id);

#endif

// file format utf-8
// ident using space