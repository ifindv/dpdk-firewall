#include <signal.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_log.h>
#include <rte_per_lcore.h>

#include "cli.h"
#include "config.h"
#include "interface/interface.h"
#include "module.h"
#include "packet.h"
#include "worker.h"

extern config_t config_a, config_b;
extern int config_index_for_worker[MAX_WORKER_NUM], config_index_for_mgmt;

config_t *config_for_mgmt = &config_a;
__thread config_t *config_for_worker;

volatile bool force_quit;

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    force_quit = true;
  }
}

static int cli_show_conf(struct cli_def *cli, const char *command, char *argv[],
                         int argc) {
  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);

  config_t *c = cli_get_context(cli);
  CLI_PRINT(cli, "working copy config-%s", (c == &config_a) ? "A" : "B");
  CLI_PRINT(cli, "indicator [%d %d %d %d %d %d %d %d] %d",
            config_index_for_worker[0], config_index_for_worker[1],
            config_index_for_worker[2], config_index_for_worker[3],
            config_index_for_worker[4], config_index_for_worker[5],
            config_index_for_worker[6], config_index_for_worker[7],
            config_index_for_mgmt);

  CLI_PRINT(cli, "pktmbuf pool %p", c->pktmbuf_pool);
  CLI_PRINT(cli, "promiscuous %d", c->promiscuous);
  CLI_PRINT(cli, "worker num %d", c->worker_num);
  CLI_PRINT(cli, "port num %d", c->port_num);
  CLI_PRINT(cli, "mangement core id %d", c->mgt_core);
  CLI_PRINT(cli, "rx core id %d", c->rx_core);
  CLI_PRINT(cli, "tx core id %d", c->tx_core);
  CLI_PRINT(cli, "rtx core id %d", c->rtx_core);
  CLI_PRINT(cli, "rtx worker core id %d", c->rtx_worker_core);
  CLI_PRINT(cli, "cli def %p", c->cli_def);
  CLI_PRINT(cli, "cli show %p", c->cli_show);
  CLI_PRINT(cli, "cli socket id %d", c->cli_sockfd);
  CLI_PRINT(cli, "rx queues %p", c->rx_queues);
  CLI_PRINT(cli, "tx queues %p", c->tx_queues);
  CLI_PRINT(cli, "rx queue num %d", c->rxq_num);
  CLI_PRINT(cli, "tx queue num %d", c->txq_num);
  CLI_PRINT(cli, "interface config %p", c->itf_cfg);
  CLI_PRINT(cli, "acl context %p", c->acl_ctx);
  CLI_PRINT(cli, "reload mark %d", c->reload_mark);
  CLI_PRINT(cli, "switch mark %d", c->switch_mark);
  return 0;
}

static int main_loop(__rte_unused void *arg) {
  int lcore_id = rte_lcore_id();
  config_for_worker = (config_t *)arg;
  config_index_for_worker[lcore_id] = 0;

  while (!force_quit) {
    if (config_for_worker->switch_mark) {
      config_for_worker = config_switch(config_for_worker, lcore_id);
    }

    if (lcore_id == config_for_worker->rx_core)
      RX(config_for_worker);
    else if (lcore_id == config_for_worker->tx_core)
      TX(config_for_worker);
    else if (lcore_id == config_for_worker->rtx_core)
      RTX(config_for_worker);
    else if (lcore_id == config_for_worker->rtx_worker_core)
      RTX_WORKER(config_for_worker);
    else
      WORKER(config_for_worker);
  }

  return 0;
}

static void mgmt_loop(__rte_unused config_t *c) {
  config_t *_c = c;

  while (!force_quit) {
    /** When a reload mark set, a config switch process started, included steps
     * below:
     * 1. reload config
     * 2. tell worker to switch config and wait all worker switch done
     * 3. switch config
     * */
    if (_c->reload_mark) {
      if (config_reload(_c)) {
        _c->reload_mark = 0;
        _c->switch_mark = 1;
        _c = config_switch(_c, -1);
        cli_set_context(_c->cli_def, _c);
        config_for_mgmt = _c;
      }
    }
    _cli_run(_c);
  }
}

int main(int argc, char **argv) {
  int lcore_id;
  int ret = 0;

  ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "rte eal init failed\n");
  }
  argc -= ret;
  argv += ret;

  ret = _rte_log_init("/opt/firewall/log/firewall.log", RTE_LOG_DEBUG);
  if (ret) {
    rte_exit(EXIT_FAILURE, "rte init log failed\n");
  }

  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  config_for_mgmt->pktmbuf_pool = rte_pktmbuf_pool_create(
      "mbuf_pool", 81920, 256, sizeof(packet_t), 128 + 2048, rte_socket_id());
  if (!config_for_mgmt->pktmbuf_pool) {
    rte_exit(EXIT_FAILURE, "create pktmbuf pool failed\n");
  }

  unsigned int lcores = rte_lcore_count();
  if (lcores < 2 || lcores > 8 || lcores % 2) {
    rte_exit(EXIT_FAILURE,
             "lcores must be multiple of 2, support 2,4,8 for now\n");
  }

  config_for_mgmt->mgt_core = rte_get_main_lcore();

  /** TODO: alloc lcore role by config file.
   * */
  RTE_LCORE_FOREACH(lcore_id) {
    if (lcores == 2) {
      if (lcore_id != config_for_mgmt->mgt_core) {
        config_for_mgmt->rtx_worker_core = lcore_id;
        config_for_mgmt->worker_num++;
      }
    }

    if (lcores == 4) {
      if (lcore_id != config_for_mgmt->mgt_core) {
        if (config_for_mgmt->rtx_core == -1) {
          config_for_mgmt->rtx_core = lcore_id;
        } else {
          config_for_mgmt->worker_num++;
        }
      }
    }

    if (lcores == 8) {
      if (lcore_id != config_for_mgmt->mgt_core) {
        if (config_for_mgmt->rx_core == -1) {
          config_for_mgmt->rx_core = lcore_id;
          continue;
        }

        if (config_for_mgmt->tx_core == -1) {
          config_for_mgmt->tx_core = lcore_id;
          continue;
        }

        config_for_mgmt->worker_num++;
      }
    }
  }

  config_for_mgmt->port_num = rte_eth_dev_count_avail();
  if (config_for_mgmt->port_num < 2) {
    rte_exit(EXIT_FAILURE, "need 2 port at least");
  }

  ret = worker_init(config_for_mgmt);
  if (ret) {
    rte_exit(EXIT_FAILURE, "worker init erorr\n");
  }

  ret = _cli_init(config_for_mgmt);
  if (ret) {
    rte_exit(EXIT_FAILURE, "cli init erorr\n");
  }

  CLI_CMD_C(config_for_mgmt->cli_def, config_for_mgmt->cli_show, "config",
            cli_show_conf, "global configuration");

  modules_load();
  ret = modules_init(config_for_mgmt);
  if (ret) {
    rte_exit(EXIT_FAILURE, "module init erorr\n");
  }

  rte_eal_mp_remote_launch(main_loop, (void *)config_for_mgmt, SKIP_MAIN);
  mgmt_loop(config_for_mgmt);

  ret = 0;
  rte_eal_mp_wait_lcore();
  modules_free(config_for_mgmt);
  rte_eal_cleanup();

  return ret;
}

// file-format utf-8
// ident using space