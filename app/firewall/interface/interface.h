#ifndef _M_INTERFACE_H_
#define _M_INTERFACE_H_

#include "../module.h"

#define MAX_PORT_NUM 32

typedef enum {
  PORT_TYPE_NONE,
  PORT_TYPE_VWIRE,
} port_type_t;

typedef struct {
  uint16_t id;
  port_type_t type;
  char bus[16];
  char mac[32];
  uint16_t vwire;
} port_config_t;

typedef struct {
  uint16_t vwire_id;
  uint16_t port1;
  uint16_t port2;
} vwire_pair_t;

typedef struct {
  port_config_t ports[MAX_PORT_NUM];
  vwire_pair_t *vwire_pairs;
  uint16_t port_num;
  uint16_t vwire_pair_num;
  void *priv;
} interface_config_t;

int interface_init(void *config);
mod_ret_t interface_proc(void *config, struct rte_mbuf *mbuf, mod_hook_t hook);

#endif

// file-format: utf-8
// ident using spaces