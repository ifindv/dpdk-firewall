/**
 * An implementation for modular design. Each specific module can be
 * implemented easily just follow the convention in this part.
 * !!! Be careful when include header file in *.c that module.h must
 * be in front of any specific module's header file.
 */

#ifndef __M_MODULE_H__
#define __M_MODULE_H__

#include <rte_log.h>
#include <rte_mbuf.h>

#define __module__ __attribute((section(".module_section")))

typedef enum {
  MOD_ID_NONE,
  MOD_ID_INTERFACE,
  MOD_ID_DECODER,
  MOD_ID_ACL,
} mod_id_t;

typedef enum {
  MOD_HOOK_RECV,
  MOD_HOOK_INGRESS,
  MOD_HOOK_PREROUTING,
  MOD_HOOK_FORWARD,
  MOD_HOOK_POSTROUTING,
  MOD_HOOK_LOCALIN,
  MOD_HOOK_LOCALOUT,
  MOD_HOOK_EGRESS,
  MOD_HOOK_SEND,
} mod_hook_t;

typedef enum {
  MOD_RET_ACCEPT,
  MOD_RET_STOLEN,
} mod_ret_t;

typedef mod_ret_t (*mod_func_t)(void *config, struct rte_mbuf *mbuf,
                                mod_hook_t hook);
typedef int (*mod_init_t)(void *config);
typedef int (*mod_conf_t)(void *config);
typedef int (*mod_free_t)(void *config);

#pragma pack(1)

typedef struct {
  const char *name;  /** module name */
  uint16_t id;       /** module id */
  bool enabled;      /** module switch */
  bool log;          /** log switch */
  mod_init_t init;   /** init function */
  mod_func_t proc;   /** process function */
  mod_conf_t conf;   /** reload config */
  mod_free_t free;   /** free unused resource */
  void *priv;        /** private use */
  char reserved[12]; /** reserved */
} module_t;

#pragma pack()

#define MAX_MODULE_NUM 128
extern int max_module_id;
extern module_t *modules[MAX_MODULE_NUM];

#define MODULE_DECLARE(m) module_t m __module__

#define MODULE_REGISTER(m)                                                     \
  do {                                                                         \
    if (((m)->id > 0) && ((m)->id < 128) && (!modules[(m)->id])) {             \
      modules[(m)->id] = m;                                                    \
      if ((m)->id > max_module_id) {                                           \
        max_module_id = (m)->id;                                               \
      }                                                                        \
    }                                                                          \
  } while (0)

#define MODULE_FOREACH(m, id)                                                  \
  for (id = 0, m = modules[id]; id <= max_module_id; m = modules[++id])

int modules_load(void);
int modules_init(void *config);
int modules_proc(void *config, struct rte_mbuf *pkt, mod_hook_t hook);
int modules_conf(void *config);
int modules_free(void *config);

#endif

// file-format: utf-8
// ident using spaces