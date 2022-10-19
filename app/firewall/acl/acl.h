#ifndef _M_ACL_H_
#define _M_ACL_H_

#include "../module.h"
#include "../packet.h"

#define MAX_ACL_RULE_NUM (1U << 16)

#define ACL_ACTION_DENY 0
#define ACL_ACTION_PASS 1

int acl_init(void *config);
mod_ret_t acl_proc(void *config, struct rte_mbuf *mbuf, mod_hook_t hook);
int acl_conf(void *config);
int acl_free(void *config);

#endif

// file format utf-8
// ident using space