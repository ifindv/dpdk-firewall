#include <arpa/inet.h>
#include <rte_acl.h>
#include <rte_ip.h>

#include "../cli.h"
#include "../config.h"
#include "../json.h"
#include "../module.h"
#include "../packet.h"

#include "acl.h"

struct rte_acl_field_def acl_field_def[5] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = offsetof(ip4_tuple_t, proto),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof(ip4_tuple_t, sip),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset = offsetof(ip4_tuple_t, dip),
    },
    /*
     * Next 2 fields (src & dst ports) form 4 consecutive bytes.
     * They share the same input index.
     */
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset = offsetof(ip4_tuple_t, sp),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 3,
        .offset = offsetof(ip4_tuple_t, dp),
    },
};

struct rte_acl_config acl_cfg = {
    .num_categories = 1,
    .num_fields = RTE_DIM(acl_field_def),
    .max_size = 100000000,
};

RTE_ACL_RULE_DEF(acl_rule, RTE_DIM(acl_field_def));

struct rte_acl_param acl_param_A = {
    .name = "param_A",
    .socket_id = SOCKET_ID_ANY,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(acl_field_def)),
    .max_rule_num = MAX_ACL_RULE_NUM,
};

struct rte_acl_param acl_param_B = {
    .name = "param_B",
    .socket_id = SOCKET_ID_ANY,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(acl_field_def)),
    .max_rule_num = MAX_ACL_RULE_NUM,
};

struct rte_acl_param *acl_param;

MODULE_DECLARE(acl) = {.name = "acl",
                       .id = MOD_ID_ACL,
                       .enabled = true,
                       .log = true,
                       .init = acl_init,
                       .proc = acl_proc,
                       .conf = acl_conf,
                       .free = acl_free,
                       .priv = NULL};

static int acl_rule_load(config_t *config) {
  struct rte_acl_ctx *acl_ctx;
  char *p = NULL;
  json_object *jr = NULL, *ja;
  int i, j, rule_num;
  int ret = 0;

  acl_ctx = config->acl_ctx;
  if (!acl_ctx) {
    return -1;
  }

  jr = JR(CONFIG_PATH, "acl.json");
  if (!jr) {
    return -1;
  }

  rule_num = JA(jr, "rules", &ja);
  if (rule_num == -1) {
    JR_FREE(jr);
    return -1;
  }

  struct acl_rule r[rule_num];

#define ACL_JV(item)                                                           \
  jv = JV(jo, item);                                                           \
  if (!jv) {                                                                   \
    ret = -1;                                                                  \
    goto done;                                                                 \
  }

  for (i = 0, j = 0; i < rule_num; i++) {
    json_object *jo, *jv;
    char ip[16], mask[4];

    jo = JO(ja, i);

    ACL_JV("enabled");
    if (!JV_I(jv)) {
      continue;
    }

    ACL_JV("id");
    r[j].data.priority = JV_I(jv);
    r[j].data.userdata = r[j].data.priority;

    memset(ip, 0, 16);
    memset(mask, 0, 4);

    ACL_JV("sip");
    if ((p = strstr(JV_S(jv), "/")) != NULL) {
      *p = ' ';
      sscanf(JV_S(jv), "%s %s", ip, mask);
      r[j].field[1].value.u32 = ntohl(inet_addr(ip));
      r[j].field[1].mask_range.u32 = atoi(mask);
    } else {
      r[j].field[1].value.u32 = ntohl(inet_addr(JV_S(jv)));
      r[j].field[1].mask_range.u32 = 32;
    }

    memset(ip, 0, 16);
    memset(mask, 0, 4);

    ACL_JV("dip");
    if ((p = strstr(JV_S(jv), "/")) != NULL) {
      *p = ' ';
      sscanf(JV_S(jv), "%s %s", ip, mask);
      r[j].field[2].value.u32 = ntohl(inet_addr(ip));
      r[j].field[2].mask_range.u32 = atoi(mask);
    } else {
      r[j].field[2].value.u32 = ntohl(inet_addr(JV_S(jv)));
      r[j].field[2].mask_range.u32 = 32;
    }

    ACL_JV("sp");
    r[j].field[3].value.u16 = JV_I(jv);
    r[j].field[3].mask_range.u16 = 0xffff;

    ACL_JV("dp");
    r[j].field[4].value.u16 = JV_I(jv);
    r[j].field[4].mask_range.u16 = 0xffff;

    ACL_JV("proto");
    r[j].field[0].value.u8 = JV_I(jv);
    r[j].field[0].mask_range.u8 = 0xff;

    ACL_JV("action");
    r[j].data.category_mask = 1;
    r[j].data.action = JV_I(jv);

    j++;
  }

#undef ACL_JV

  if (j) {
    if (rte_acl_add_rules(acl_ctx, (const struct rte_acl_rule *)r, j)) {
      printf("add acl rules failed\n");
      ret = -1;
      goto done;
    }

    memcpy(acl_cfg.defs, acl_field_def,
           sizeof(struct rte_acl_field_def) * RTE_DIM(acl_field_def));
    if (rte_acl_build(acl_ctx, &acl_cfg)) {
      printf("build acl rules failed\n");
      ret = -1;
      goto done;
    }
  }

done:
  if (jr)
    JR_FREE(jr);
  return ret;
}

static int acl_show(struct cli_def *cli, const char *command, char *argv[],
                    int argc) {
  json_object *jr = NULL, *ja;
  char *opt;
  int i, rule_id, rule_num;
  int ret = 0;

  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);

  jr = JR(CONFIG_PATH, "acl.json");
  if (!jr) {
    return -1;
  }

  rule_num = JA(jr, "rules", &ja);
  if (rule_num == -1) {
    JR_FREE(jr);
    return -1;
  }

  opt = CLI_OPT_V(cli, "id");
  rule_id = -1;
  if (opt) {
    rule_id = atoi(opt);
  }

#define ACL_PRINT(item)                                                        \
  jv = JV(jo, item);                                                           \
  CLI_PRINT(cli, "%s: %s", item, JV_S(jv));

  for (i = 0; i < rule_num; i++) {
    json_object *jo, *jv;
    jo = JO(ja, i);

    /** filter rule by id
     * */
    if (rule_id != -1) {
      jv = JV(jo, "id");
      if (JV_I(jv) != rule_id) {
        continue;
      }
    }

    ACL_PRINT("id");
    ACL_PRINT("enabled");
    ACL_PRINT("sip");
    ACL_PRINT("dip");
    ACL_PRINT("sp");
    ACL_PRINT("dp");
    ACL_PRINT("proto");
    ACL_PRINT("action");
    CLI_PRINT(cli, "%s", "");
  }

#undef ACL_PRINT

  if (jr)
    JR_FREE(jr);
  return ret;
}

static int acl_dump(struct cli_def *cli, const char *command, char *argv[],
                    int argc) {
  config_t *c = cli_get_context(cli);
  char buffer[2048] = {0};

  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);

  _rte_acl_dump(c->acl_ctx, buffer);
  CLI_PRINT(cli, "%s", buffer);
  return 0;
}

static int acl_add(struct cli_def *cli, const char *command, char *argv[],
                   int argc) {
  json_object *jr = NULL, *ja, *jo, *jv;
  int rule_num;
  int ret = 0;

  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);

  jr = JR(CONFIG_PATH, "acl.json");
  if (!jr) {
    CLI_PRINT(cli, "load acl json file error");
    ret = -1;
    goto done;
  }

  rule_num = JA(jr, "rules", &ja);
  if (rule_num == -1) {
    CLI_PRINT(cli, "rules array not exist");
    ret = -1;
    goto done;
  }

#define ACL_SET(item)                                                          \
  jv = JV_NEW(CLI_OPT_V(cli, item));                                           \
  if (!jv) {                                                                   \
    ret = -1;                                                                  \
    CLI_PRINT(cli, "alloc json value failed");                                 \
    goto done;                                                                 \
  }                                                                            \
  CLI_PRINT(cli, "set item %s val %s", item, CLI_OPT_V(cli, item));            \
  JO_ADD(jo, item, jv);

  jo = JO_NEW();
  if (!jo) {
    CLI_PRINT(cli, "alloc json object failed");
    goto done;
  }

  ACL_SET("id");
  ACL_SET("sip");
  ACL_SET("dip");
  ACL_SET("sp");
  ACL_SET("dp");
  ACL_SET("proto");
  ACL_SET("action");
  ACL_SET("enabled");

#undef ACL_SET

  JA_ADD(ja, jo);
  ret = JR_SAVE(CONFIG_PATH, "acl.json", jr);
  if (ret == -1) {
    CLI_PRINT(cli, "save json file error");
    goto done;
  }

  CLI_PRINT(cli, "ok!");

done:
  if (jr)
    JR_FREE(jr);
  return ret;
}

static int acl_delete(struct cli_def *cli, const char *command, char *argv[],
                      int argc) {
  json_object *jr = NULL, *ja;
  char *opt;
  int i, rule_id, rule_num;
  int ret = 0;

  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);

  jr = JR(CONFIG_PATH, "acl.json");
  if (!jr) {
    return -1;
  }

  rule_num = JA(jr, "rules", &ja);
  if (rule_num == -1) {
    JR_FREE(jr);
    return -1;
  }

  opt = CLI_OPT_V(cli, "id");
  rule_id = -1;
  if (opt) {
    rule_id = atoi(opt);
  }

  for (i = 0; i < rule_num; i++) {
    json_object *jo, *jv;
    jo = JO(ja, i);

    /** filter rule by id
     * */
    if (rule_id != -1) {
      jv = JV(jo, "id");
      if (JV_I(jv) == rule_id) {
        JA_DEL(ja, i, 1);
        CLI_PRINT(cli, "delete acl rule %d", rule_id);
        JR_SAVE(CONFIG_PATH, "acl.json", jr);
        break;
      }
    }
  }

  if (jr)
    JR_FREE(jr);
  return ret;
}

static int acl_set(struct cli_def *cli, const char *command, char *argv[],
                   int argc) {
  json_object *jr = NULL, *ja, *jo, *jv;
  int i, rule_num;
  int ret = 0;

  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);

  jr = JR(CONFIG_PATH, "acl.json");
  if (!jr) {
    CLI_PRINT(cli, "load acl json file error");
    ret = -1;
    goto done;
  }

  rule_num = JA(jr, "rules", &ja);
  if (rule_num == -1) {
    CLI_PRINT(cli, "rules array not exist");
    ret = -1;
    goto done;
  }

#define ACL_MOD(item)                                                          \
  jv = JV(jo, item);                                                           \
  if (CLI_OPT_V(cli, item)) {                                                  \
    JV_SET(jv, CLI_OPT_V(cli, item));                                          \
    CLI_PRINT(cli, "modify item %s val %s", item, CLI_OPT_V(cli, item));       \
  }

  for (i = 0; i < rule_num; i++) {
    jo = JO(ja, i);
    jv = JV(jo, "id");
    if (JV_I(jv) == atoi(CLI_OPT_V(cli, "id"))) {
      ACL_MOD("sip");
      ACL_MOD("dip");
      ACL_MOD("sp");
      ACL_MOD("dp");
      ACL_MOD("proto");
      ACL_MOD("action");
      ACL_MOD("enabled");
    }
  }

#undef ACL_MOD

  ret = JR_SAVE(CONFIG_PATH, "acl.json", jr);
  if (ret == -1) {
    CLI_PRINT(cli, "save json file error");
    goto done;
  }

  CLI_PRINT(cli, "ok!");

done:
  if (jr)
    JR_FREE(jr);
  return ret;
}

static void acl_cli_register(config_t *config) {
  struct cli_def *cli_def;
  struct cli_command *c, *c1;

  if (!config) {
    return;
  }

  cli_def = config->cli_def;
  if (!cli_def) {
    return;
  }

  c = CLI_CMD_C(cli_def, NULL, "acl", NULL, "access control list");
  CLI_CMD_C(cli_def, c, "dump", acl_dump, "dump acl context");

  c1 = CLI_CMD_C(cli_def, c, "show", acl_show, "show acl config");
  CLI_OPT(c1, "id", "rule id");

  c1 = CLI_CMD_C(cli_def, c, "add", acl_add, "add an acl rule");
  CLI_OPT_A(c1, "id", "rule id");
  CLI_OPT_A(c1, "sip", "source ip address");
  CLI_OPT_A(c1, "dip", "destination ip address");
  CLI_OPT_A(c1, "sp", "source port");
  CLI_OPT_A(c1, "dp", "destination port");
  CLI_OPT_A(c1, "proto", "transport layer protocol");
  CLI_OPT_A(c1, "action", "do action when rule matched");
  CLI_OPT_A(c1, "enabled", "switch of rule");

  c1 = CLI_CMD_C(cli_def, c, "delete", acl_delete, "delete an acl rule");
  CLI_OPT_A(c1, "id", "rule id");

  c1 = CLI_CMD_C(cli_def, c, "set", acl_set, "modify an acl rule");
  CLI_OPT_A(c1, "id", "rule id");
  CLI_OPT(c1, "sip", "source ip address");
  CLI_OPT(c1, "dip", "destination ip address");
  CLI_OPT(c1, "sp", "source port");
  CLI_OPT(c1, "dp", "destination port");
  CLI_OPT(c1, "proto", "transport layer protocol");
  CLI_OPT(c1, "action", "do action when rule matched");
  CLI_OPT(c1, "enabled", "switch of rule");
}

int acl_free(void *config) {
  config_t *c = config;
  rte_acl_reset_rules(c->acl_ctx);
  return 0;
}

int acl_conf(void *config) {
  config_t *c = config;

  if (!acl_param)
    acl_param = &acl_param_A;
  else
    acl_param = (acl_param == &acl_param_A) ? &acl_param_B : &acl_param_A;

  c->acl_ctx = rte_acl_create(acl_param);
  if (!c->acl_ctx) {
    printf("create acl ctx failed\n");
    return -1;
  }

  if (acl_rule_load(config)) {
    printf("acl rule load failed\n");
    return -1;
  }

  return 0;
}

int acl_init(void *config) {
  if (acl_conf(config)) {
    printf("acl conf failed\n");
    return -1;
  }

  acl_cli_register(config);

  return 0;
}

static mod_ret_t acl_proc_ingress(config_t *config, struct rte_mbuf *mbuf) {
  M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL, "== acl proc ingress\n");

  struct rte_acl_ctx *acl_ctx;
  struct rte_acl_rule_data *data;
  packet_t *p;
  ip4_tuple_t *k;
  uint32_t r;
  int ret;

  acl_ctx = config->acl_ctx;
  if (!acl_ctx) {
    goto done;
  }

  p = rte_mbuf_to_priv(mbuf);
  if (!p) {
    goto done;
  }

  k = &p->tuple.v4;

  ret = rte_acl_classify(acl_ctx, (const unsigned char **)&k, &r, 1, 1);
  if (ret) {
    goto done;
  }

  M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL,
        "packet proto %u sip %u dip %u sp %u dp %u\n", k->proto, k->sip, k->dip,
        k->sp, k->dp);

  if (!r) {
    M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL, "no acl rule match\n");
    goto done;
  }

  data = rte_acl_rule_data(acl_ctx, r);
  if (!data) {
    M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL, "illegal acl rule id\n");
    goto done;
  }

  M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL, "match acl id %u action %u\n", r,
        data->action);

  if (data->action == ACL_ACTION_DENY) {
    rte_pktmbuf_free(mbuf);
    M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL, "acl action deny\n");
    return MOD_RET_STOLEN;
  }

  M_LOG(acl.log, RTE_LOG_DEBUG, MOD_ID_ACL, "acl action pass\n");

done:
  return MOD_RET_ACCEPT;
}

mod_ret_t acl_proc(void *config, struct rte_mbuf *mbuf, mod_hook_t hook) {
  if (hook == MOD_HOOK_INGRESS) {
    return acl_proc_ingress(config, mbuf);
  }

  return MOD_RET_ACCEPT;
}

// file format utf-8
// ident using space