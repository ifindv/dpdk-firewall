#ifndef _M_CLI_H_
#define _M_CLI_H_

/** simple encapsulation of libcli
 * */

#include <libcli.h>

/** macros for register commnd
 *  _C for config mode
 *  _S for super user
 *  _CS for both
 * */

#define CLI_CMD(cli, parent, cmd, cb, help)                                    \
  cli_register_command(cli, parent, cmd, cb, PRIVILEGE_UNPRIVILEGED,           \
                       MODE_EXEC, help)

#define CLI_CMD_C(cli, parent, cmd, cb, help)                                  \
  cli_register_command(cli, parent, cmd, cb, PRIVILEGE_UNPRIVILEGED,           \
                       MODE_CONFIG, help)

#define CLI_CMD_S(cli, parent, cmd, cb, help)                                  \
  cli_register_command(cli, parent, cmd, cb, PRIVILEGE_PRIVILEGED, MODE_EXEC,  \
                       help)

#define CLI_CMD_CS(cli, parent, cmd, cb, help)                                 \
  cli_register_command(cli, parent, cmd, cb, PRIVILEGE_PRIVILEGED,             \
                       MODE_CONFIG, help)

/** macros for register option arg
 *  _A for argument is required, otherwise, argument is optional
 * */

#define CLI_OPT(cmd, name, help)                                               \
  cli_register_optarg(cmd, name, CLI_CMD_OPTIONAL_ARGUMENT,                    \
                      PRIVILEGE_UNPRIVILEGED, MODE_CONFIG, help, NULL, NULL,   \
                      NULL)

#define CLI_OPT_A(cmd, name, help)                                             \
  cli_register_optarg(cmd, name, CLI_CMD_ARGUMENT, PRIVILEGE_UNPRIVILEGED,     \
                      MODE_CONFIG, help, NULL, NULL, NULL)

/** macros for get option value
 * */
#define CLI_OPT_V(cli, name) cli_get_optarg_value(cli, name, NULL)

/** macros for register option arg help message
 * */

#define CLI_HLP(opt, name, help) cli_optarg_addhelp(opt, name, help);

/** macros for cli print
 * */

#define CLI_PRINT(cli, fmt, ...) cli_print(cli, fmt, ##__VA_ARGS__)

int _cli_init(void *config);
int _cli_run(void *config);

#endif

// file format utf-8
// ident using space