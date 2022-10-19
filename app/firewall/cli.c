#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cli.h"
#include "config.h"

#define CLI_PORT 8000

unsigned int cli_regular_count;
unsigned int cli_regular_debug;

struct cli_def *m_cli_def;
int m_cli_sockfd;

static int cli_regular_callback(struct cli_def *cli) {
  cli_regular_count++;
  if (cli_regular_debug) {
    cli_print(cli, "Regular callback - %u times so far", cli_regular_count);
    cli_reprompt(cli);
  }
  return CLI_OK;
}

static int cli_check_auth(const char *username, const char *password) {
  if (strcasecmp(username, "ifindv") != 0)
    return CLI_ERROR;
  if (strcasecmp(password, "ifindv") != 0)
    return CLI_ERROR;
  return CLI_OK;
}

static int cli_check_enable(const char *password) {
  return !strcasecmp(password, "superman");
}

static int cli_idle_timeout(struct cli_def *cli) {
  cli_print(cli, "Custom idle timeout");
  return CLI_QUIT;
}

static int cli_save_conf(struct cli_def *cli, const char *command, char *argv[],
                         int argc) {
  CLI_PRINT(cli, "command %s argv[0] %s argc %d", command, argv[0], argc);
  config_t *c = cli_get_context(cli);
  c->reload_mark = 1;
  return 0;
}

int _cli_init(void *config) {
  config_t *c = (config_t *)config;
  struct sockaddr_in addr;
  int on = 1;
  const char *banner =
      "=====================================================================\n"
      "      _____ .__                                 .__   .__\n"
      "    _/ ____\\|__|_______   ____ __  _  _______   |  |  |  |\n"
      "    \\   __\\ |  |\\_  __ \\_/ __ \\ \\/ \\/ /\\__  \\  |  |  |  |\n"
      "     |  |   |  | |  | \\/\\  ___/ \\     /  / __ \\_|  |__|  |__\n"
      "     |__|   |__| |__|    \\___  > \\/\\_/  (____  /|____/|____/\n"
      "                             \\/              \\/\n"
      "=====================================================================";

  if (c->cli_def || c->cli_sockfd) {
    return -1;
  }

  c->cli_def = cli_init();
  cli_set_banner(c->cli_def, banner);
  cli_set_hostname(c->cli_def, "sys");
  cli_telnet_protocol(c->cli_def, 1);
  cli_regular(c->cli_def, cli_regular_callback);
  cli_regular_interval(c->cli_def, 5);
  cli_set_idle_timeout_callback(c->cli_def, 300, cli_idle_timeout);
  cli_set_auth_callback(c->cli_def, cli_check_auth);
  cli_set_enable_callback(c->cli_def, cli_check_enable);
  cli_set_context(c->cli_def, c);

  CLI_CMD_C(c->cli_def, NULL, "save", cli_save_conf,
            "save and reload configuration");
  c->cli_show =
      CLI_CMD_C(c->cli_def, NULL, "show", NULL, "show system information");

  if ((c->cli_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  if (setsockopt(c->cli_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
    perror("setsockopt");
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(CLI_PORT);
  if (bind(c->cli_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return -1;
  }

  if (listen(c->cli_sockfd, 50) < 0) {
    perror("listen");
    return -1;
  }

  return 0;
}

static void *_cli_loop(void *arg) {
  struct params {
    int _x;
    void *_c;
  } *p = arg;

  config_t *c = p->_c;
  int x = p->_x;

  cli_loop(c->cli_def, x);
  close(x);
  pthread_exit(NULL);
}

int _cli_run(void *config) {
  config_t *c = config;
  pthread_t thread_id;
  struct timeval timeout;
  fd_set fds;
  int x, r;

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;
  FD_ZERO(&fds);
  FD_SET(c->cli_sockfd, &fds);

  r = select(c->cli_sockfd + 1, &fds, NULL, NULL, &timeout);
  if (r == -1) {
    return -1;
  }

  if (r == 0) {
    return -1;
  }

  x = accept(c->cli_sockfd, NULL, 0);
  if (x > 0) {
    struct params {
      int _x;
      void *_c;
    } p;
    p._x = x;
    p._c = c;
    pthread_create(&thread_id, NULL, _cli_loop, &p);
    pthread_detach(thread_id);
  }

  return 0;
}

// file format utf-8
// ident using space