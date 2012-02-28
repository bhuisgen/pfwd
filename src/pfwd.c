/*
 * pfwd - a port forwarding server
 *
 * Copyright 2011 Boris HUISGEN <bhuisgen@hbis.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "pfwd.h"
#include "daemon.h"
#include "log.h"
#include "log_console.h"
#include "log_file.h"
#include "log_syslog.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_ERROR(_fmt, ...)    log_message(app->logger, LOG_LEVEL_ERROR, _fmt, __VA_ARGS__)
#define LOG_INFO(_fmt, ...)     log_message(app->logger, LOG_LEVEL_INFO, _fmt, __VA_ARGS__)
#ifdef DEBUG
#define LOG_DEBUG(_fmt, ...)    log_message(app->logger, LOG_LEVEL_DEBUG, _fmt, __VA_ARGS__)
#else
#define LOG_DEBUG(_fmt, ...)
#endif

#define IPV4_ANY                "*"
#define IPV4_MAXLEN             15
#define IPV6_ANY                "::"
#define IPV6_MAXLEN             45

typedef struct _pfw_t
{
  gchar *name;
  gchar *listen;
  gushort listen_port;
  gint listen_af;
  gint listen_backlog;
  gchar *forward;
  gushort forward_port;
  gint forward_af;
  gint buffer_size;
  gchar **allow_ips;
  gchar **deny_ips;
  struct ev_loop *ev_loop;
  ev_io *w;
  gint fd;
  GSList *c_ws;
  GSList *s_ws;
} pfw_t;

typedef struct _pfw_io_t
{
  struct _pfw_t *pfw;
  gint c_fd;
  gchar c_ip[IPV6_MAXLEN];
  gshort c_port;
  gint s_fd;
  gchar *buf;
} pfw_io_t;

application_t *app = NULL;

gchar *
get_default_config_file();
gboolean
load_config();
gboolean
reload_config();
GSList *
init_pfwds();
logger_t *
init_logger();
gboolean
run_main_loop();
static void
exit_main_loop(void);
static gboolean
start_pfwd(pfw_t *pfw);
static void
stop_pfwd(pfw_t *pfw);
static void
pfwd_accept_event(EV_P_ ev_io *w, gint revents);
static void
pfwd_read_event(EV_P_ ev_io *w, gint revents);
gboolean
pfwd_check_access(pfw_t *pfw, gchar *ip);
void
version();
void
parse_command_line(gint argc, gchar *argv[]);
void
sigpipe(gint sig);
void
sighup(gint sig);
void
sigint(gint sig);
void
sigterm(gint sig);
void
cleanup(void);

gchar*
get_default_config_file()
{
  const gchar *homedir;
  gchar* config_file;

  homedir = g_getenv("HOME");
  if (!homedir)
    homedir = g_get_home_dir();

  config_file = g_build_path(G_DIR_SEPARATOR_S, homedir, PFWD_HOMEDIR,
      PFWD_CONFIGFILE, NULL);

  if (!g_file_test(config_file, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
    {
      g_free(config_file);

      config_file = g_build_path(G_DIR_SEPARATOR_S, SYSCONFDIR, PFWD_CONFIGFILE,
          NULL);
    }

  return config_file;
}

gboolean
load_config()
{
  GError *error = NULL;
  gchar *group;

  app->settings = g_key_file_new();

  g_key_file_load_from_file(app->settings, app->config_file, G_KEY_FILE_NONE,
      &error);
  if (error)
    {
      g_printerr("%s: %s (%s)\n", app->config_file, N_("error in config file"),
          error->message);

      g_error_free(error);

      return FALSE;
    }

  g_key_file_set_list_separator(app->settings, ',');

  group = g_key_file_get_start_group(app->settings);
  if (!group)
    {
      g_printerr("%s: %s (%s)\n", app->config_file, N_("error in config file"),
          N_("no group 'main'"));

      return FALSE;
    }

  if (g_strcmp0(group, CONFIG_GROUP_MAIN) != 0)
    {
      g_printerr("%s: %s (%s)\n", app->config_file, N_("error in config file"),
          N_("the first group is not 'main'"));

      g_free(group);

      return FALSE;
    }

  g_free(group);

  return TRUE;
}

gboolean
reload_config()
{
  GKeyFile *settings;
  GError *error = NULL;
  gchar *group;

  settings = g_key_file_new();
  if (!g_key_file_load_from_file(settings, app->config_file, G_KEY_FILE_NONE,
      &error))
    {
      LOG_ERROR("%s: %s (%s)\n",
          app->config_file, N_("error in config file, aborting reload"), error->message);

      g_key_file_free(settings);

      return FALSE;
    }

  g_key_file_set_list_separator(settings, ',');

  group = g_key_file_get_start_group(settings);
  if (!group)
    {
      LOG_ERROR("%s: %s (%s)\n",
          app->config_file, N_("error in config file"), N_("no group 'main'"));

      g_key_file_free(settings);

      return FALSE;
    }

  if (g_strcmp0(group, CONFIG_GROUP_MAIN) != 0)
    {
      LOG_ERROR("%s: %s (%s)\n",
          app->config_file, N_("error in config file"), N_("the first group is not 'main'"));

      g_free(group);
      g_key_file_free(settings);

      return FALSE;
    }

  g_free(group);

  if (app->settings)
    g_key_file_free(app->settings);

  app->settings = settings;

  return TRUE;
}

GSList *
init_pfwds()
{
  GSList *list = NULL;
  GRegex *regex_ipv6, *regex_ipv4, *regex_unix;
  GMatchInfo *match_info;
  GError *error = NULL;
  gchar **groups;
  gsize len;
  gint i;

  regex_ipv6 = g_regex_new("^\\[(.+)\\]$", 0, 0, NULL);
  regex_ipv4 = g_regex_new("^(\\d+\\.\\d+\\.\\d+\\.\\d+|\\*)$", 0, 0, NULL);
  regex_unix = g_regex_new("^unix:(.+)$", 0, 0, NULL);

  groups = g_key_file_get_groups(app->settings, &len);

  if (len < 2)
    {
      g_printerr("%s: %s (%s)\n", app->config_file, N_("error in config file"),
          N_("no redirector group"));

      g_strfreev(groups);
      g_regex_unref(regex_unix);
      g_regex_unref(regex_ipv4);
      g_regex_unref(regex_ipv6);

      return NULL;
    }

  for (i = 0; i < len; i++)
    {
      if (g_strcmp0(groups[i], CONFIG_GROUP_MAIN) == 0)
        continue;

      pfw_t *pfw;
      gchar *value;

      pfw = g_new0(pfw_t, 1);

      pfw->name = g_strdup(groups[i]);

      value = g_key_file_get_string(app->settings, pfw->name,
          CONFIG_KEY_PFW_LISTEN, &error);
      if (error)
        {
          g_printerr("%s: %s\n", pfw->name, N_("invalid listen address"));
          g_error_free(error);

          g_free(pfw);
          g_regex_unref(regex_unix);
          g_regex_unref(regex_ipv4);
          g_regex_unref(regex_ipv6);
          g_strfreev(groups);

          return NULL;
        }

      if (g_regex_match(regex_ipv6, value, 0, &match_info))
        {
          struct in6_addr in6;
          gchar *ipv6;

          ipv6 = g_match_info_fetch(match_info, 1);
          if (!ipv6)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv6 listen address"));

              g_free(value);
              g_match_info_free(match_info);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          if ((g_strcmp0(ipv6, IPV6_ANY) != 0)
              && !inet_pton(AF_INET6, ipv6, &in6))
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv6 listen address"));

              g_free(ipv6);
              g_free(value);
              g_match_info_free(match_info);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          pfw->listen = ipv6;
          pfw->listen_af = AF_INET6;
        }

      g_match_info_free(match_info);

      if (g_regex_match(regex_ipv4, value, 0, &match_info))
        {
          struct in_addr in4;
          gchar *ipv4;

          ipv4 = g_match_info_fetch(match_info, 0);
          if (!ipv4)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv4 listen address"));

              g_match_info_free(match_info);
              g_free(value);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          if (g_strcmp0(ipv4, IPV4_ANY) != 0)
            {
              in4.s_addr = inet_addr(ipv4);
              if (!inet_pton(AF_INET, ipv4, &in4))
                {
                  g_printerr("%s: %s\n", pfw->name,
                      N_("invalid IPv4 listen address"));

                  g_free(ipv4);
                  g_match_info_free(match_info);
                  g_free(value);
                  g_free(pfw);
                  g_strfreev(groups);
                  g_regex_unref(regex_unix);
                  g_regex_unref(regex_ipv4);
                  g_regex_unref(regex_ipv6);

                  return NULL;
                }
            }

          pfw->listen = ipv4;
          pfw->listen_af = AF_INET;
        }

      g_match_info_free(match_info);

      if (g_regex_match(regex_unix, value, 0, &match_info))
        {
          gchar *path;

          path = g_match_info_fetch(match_info, 1);
          if (!path)
            {
              g_printerr("%s: %s\n", pfw->name, N_("invalid UNIX listen path"));

              g_match_info_free(match_info);
              g_free(value);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          pfw->listen = path;
          pfw->listen_af = AF_UNIX;
        }

      g_match_info_free(match_info);
      g_free(value);

      if (pfw->listen_af != AF_UNIX)
        {
          pfw->listen_port = g_key_file_get_integer(app->settings, pfw->name,
              CONFIG_KEY_PFW_LISTENPORT, &error);
          if (error || (pfw->listen_port <= 0))
            {
              g_printerr("%s: %s\n", pfw->name, N_("invalid listen port"));

              if (error)
                {
                  g_error_free(error);
                }

              g_free(pfw->listen);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }
        }

      if (pfw->listen_af != AF_UNIX)
        {
          pfw->listen_backlog = g_key_file_get_integer(app->settings, pfw->name,
              CONFIG_KEY_PFW_LISTENBACKLOG, &error);
          if (error || (pfw->listen_backlog <= 0))
            {
              g_printerr("%s: %s\n", pfw->name, N_("invalid listen backlog"));

              if (error)
                {
                  g_error_free(error);
                }

              return NULL;
            }
        }

      value = g_key_file_get_string(app->settings, pfw->name,
          CONFIG_KEY_PFW_FORWARD, &error);
      if (error)
        {
          g_printerr("%s: %s\n", pfw->name, N_("invalid forward address"));

          g_error_free(error);
          g_free(pfw->listen);
          g_free(pfw);
          g_strfreev(groups);
          g_regex_unref(regex_unix);
          g_regex_unref(regex_ipv4);
          g_regex_unref(regex_ipv6);


          return NULL;
        }

      if (g_regex_match(regex_ipv6, value, 0, &match_info))
        {
          struct in6_addr in6;
          gchar *ipv6;

          ipv6 = g_match_info_fetch(match_info, 1);
          if (!ipv6)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv6 forward address"));

              g_match_info_free(match_info);
              g_free(value);
              g_free(pfw->listen);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          if ((g_strcmp0(ipv6, IPV6_ANY) != 0)
              && !inet_pton(AF_INET6, ipv6, &in6))
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv6 forward address"));

              g_free(ipv6);
              g_match_info_free(match_info);
              g_free(value);
              g_free(pfw->listen);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          pfw->forward = ipv6;
          pfw->forward_af = AF_INET6;
        }

      g_match_info_free(match_info);

      if (g_regex_match(regex_ipv4, value, 0, &match_info))
        {
          struct in_addr in4;
          gchar *ipv4;

          ipv4 = g_match_info_fetch(match_info, 0);
          if (!ipv4)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv4 forward address"));

              g_match_info_free(match_info);
              g_free(value);
              g_free(pfw->listen);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          if (g_strcmp0(ipv4, IPV4_ANY) != 0)
            {
              in4.s_addr = inet_addr(ipv4);
              if (!inet_pton(AF_INET, ipv4, &in4))
                {
                  g_printerr("%s: %s\n", pfw->name,
                      N_("invalid IPv4 forward address"));

                  g_free(ipv4);
                  g_match_info_free(match_info);
                  g_free(value);
                  g_free(pfw->listen);
                  g_free(pfw);
                  g_strfreev(groups);
                  g_regex_unref(regex_unix);
                  g_regex_unref(regex_ipv4);
                  g_regex_unref(regex_ipv6);

                  return NULL;
                }
            }

          pfw->forward = ipv4;
          pfw->forward_af = AF_INET;
        }

      g_match_info_free(match_info);

      if (g_regex_match(regex_unix, value, 0, &match_info))
        {
          gchar *path;

          path = g_match_info_fetch(match_info, 1);
          if (!path)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid UNIX forward path"));

              g_match_info_free(match_info);
              g_free(value);
              g_free(pfw->listen);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }

          pfw->forward = path;
          pfw->forward_af = AF_UNIX;
        }

      g_match_info_free(match_info);
      g_free(value);

      if (pfw->forward_af != AF_UNIX)
        {
          pfw->forward_port = g_key_file_get_integer(app->settings, pfw->name,
              CONFIG_KEY_PFW_FORWARDPORT, &error);
          if (error || (pfw->forward_port <= 0))
            {
              g_printerr("%s: %s\n", pfw->name, N_("invalid forward port"));

              if (error)
                {
                  g_error_free(error);
                }

              g_free(pfw->forward);
              g_free(pfw->listen);
              g_free(pfw);
              g_strfreev(groups);
              g_regex_unref(regex_unix);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);

              return NULL;
            }
        }

      pfw->buffer_size = g_key_file_get_integer(app->settings, pfw->name,
          CONFIG_KEY_PFW_BUFFERSIZE, &error);
      if (error || (pfw->buffer_size < CONFIG_KEY_PFW_BUFFERSIZE_MINIMUM))
        {
          pfw->buffer_size = CONFIG_KEY_PFW_BUFFERSIZE_DEFAULT;

          g_printerr("%s: %s\n", pfw->name,
              N_("setting socket buffer size to minimal value"));

          if (error)
            {
              g_error_free(error);
              error = NULL;
            }
        }

      pfw->allow_ips = g_key_file_get_string_list(app->settings, pfw->name,
          CONFIG_KEY_PFW_ALLOW, NULL, &error);
      if (error)
        {
          g_error_free(error);
          error = NULL;
        }

      pfw->deny_ips = g_key_file_get_string_list(app->settings, pfw->name,
          CONFIG_KEY_PFW_DENY, NULL, NULL);
      if (error)
        {
          g_error_free(error);
          error = NULL;
        }

      list = g_slist_append(list, pfw);
    }

  g_strfreev(groups);
  g_regex_unref(regex_unix);
  g_regex_unref(regex_ipv4);
  g_regex_unref(regex_ipv6);

  return list;
}

logger_t *
init_logger()
{
  logger_t *logger = NULL;
  gboolean daemon;
  GError *error = NULL;

  daemon = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
      CONFIG_KEY_MAIN_DAEMONIZE, &error);
  if (error)
    {
      daemon = CONFIG_KEY_MAIN_DAEMONIZE_DEFAULT;

      g_error_free(error);
      error = NULL;
    }
  if (daemon)
    {
      gboolean use_syslog;
      gint log_level;
      LoggerLevel level = LOGGER_LEVEL_NONE;

      use_syslog = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_USESYSLOG, &error);
      if (error)
        {
          use_syslog = CONFIG_KEY_MAIN_USESYSLOG_DEFAULT;

          g_error_free(error);
          error = NULL;
        }

      log_level = g_key_file_get_integer(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_LOGLEVEL, &error);
      if (error)
        {
          log_level = CONFIG_KEY_MAIN_LOGLEVEL_DEFAULT;

          g_error_free(error);
          error = NULL;
        }

      switch (log_level)
        {
      case CONFIG_KEY_MAIN_LOGLEVEL_NONE:
        level = LOGGER_LEVEL_NONE;
        break;

      case CONFIG_KEY_MAIN_LOGLEVEL_ERROR:
        level = LOGGER_LEVEL_ERROR;
        break;

      case CONFIG_KEY_MAIN_LOGLEVEL_WARNING:
        level = LOGGER_LEVEL_WARNING;
        break;

      case CONFIG_KEY_MAIN_LOGLEVEL_INFO:
        level = LOGGER_LEVEL_INFO;
        break;

      case CONFIG_KEY_MAIN_LOGLEVEL_DEBUG:
        level = LOGGER_LEVEL_DEBUG;
        break;
        }

      if (use_syslog)
        {
          gchar *syslog_facility;

          syslog_facility = g_key_file_get_string(app->settings,
              CONFIG_KEY_MAIN_GROUP, CONFIG_KEY_MAIN_SYSLOGFACILITY, &error);
          if (error)
            {
              syslog_facility = g_strdup(CONFIG_KEY_MAIN_SYSLOGFACILITY);

              g_error_free(error);
            }

          handler_t *handler = log_handler_create(LOG_HANDLER_TYPE_SYSLOG);
          if (!handler)
            {
              g_free(syslog_facility);

              return NULL;
            }

          if (!log_handler_set_option(handler,
              LOG_HANDLER_SYSLOG_OPTION_FACILITY, syslog_facility))
            {
              log_handler_destroy(handler);
              g_free(syslog_facility);

              return NULL;
            }

          g_free(syslog_facility);

          logger = log_create_logger(handler, level);
          if (!logger)
            {
              log_handler_destroy(handler);

              return NULL;
            }
        }
      else
        {
          gchar *log_file;

          log_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
              CONFIG_KEY_MAIN_LOGFILE, &error);
          if (error)
            {
              log_file = g_strdup(CONFIG_KEY_MAIN_LOGFILE_DEFAULT);

              g_error_free(error);
              error = NULL;
            }

          handler_t *handler = log_handler_create(LOG_HANDLER_TYPE_FILE);
          if (!handler)
            {
              g_free(log_file);

              return NULL;
            }

          if (!log_handler_set_option(handler, LOG_HANDLER_FILE_OPTION_LOGFILE,
              log_file))
            {
              log_handler_destroy(handler);
              g_free(log_file);

              return NULL;
            }

          g_free(log_file);

          logger = log_create_logger(handler, level);
          if (!logger)
            {
              log_handler_destroy(handler);

              return NULL;
            }
        }
    }
  else
    {
      handler_t *handler = log_handler_create(LOG_HANDLER_TYPE_CONSOLE);
      if (!handler)
        return NULL;

#ifdef DEBUG
      logger = log_create_logger(handler, LOGGER_LEVEL_ALL);
#else
      logger = log_create_logger(handler, LOGGER_LEVEL_INFO);
#endif
      if (!logger)
        {
          log_handler_destroy(handler);

          return NULL;
        }
    }

  return logger;
}

gboolean
run_main_loop()
{
  struct ev_loop *loop;
  GSList *item;
  pfw_t *pfw;

  LOG_DEBUG("%s", N_("running main loop"));

  loop = ev_default_loop(EVFLAG_AUTO);
  if (!loop)
    {
      LOG_ERROR("%s", N_("failed to retrieve main loop"));

      return FALSE;
    };

  atexit(exit_main_loop);

  for (item = app->pfwds; item; item = item->next)
    {
      pfw = (pfw_t *) item->data;

      if (!start_pfwd(pfw))
        continue;
    }

  ev_loop(loop, 0);

  return TRUE;
}

static void
exit_main_loop(void)
{
  GSList *item;
  pfw_t *pfw;

  LOG_DEBUG("%s", N_("exiting main loop"));

  for (item = app->pfwds; item; item = item->next)
    {
      pfw = (pfw_t *) item->data;

      stop_pfwd(pfw);
    }

  ev_default_destroy();
}

static gboolean
start_pfwd(pfw_t *pfw)
{
  LOG_DEBUG("%s: %s", pfw->name, "starting redirector");

  pfw->ev_loop = ev_default_loop(EVFLAG_AUTO);
  if (!pfw->ev_loop)
    {
      LOG_ERROR("%s: %s", pfw->name, "failed to retrieve main loop");

      return FALSE;
    };

  if (pfw->listen_af == AF_INET6)
    {
      struct sockaddr_in6 saddr6;
      gint opt, flags;

      memset(&saddr6, 0, sizeof (struct sockaddr_in6));
      saddr6.sin6_family = AF_INET6;
      saddr6.sin6_port = htons(pfw->listen_port);

      if (strcmp(pfw->listen, IPV6_ANY) == 0)
        saddr6.sin6_addr = in6addr_any;
      else
        inet_pton(AF_INET6, pfw->listen, &saddr6.sin6_addr);

      pfw->fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
      if (pfw->fd < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to create local IPv6 socket"));

          return FALSE;
        }

      opt = 1;
      setsockopt(pfw->fd, SOL_SOCKET, SO_REUSEADDR, (const gchar *) &opt,
          sizeof(opt));

      if (bind(pfw->fd, (struct sockaddr *) &saddr6,
          sizeof(struct sockaddr_in6)) < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to bind local IPv6 socket"));

          return FALSE;
        }

      if (listen(pfw->fd, pfw->listen_backlog) < 0)
        {
          LOG_ERROR("%s", N_("Failed to listen on local IPv6 socket"));

          return FALSE;
        }

      flags = fcntl(pfw->fd, F_GETFL, 0);
      fcntl(pfw->fd, F_SETFL, flags | O_NONBLOCK);
    }
  else if (pfw->listen_af == AF_INET)
    {
      struct sockaddr_in saddr4;
      gint opt, flags;

      memset(&saddr4, 0, sizeof (struct sockaddr_in));
      saddr4.sin_family = AF_INET;
      saddr4.sin_port = htons(pfw->listen_port);

      if (strcmp(pfw->listen, IPV4_ANY) == 0)
        saddr4.sin_addr.s_addr = INADDR_ANY;
      else
        inet_pton(AF_INET, pfw->listen, &saddr4.sin_addr);

      pfw->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (pfw->fd < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to create local IPv4 socket"));

          return FALSE;
        }

      opt = 1;
      setsockopt(pfw->fd, SOL_SOCKET, SO_REUSEADDR, (const gchar *) &opt,
          sizeof(opt));

      if (bind(pfw->fd, (struct sockaddr *) &saddr4, sizeof(struct sockaddr_in))
          < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to bind local IPv4 socket"));

          return FALSE;
        }

      if (listen(pfw->fd, pfw->listen_backlog) < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to listen on local IPv4 socket"));

          return FALSE;
        }

      flags = fcntl(pfw->fd, F_GETFL, 0);
      fcntl(pfw->fd, F_SETFL, flags | O_NONBLOCK);
    }
  else /*if (pfw->listen_af == AF_UNIX)*/
    {
      struct sockaddr_un sun;
      gint flags;

      memset(&sun, 0, sizeof (struct sockaddr_un));
      sun.sun_family = AF_UNIX;
      strcpy(sun.sun_path, pfw->listen);

      pfw->fd = socket(AF_UNIX, SOCK_STREAM, 0);
      if (pfw->fd < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to create local UNIX socket"));

          return FALSE;
        }

      if (bind(pfw->fd, (struct sockaddr *) &sun, sizeof(struct sockaddr_un))
          < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to bind local UNIX socket"));

          return FALSE;
        }

      if (listen(pfw->fd, pfw->listen_backlog) < 0)
        {
          LOG_ERROR("%s: %s",
              pfw->name, N_("failed to listen on local UNIX socket"));

          return FALSE;
        }

      flags = fcntl(pfw->fd, F_GETFL, 0);
      fcntl(pfw->fd, F_SETFL, flags | O_NONBLOCK);
    }

  pfw->w = g_new0(ev_io, 1);
  pfw->w->data = pfw;
  ev_io_init(pfw->w, pfwd_accept_event, pfw->fd, EV_READ);
  LOG_DEBUG("%s: %s (pfw=%p)", pfw->name, N_("accept watcher created"), pfw);

  ev_io_start(pfw->ev_loop, pfw->w);
  LOG_DEBUG("%s: %s (fd=%d, event=EV_READ, data=%p)",
      pfw->name, N_("accept watcher started"), pfw->w->fd, pfw->w->data);

  if (pfw->listen_af == AF_INET6)
    {
      LOG_INFO("%s: %s ([%s]:%hu)",
          pfw->name, N_("socket is listening"), pfw->listen, pfw->listen_port);
    }
  else if (pfw->listen_af == AF_INET)
    {
      LOG_INFO("%s: %s (%s:%hu)",
          pfw->name, N_("socket is listening"), pfw->listen, pfw->listen_port);
    }
  else /*if (pfw->listen_af == AF_UNIX)*/
    {
      LOG_INFO("%s: %s (unix:%s)",
          pfw->name, N_("socket is listening"), pfw->listen);
    }

  return TRUE;
}

static void
stop_pfwd(pfw_t *pfw)
{
  LOG_DEBUG("%s: %s", pfw->name, "stopping redirector");

  if (pfw->w)
    {
      if (ev_is_active(pfw->w))
        {
          ev_io_stop(pfw->ev_loop, pfw->w);

          LOG_DEBUG("%s: %s", pfw->name, N_("accept watcher stopped"));
        }

      g_free(pfw->w);

      LOG_DEBUG("%s: %s", pfw->name, N_("accept watcher cleaned"));
    }

  if (pfw->s_ws)
    {
      GSList *item;
      ev_io *ev;
      pfw_io_t *pfw_io;

      for (item = pfw->s_ws; item; item = item->next)
        {
          ev = (ev_io *) item->data;
          if (!ev)
            continue;

          if (ev_is_active(ev))
            {
              ev_io_stop(pfw->ev_loop, ev);

              LOG_DEBUG("%s: %s", pfw->name, N_("server read watcher stopped"));
            }

          if (ev->data)
            {
              pfw_io = (pfw_io_t *) ev->data;

              if (pfw_io->buf)
                {
                  g_free(pfw_io->buf);
                }

              g_free(pfw_io);
            }

          g_free(ev);
        }

      g_slist_free(pfw->s_ws);

      LOG_DEBUG("%s: %s", pfw->name, N_("server read watchers cleaned"));
    }

  if (pfw->c_ws)
    {
      GSList *item;
      ev_io *ev;
      pfw_io_t *pfw_io;

      for (item = pfw->c_ws; item; item = item->next)
        {
          ev = (ev_io *) item->data;
          if (!ev)
            continue;

          if (ev_is_active(ev))
            {
              ev_io_stop(pfw->ev_loop, ev);

              LOG_DEBUG("%s: %s", pfw->name, N_("client read watcher stopped"));
            }

          if (ev->data)
            {
              pfw_io = (pfw_io_t *) ev->data;

              close(pfw_io->s_fd);
              close(pfw_io->c_fd);

              if (pfw_io->buf)
                g_free(pfw_io->buf);

              g_free(pfw_io);
            }

          g_free(ev);
        }

      g_slist_free(pfw->c_ws);

      LOG_DEBUG("%s: %s", pfw->name, N_("client read watchers cleaned"));
    }

  if (pfw->fd)
    {
      close(pfw->fd);

      if (pfw->listen_af == AF_UNIX)
        {
          unlink(pfw->listen);

          LOG_DEBUG("%s: %s", pfw->name, N_("UNIX socket file deleted"));
        }

      if (pfw->listen_af == AF_INET6)
        {
          LOG_INFO("%s: %s ([%s]:%hu)",
              pfw->name, N_("socket closed"), pfw->listen, pfw->listen_port);
        }
      else if (pfw->listen_af == AF_INET)
        {
          LOG_INFO("%s: %s (%s:%hu)",
              pfw->name, N_("socket closed"), pfw->listen, pfw->listen_port);
        }
      else if (pfw->listen_af == AF_UNIX)
        {
          LOG_INFO("%s: %s (unix:%s)",
              pfw->name, N_("socket closed"), pfw->listen);
        }
    }
}

static void
pfwd_accept_event(EV_P_ ev_io *w, gint revents)
  {
    LOG_DEBUG("%s (fd=%d, data=%p)",
        N_("new accept event"), w->fd,w->data);

    pfw_t *pfw = (pfw_t *)w->data;
    if (pfw == NULL)
      {
        LOG_ERROR("%s", N_("no data found, ignoring accept event"));

        return;
      }

    ev_io *c_w, *s_w;
    pfw_io_t *c_data, *s_data;
    gint c, s;
    gchar c_ip[IPV6_MAXLEN];
    short c_port = 0;
    gchar *ip;

    memset(c_ip, 0, sizeof(c_ip));

    if (pfw->listen_af == AF_INET6)
      {
        struct sockaddr_in6 sin6;
        socklen_t len;
        gint flags, opt;

        memset(&sin6, 0, sizeof (struct sockaddr_in6));
        len = sizeof(struct sockaddr_in6);

        c = accept(w->fd, (struct sockaddr *) &sin6, &len);
        if (c < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to accept new IPv6 client"));

            return;
          }

        if (!inet_ntop(AF_INET6, &sin6.sin6_addr, c_ip, sizeof(c_ip)))
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to resolv IPv6 client address"));

            close(c);

            return;
          }

        c_port = htons(sin6.sin6_port);

        ip = g_strdup_printf("[%s]", c_ip);
        if (!pfwd_check_access(pfw, c_ip))
          {
            LOG_INFO("%s: %s (%s)",
                pfw->name, N_("IPv6 client address denied"), ip);

            g_free(ip);
            close(c);

            return;
          }

        LOG_INFO("%s: %s (%s)",
            pfw->name, N_("IPv6 client address allowed"), ip);

        g_free(ip);

        flags = fcntl(c, F_GETFL, 0);
        fcntl(c, F_SETFL, flags | O_NONBLOCK);
        opt = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }
    else if (pfw->listen_af == AF_INET)
      {
        struct sockaddr_in sin4;
        socklen_t len;
        gint flags, opt;

        memset(&sin4, 0, sizeof (struct sockaddr_in));
        len = sizeof(struct sockaddr_in);

        c = accept(w->fd, (struct sockaddr *) &sin4, &len);
        if (c < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to accept new IPv4 client"));

            return;
          }

        if (!inet_ntop(AF_INET, &sin4.sin_addr, c_ip, sizeof(c_ip)))
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to resolv IPv4 client address"));

            close(c);

            return;
          }

        c_port = htons(sin4.sin_port);

        ip = g_strdup_printf("%s", c_ip);
        if (!pfwd_check_access(pfw, c_ip))
          {
            LOG_INFO("%s: %s (%s)",
                pfw->name, N_("IPv4 client address denied"), ip);

            g_free(ip);
            close(c);

            return;
          }

        LOG_INFO("%s: %s (%s)",
            pfw->name, N_("IPv4 client address allowed"), ip);

        g_free(ip);

        flags = fcntl(c, F_GETFL, 0);
        fcntl(c, F_SETFL, flags | O_NONBLOCK);
        opt = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }
    else /*if (pfw->listen_af == AF_UNIX)*/
      {
        struct sockaddr_un sun;
        socklen_t len;
        gint flags, opt;

        memset(&sun, 0, sizeof (struct sockaddr_un));
        len = sizeof(struct sockaddr_un);

        c = accept(w->fd, (struct sockaddr *) &sun, &len);
        if (c < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to accept new UNIX client"));

            return;
          }

        flags = fcntl(c, F_GETFL, 0);
        fcntl(c, F_SETFL, flags | O_NONBLOCK);
        opt = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }

    if (pfw->forward_af == AF_INET6)
      {
        struct sockaddr_in6 sin6;
        gint flags, opt;

        s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to create remote IPv6 socket"));

            close(c);

            return;
          }

        memset(&sin6, 0, sizeof(struct sockaddr_in6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = INADDR_ANY;

        if (bind(s, (struct sockaddr *) &sin6, sizeof(struct sockaddr_in6)) < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to bind remote IPv6 socket"));

            close(s);
            close(c);

            return;
          }

        if (strcmp(pfw->forward, IPV6_ANY) == 0)
          {
            sin6.sin6_addr = in6addr_any;
          }
        else
          {
            inet_pton(AF_INET6, pfw->forward, &sin6.sin6_addr);
            sin6.sin6_port = htons(pfw->forward_port);
          }

        if (connect(s, (struct sockaddr *) &sin6,
                sizeof(struct sockaddr_in6)) < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to connect remote IPv6 socket"));

            close(s);
            close(c);

            return;
          }

        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        opt = 0;
        setsockopt(s, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }
    else if (pfw->forward_af == AF_INET)
      {
        struct sockaddr_in sin4;
        gint flags, opt;

        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to create remote IPv4 socket"));

            close(c);

            return;
          }

        memset(&sin4, 0, sizeof(struct sockaddr_in));
        sin4.sin_family = AF_INET;
        sin4.sin_port = INADDR_ANY;

        if (bind(s, (struct sockaddr *) &sin4, sizeof(struct sockaddr_in)) < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to bind remote IPv4 socket"));

            close(s);
            close(c);

            return;
          }

        inet_pton(AF_INET, pfw->forward, &(sin4.sin_addr));
        sin4.sin_port = htons(pfw->forward_port);

        if (connect(s, (struct sockaddr *) &sin4, sizeof(struct sockaddr_in))
            < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to connect remote IPv4 socket"));

            close(s);
            close(c);

            return;
          }

        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        opt = 0;
        setsockopt(s, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }
    else /*if (pfw->forward_af == AF_UNIX)*/
      {
        struct sockaddr_un sun;
        gint flags, opt;

        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to create remote UNIX socket"));

            close(c);

            return;
          }

        memset(&sun, 0, sizeof(struct sockaddr_un));
        sun.sun_family = AF_UNIX;
        strcpy(sun.sun_path, pfw->forward);

        if (bind(s, (struct sockaddr *) &sun, sizeof(struct sockaddr_un)) < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to bind remote UNIX socket"));

            close(s);
            close(c);

            return;
          }

        if (connect(s, (struct sockaddr *) &sun, sizeof(struct sockaddr_un))
            < 0)
          {
            LOG_ERROR("%s: %s",
                pfw->name, N_("failed to connect remote UNIX socket"));

            close(s);
            close(c);

            return;
          }

        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        opt = 0;
        setsockopt(s, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }

    c_w = g_new0(ev_io, 1);
    c_data = g_new0(pfw_io_t, 1);
    c_w->data = c_data;
    c_data->pfw = pfw;
    c_data->c_fd = c;
    g_strlcpy(c_data->c_ip, c_ip, sizeof(c_data->c_ip));
    c_data->c_port = c_port;
    c_data->s_fd = s;
    c_data->buf = (gchar *)g_malloc0(pfw->buffer_size);

    pfw->c_ws = g_slist_append(pfw->c_ws, c_w);

    LOG_DEBUG("%s: %s (c_fd=%d, s_fd=%d, buf=%p, buf_len=%d)",
        pfw->name, N_("client read watcher created"), c_data->c_fd, c_data->s_fd,
        c_data->buf, pfw->buffer_size);

    ev_io_init(c_w, pfwd_read_event, c, EV_READ);
    ev_io_start(pfw->ev_loop, c_w);

    LOG_DEBUG("%s: %s (fd=%d, event=EV_READ, data=%p)",
        pfw->name, N_("client read watcher started"),
        c_w->fd, c_w->data);

    s_w = g_new0(ev_io, 1);
    s_data = g_new0(pfw_io_t, 1);
    s_w->data = s_data;
    s_data->pfw = pfw;
    s_data->c_fd = c;
    g_strlcpy(s_data->c_ip, c_ip, sizeof(c_data->c_ip));
    s_data->c_port = c_port;
    s_data->s_fd = s;
    s_data->buf = (gchar *)g_malloc0(pfw->buffer_size);

    pfw->s_ws = g_slist_append(pfw->s_ws, s_w);

    LOG_DEBUG("%s: %s (c_fd=%d, s_fd=%d, buf=%p, buf_len=%d)",
        pfw->name, N_("server read watcher created"), s_data->c_fd, s_data->s_fd,
        s_data->buf, pfw->buffer_size);

    ev_io_init(s_w, pfwd_read_event, s, EV_READ);
    ev_io_start(pfw->ev_loop, s_w);

    LOG_DEBUG("%s: %s (fd=%d, event=EV_READ, data=%p)",
        pfw->name, N_("server read watcher started"), s_w->fd, s_w->data);

    if (pfw->listen_af == AF_INET6)
      {
        LOG_INFO("%s: %s ([%s]:%hu)",
            pfw->name, N_("new client connection"),
            c_ip, c_port);
      }
    else if (pfw->listen_af == AF_INET)
      {
        LOG_INFO("%s: %s (%s:%hu)",
            pfw->name, N_("new client connection"),
            c_ip, c_port);
      }
    else /*if (pfw->listen_af == AF_UNIX)*/
      {
        LOG_INFO("%s: %s",
            pfw->name, N_("new client connection"));
      }
  }

static void
pfwd_read_event(EV_P_ ev_io *w, gint revents)
  {
    LOG_DEBUG("%s (fd=%d, data=%p)",
    N_("new read event"), w->fd, w->data);

    gint nread, nwrite, i;

    pfw_io_t *pfw_io = (pfw_io_t *)w->data;
    if (pfw_io == NULL)
      {
        LOG_ERROR("%s", N_("no data found, ignoring read event"));

        return;
      }

    LOG_DEBUG("%s: %s (c_fd=%d, s_fd=%d)",
    pfw_io->pfw->name, N_("read event data"), pfw_io->c_fd, pfw_io->s_fd);

    nread= read(w->fd, pfw_io->buf, pfw_io->pfw->buffer_size);
    if (nread >= 0)
      {
        LOG_DEBUG("%s: %s=%d", pfw_io->pfw->name, N_("bytes readed"), nread);
      }

    if (nread <= 0)
      {
        if (nread < 0)
          {
            LOG_DEBUG("%s: %s (%s)", pfw_io->pfw->name, N_("read error"), g_strerror(errno));

            if (errno == EAGAIN)
              {
                return;
              }
          }

        ev_io_stop(pfw_io->pfw->ev_loop, w);
        LOG_DEBUG("%s: %s", pfw_io->pfw->name, N_("read watcher stopped"));

        close(pfw_io->s_fd);
        close(pfw_io->c_fd);

        if (w->fd == pfw_io->c_fd)
          {
            if (pfw_io->pfw->listen_af == AF_INET6)
              {
                LOG_INFO("%s: %s ([%s]:%hu)",
                pfw_io->pfw->name, N_("client connection closed"),
                pfw_io->c_ip, pfw_io->c_port);
              }
            else if (pfw_io->pfw->listen_af == AF_INET)
              {
                LOG_INFO("%s: %s (%s:%hu)",
                pfw_io->pfw->name, N_("client connection closed"),
                pfw_io->c_ip, pfw_io->c_port);
              }
            else /*if (pfw_io->pfw->listen_af == AF_UNIX)*/
              {
                LOG_INFO("%s: %s",
                pfw_io->pfw->name, N_("client connection closed"));
              }

            pfw_io->pfw->c_ws = g_slist_remove(pfw_io->pfw->c_ws, w);
          }
        else /*if (w->fd == pfw_io->s_fd) */
          {
            LOG_INFO("%s: %s", pfw_io->pfw->name, N_("server connection closed"));

            pfw_io->pfw->s_ws = g_slist_remove(pfw_io->pfw->s_ws, w);
          }

        g_free(pfw_io->buf);
        g_free(pfw_io);
        g_free(w);

        return;
      }

    for (i=0; i < nread; i += nwrite)
      {
        if (w->fd == pfw_io->c_fd)
          {
            nwrite = write(pfw_io->s_fd, pfw_io->buf + i, nread - i);
          }
        else
          {
            nwrite = write(pfw_io->c_fd, pfw_io->buf + i, nread - i);
          }

        if (nwrite >= 0)
          {
            LOG_DEBUG("%s: %s=%d",
            pfw_io->pfw->name, N_("bytes written"), nwrite);
          }

        if (nwrite < 0)
          {
            LOG_DEBUG("%s: %s (%s)",
            pfw_io->pfw->name, N_("write error"), g_strerror(errno));

            if (errno == EAGAIN)
              {
                nwrite = 0;

                continue;
              }
          }
      }
  }

gboolean
pfwd_check_access(pfw_t *pfw, gchar *ip)
{
  gboolean deny = FALSE;
  gboolean allow = FALSE;
  gint i;

  if (pfw->deny_ips)
    {
      deny = TRUE;

      for (i = 0; pfw->deny_ips[i] != NULL; i++)
        {
          if (g_pattern_match_simple(pfw->deny_ips[i], ip))
            {
              LOG_DEBUG("%s (%s)", N_("IP address matches deny rule"), ip);

              return FALSE;
            }
        }
    }

  if (pfw->allow_ips)
    {
      allow = TRUE;

      for (i = 0; pfw->allow_ips[i] != NULL; i++)
        {
          if (g_pattern_match_simple(pfw->allow_ips[i], ip))
            {
              LOG_DEBUG("%s (%s)", N_("IP address matches allow rule"), ip);

              return TRUE;
            }
        }
    }

  if (allow)
    {
      LOG_DEBUG("%s (%s)", N_("IP address matches default deny rule"), ip);

      return FALSE;
    }

  LOG_DEBUG("%s (%s)", N_("IP address matches default allow rule"), ip);

  return TRUE;
}

void
version()
{
  g_print("%s\n", PACKAGE_STRING);
  g_print("%s\n", PFWD_COPYRIGHT);
  g_print("\n");
  g_print("%s\n", PFWD_LICENCE);
  g_print("\n");
}

void
parse_command_line(gint argc, gchar *argv[])
{
  GOptionContext *context;
  gchar *help;
  gchar *config_file = NULL;
  gboolean verbose = FALSE;
  gint show_version = 0;
  GError *error = NULL;

  GOptionEntry entries[] =
    {
      { "file", 'f', 0, G_OPTION_ARG_FILENAME, &config_file,
          N_("read configuration from file"), N_("file") },
          { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
              N_("set verbose output") },
          { "version", 0, 0, G_OPTION_ARG_NONE, &show_version,
              N_("show version information"), NULL },
          { NULL } };

  context = g_option_context_new(NULL);
  g_option_context_add_main_entries(context, entries, PACKAGE);

  g_option_context_parse(context, &argc, &argv, &error);
  if (error)
    {
      help = g_option_context_get_help(context, TRUE, NULL);
      g_option_context_free(context);
      g_print("%s", help);

      g_error_free(error);
      g_free(help);

      exit(1);
    }

  g_option_context_free(context);

  if (show_version == 1)
    {
      version();

      exit(0);
    }

  if (config_file)
    app->config_file = g_strdup(config_file);
  else
    app->config_file = get_default_config_file();

  app->verbose = verbose;
}

void
sigpipe(gint sig)
{
  LOG_INFO("%s", N_("SIGPIPE received, continuing execution"));
}

void
sighup(gint sig)
{
  LOG_INFO("%s", N_("SIGHUP received, reloading configuration"));

  reload_config();
}

void
sigint(gint sig)
{
  LOG_INFO("%s", N_("SIGINT received, exiting"));

  exit(0);
}

void
sigterm(gint sig)
{
  LOG_INFO("%s", N_("SIGTERM received, exiting"));

  exit(0);
}

void
cleanup(void)
{
  gboolean daemon;
  GError *error = NULL;

  if (app->logger)
    LOG_DEBUG("%s", N_("cleanup"));

  if (app->settings && app->daemon)
    {
      daemon = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_DAEMONIZE, &error);
      if (error)
        {
          daemon = CONFIG_KEY_MAIN_DAEMONIZE_DEFAULT;

          g_error_free(error);
          error = NULL;
        }
      if (daemon)
        {
          gchar *pid_file;

          pid_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
              CONFIG_KEY_MAIN_PIDFILE, &error);
          if (error)
            {
              pid_file = g_strdup(CONFIG_KEY_MAIN_PIDFILE_DEFAULT);

              g_error_free(error);
              error = NULL;
            }

          g_unlink(pid_file);
          g_free(pid_file);
        }

      LOG_INFO("%s %s", PACKAGE, N_("daemon stopped"));
    }

  if (app->logger)
    {
      log_destroy_logger(app->logger);
    }

  if (app->pfwds)
    {
      GSList *item;
      pfw_t *pfw;

      for (item = app->pfwds; item; item = item->next)
        {
          pfw = (pfw_t *) item->data;
          if (!pfw)
            continue;

          g_free(pfw->name);
          g_free(pfw->listen);
          g_free(pfw->forward);
          g_strfreev(pfw->allow_ips);
          g_strfreev(pfw->deny_ips);
          g_free(pfw);
        }

      g_slist_free(app->pfwds);
    }

  if (app->settings)
    g_key_file_free(app->settings);

  g_free(app->config_file);
  g_free(app);
}

gint
main(gint argc, gchar *argv[])
{
  gboolean daemon;
  gint ret;
  GError *error = NULL;

  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);

  app = g_new0(application_t, 1);
  atexit(cleanup);

  parse_command_line(argc, argv);

  if (!load_config())
    exit(-1);

  app->pfwds = init_pfwds();
  if (!app->pfwds)
    exit(-3);

  app->logger = init_logger();
  if (!app->logger)
    {
      g_printerr("%s\n", N_("failed to create logger"));

      exit(-2);
    }

  daemon = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
      CONFIG_KEY_MAIN_DAEMONIZE, &error);
  if (error)
    {
      daemon = CONFIG_KEY_MAIN_DAEMONIZE_DEFAULT;

      g_error_free(error);
      error = NULL;
    }
  if (daemon)
    {
      gchar *pid_file, *user, *group;

      pid_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_PIDFILE, &error);
      if (error)
        {
          pid_file = g_strdup(CONFIG_KEY_MAIN_PIDFILE_DEFAULT);

          g_error_free(error);
          error = NULL;
        }

      user = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_USER, &error);
      if (error)
        {
          user = g_strdup(CONFIG_KEY_MAIN_USER_DEFAULT);

          g_error_free(error);
          error = NULL;
        }

      group = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_GROUP, &error);
      if (error)
        {
          group = g_strdup(CONFIG_KEY_MAIN_GROUP_DEFAULT);

          g_error_free(error);
          error = NULL;
        }

      ret = daemonize(pid_file, user, group);

      g_free(pid_file);
      g_free(user);
      g_free(group);

      if (ret < 0)
        {
          LOG_ERROR("%s: %d", N_("failed to daemonize, error code"), ret);

          exit(-3);
        }

      app->daemon = TRUE;
      LOG_INFO("%s %s", PACKAGE, N_("daemon started"));
    }

  signal(SIGPIPE, sigpipe);
  signal(SIGHUP, sighup);
  signal(SIGINT, sigint);
  signal(SIGTERM, sigterm);

  if (!run_main_loop())
    exit(-4);

  return 0;
}
