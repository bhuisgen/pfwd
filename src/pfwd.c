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
#include <ev.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_ERROR(logger, _fmt, ...)    log_message(logger, LOG_LEVEL_ERROR, _fmt, __VA_ARGS__)
#define LOG_INFO(logger, _fmt, ...)     log_message(logger, LOG_LEVEL_INFO, _fmt, __VA_ARGS__)
#ifdef DEBUG
#define LOG_DEBUG(logger, _fmt, ...)    log_message(logger, LOG_LEVEL_DEBUG, _fmt, __VA_ARGS__)
#else
#define LOG_DEBUG(logger, _fmt, ...)
#endif

#define IPV4_ANY                        "*"
#define IPV4_MAXLEN                     15
#define IPV6_ANY                        "::"
#define IPV6_MAXLEN                     45

typedef struct _pfw_t
{
  gchar *name;
  gchar *listen_ip;
  gushort listen_port;
  gchar *forward_ip;
  gushort forward_port;
  gchar **allow_ips;
  gchar **deny_ips;
  struct ev_loop *ev_loop;
  ev_io *w;
  gint fd;
  gint af;
  gint backlog;
  gint buf_size;

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
gboolean
run_child_loop(pfw_t *pfw);
static void
exit_main_loop(void);
static void
accept_event(EV_P_ ev_io *w, gint revents);
static void
read_event(EV_P_ ev_io *w, gint revents);
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
  gchar* config_file;

  config_file = g_build_path(G_DIR_SEPARATOR_S, PACKAGE_SYSCONF_DIR,
      PFWD_CONFIGFILE, NULL);

  return config_file;
}

gboolean
load_config()
{
  GError *error = NULL;

  app->settings = g_key_file_new();

  if (!g_key_file_load_from_file(app->settings, app->config_file,
      G_KEY_FILE_NONE, &error))
    {
      g_printerr("%s: %s\n", N_("Error in config file"), error->message);

      return FALSE;
    }

  g_key_file_set_list_separator(app->settings, ',');

  return TRUE;
}

gboolean
reload_config()
{
  GKeyFile *settings;

  settings = g_key_file_new();
  if (!g_key_file_load_from_file(settings, app->config_file, G_KEY_FILE_NONE,
      NULL))
    {
      LOG_ERROR(app->logger, "%s", N_("Error in config file, aborting reload"));

      return FALSE;
    }

  g_key_file_set_list_separator(settings, ',');

  if (app->settings)
    g_key_file_free(app->settings);

  app->settings = settings;

  return TRUE;
}

GSList *
init_pfwds()
{
  GSList *list = NULL;
  GRegex *regex_ipv6, *regex_ipv4;
  GMatchInfo *match_info;
  gchar **groups;
  gint i;
  gsize len;

  regex_ipv6 = g_regex_new("^\\[(.+)\\]$", 0, 0, NULL);
  regex_ipv4 = g_regex_new("^(\\d+\\.\\d+\\.\\d+\\.\\d+|\\*)$", 0, 0, NULL);

  groups = g_key_file_get_groups(app->settings, NULL);
  for (i = 0; groups[i] != NULL; i++)
    {
      if (g_strcmp0(groups[i], CONFIG_GROUP_MAIN) == 0)
        continue;

      pfw_t *pfw;
      gchar *value;

      pfw = g_new0(pfw_t, 1);

      pfw->name = g_strdup(groups[i]);

      value = g_key_file_get_string(app->settings, pfw->name,
          CONFIG_KEY_PFW_LISTEN, NULL);
      if (!value)
        {
          g_printerr("%s: %s\n", pfw->name, N_("invalid listen address"));

          g_regex_unref(regex_ipv4);
          g_regex_unref(regex_ipv6);
          g_free(pfw);
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

              g_match_info_free(match_info);
              g_free(value);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(pfw);
              g_strfreev(groups);

              return NULL;
            }

          if ((g_strcmp0(ipv6, IPV6_ANY) != 0)
              && !inet_pton(AF_INET6, ipv6, &in6))
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv6 listen address"));

              g_free(ipv6);
              g_match_info_free(match_info);
              g_free(value);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(pfw);
              g_strfreev(groups);

              return NULL;
            }

          pfw->af = AF_INET6;
          pfw->listen_ip = ipv6;
        }
      else
        {
          struct in_addr in4;
          gchar *ipv4;

          g_match_info_free(match_info);

          if (g_regex_match(regex_ipv4, value, 0, &match_info))
            ipv4 = g_match_info_fetch(match_info, 0);
          else
            ipv4 = NULL;
          if (!ipv4)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv4 listen address"));

              g_match_info_free(match_info);
              g_free(value);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(pfw);
              g_strfreev(groups);

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
                  g_regex_unref(regex_ipv4);
                  g_regex_unref(regex_ipv6);
                  g_free(pfw);
                  g_strfreev(groups);

                  return NULL;
                }
            }

          pfw->af = AF_INET;
          pfw->listen_ip = ipv4;
        }

      g_match_info_free(match_info);
      g_free(value);

      pfw->listen_port = g_key_file_get_integer(app->settings, pfw->name,
          CONFIG_KEY_PFW_LISTENPORT, NULL);
      if (pfw->listen_port == 0)
        {
          g_printerr("%s: %s\n", pfw->name, N_("invalid listen port"));

          g_free(pfw->listen_ip);
          g_free(pfw);
          g_strfreev(groups);

          return NULL;
        }

      pfw->backlog = g_key_file_get_integer(app->settings, pfw->name,
          CONFIG_KEY_PFW_BACKLOG, NULL);
      if (pfw->backlog <= 0)
        pfw->backlog = CONFIG_KEY_PFW_BACKLOG_DEFAULT;

      pfw->buf_size = g_key_file_get_integer(app->settings, pfw->name,
          CONFIG_KEY_PFW_BUFFER, NULL);
      if (pfw->buf_size < 4096)
        pfw->buf_size = CONFIG_KEY_PFW_BUFFER_DEFAULT;

      value = g_key_file_get_string(app->settings, pfw->name,
          CONFIG_KEY_PFW_FORWARD, NULL);
      if (!value)
        {
          g_printerr("%s: %s\n", pfw->name, N_("invalid forward address"));

          g_free(pfw);
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
                  N_("invalid IPv6 forward address"));

              g_match_info_free(match_info);
              g_regex_unref(regex_ipv6);
              g_free(value);
              g_free(pfw->listen_ip);
              g_free(pfw);
              g_strfreev(groups);

              return NULL;
            }

          if ((g_strcmp0(ipv6, IPV6_ANY) != 0)
              && !inet_pton(AF_INET6, ipv6, &in6))
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv6 forward address"));

              g_free(ipv6);
              g_match_info_free(match_info);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(value);
              g_free(pfw->listen_ip);
              g_free(pfw);
              g_strfreev(groups);

              return NULL;
            }

          if (pfw->af != AF_INET6)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("the addresses are not of the same family"));

              g_free(ipv6);
              g_match_info_free(match_info);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(value);
              g_free(pfw->listen_ip);
              g_free(pfw);
              g_strfreev(groups);

              return NULL;
            }

          pfw->forward_ip = ipv6;
        }
      else
        {
          struct in_addr in4;
          gchar *ipv4;

          if (g_regex_match(regex_ipv4, value, 0, &match_info))
            ipv4 = g_match_info_fetch(match_info, 0);
          else
            ipv4 = NULL;
          if (!ipv4)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("invalid IPv4 forward address"));

              g_match_info_free(match_info);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(value);
              g_free(pfw->listen_ip);
              g_free(pfw);
              g_strfreev(groups);

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
                  g_regex_unref(regex_ipv4);
                  g_regex_unref(regex_ipv6);
                  g_free(value);
                  g_free(pfw);
                  g_strfreev(groups);

                  return NULL;
                }
            }

          if (pfw->af != AF_INET)
            {
              g_printerr("%s: %s\n", pfw->name,
                  N_("the addresses are not of the same family"));

              g_free(ipv4);
              g_match_info_free(match_info);
              g_regex_unref(regex_ipv4);
              g_regex_unref(regex_ipv6);
              g_free(value);
              g_free(pfw->listen_ip);
              g_free(pfw);
              g_strfreev(groups);

              return NULL;
            }

          pfw->forward_ip = ipv4;
        }

      g_match_info_free(match_info);
      g_free(value);

      pfw->forward_port = g_key_file_get_integer(app->settings, pfw->name,
          CONFIG_KEY_PFW_FORWARDPORT, NULL);
      if (pfw->forward_port == 0)
        {
          g_printerr("%s: %s\n", pfw->name, N_("invalid forward port"));

          g_free(pfw->forward_ip);
          g_free(pfw->listen_ip);
          g_free(pfw);
          g_strfreev(groups);

          return NULL;
        }

      pfw->allow_ips = g_key_file_get_string_list(app->settings, pfw->name,
          CONFIG_KEY_PFW_ALLOW, &len, NULL);

      pfw->deny_ips = g_key_file_get_string_list(app->settings, pfw->name,
          CONFIG_KEY_PFW_DENY, &len, NULL);

      list = g_slist_append(list, pfw);
    }

  g_strfreev(groups);

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
    daemon = CONFIG_KEY_MAIN_DAEMONIZE_DEFAULT;

  if (daemon)
    {
      gboolean use_syslog;
      gint log_level;
      LoggerLevel level = LOGGER_LEVEL_NONE;

      use_syslog = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_USESYSLOG, &error);
      if (error)
        use_syslog = CONFIG_KEY_MAIN_USESYSLOG_DEFAULT;

      log_level = g_key_file_get_integer(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_LOGLEVEL, &error);
      if (error)
        log_level = CONFIG_KEY_MAIN_LOGLEVEL_DEFAULT;

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
            syslog_facility = g_strdup(CONFIG_KEY_MAIN_SYSLOGFACILITY);

          handler_t *handler = log_handler_syslog_create();
          if (!handler)
            return NULL;
          log_handler_set_option(handler, LOG_HANDLER_SYSLOG_OPTION_FACILITY,
              syslog_facility);

          logger = log_create_logger(handler, level);
        }
      else
        {
          gchar *log_file;

          log_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
              CONFIG_KEY_MAIN_LOGFILE, NULL);
          if (!log_file)
            log_file = g_strdup(CONFIG_KEY_MAIN_LOGFILE_DEFAULT);

          handler_t *handler = log_handler_file_create();
          if (!handler)
            return NULL;
          log_handler_set_option(handler, LOG_HANDLER_FILE_OPTION_LOGFILE,
              log_file);

          logger = log_create_logger(handler, level);
        }
    }
  else
    {
      handler_t *handler = log_handler_console_create();
      if (!handler)
        return NULL;

#ifdef DEBUG
      logger = log_create_logger(handler, LOGGER_LEVEL_ALL);
#else
      logger = log_create_logger(handler, LOGGER_LEVEL_INFO);
#endif
    }

  return logger;
}

gboolean
run_main_loop()
{
  struct ev_loop *loop;
  GSList *item;
  pfw_t *pfw;

  loop = ev_default_loop(EVFLAG_AUTO);
  if (!loop)
    {
      LOG_ERROR(app->logger, "%s", N_("failed to initialize main event loop"));

      return FALSE;
    };

  for (item = app->pfwds; item; item = item->next)
    {
      pfw = (pfw_t *) item->data;

      run_child_loop(pfw);
    }

  atexit(exit_main_loop);
  ev_loop(loop, 0);

  return TRUE;
}

gboolean
run_child_loop(pfw_t *pfw)
{
  pfw->ev_loop = ev_loop_new(EVFLAG_AUTO);
  if (!pfw->ev_loop)
    {
      LOG_ERROR(app->logger, "%s: %s",
          pfw->name, "failed to initialize child event loop");

      return FALSE;
    };

  LOG_DEBUG(app->logger, "%s: %s", pfw->name, N_("child event loop initialized"));

  if (pfw->af == AF_INET6)
    {
      struct sockaddr_in6 saddr6;
      gint opt;

      memset(&saddr6, 0, sizeof (struct sockaddr_in6));
      saddr6.sin6_family = AF_INET6;
      saddr6.sin6_port = htons(pfw->listen_port);

      if (strcmp(pfw->listen_ip, IPV6_ANY) == 0)
        saddr6.sin6_addr = in6addr_any;
      else
        inet_pton(AF_INET6, pfw->listen_ip, &saddr6.sin6_addr);

      pfw->fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
      if (pfw->fd < 0)
        {
          LOG_ERROR(app->logger, "%s: %s",
              pfw->name, N_("failed to create client socket"));

          return FALSE;
        }

      opt = 1;
      setsockopt(pfw->fd, SOL_SOCKET, SO_REUSEADDR, (const gchar *) &opt,
          sizeof(opt));

      if (bind(pfw->fd, (struct sockaddr *) &saddr6,
          sizeof(struct sockaddr_in6)) < 0)
        {
          LOG_ERROR(app->logger, "%s: %s",
              pfw->name, N_("failed to bind client socket"));

          return FALSE;
        }

      if (listen(pfw->fd, pfw->backlog) < 0)
        {
          LOG_ERROR(app->logger, "%s", N_("Failed to listen on client socket"));

          return FALSE;
        }

      fcntl(pfw->fd, F_SETFL, O_NONBLOCK);
    }
  else
    {
      struct sockaddr_in saddr4;
      gint opt;

      memset(&saddr4, 0, sizeof (struct sockaddr_in));
      saddr4.sin_family = AF_INET;
      saddr4.sin_port = htons(pfw->listen_port);

      if (strcmp(pfw->listen_ip, IPV4_ANY) == 0)
        saddr4.sin_addr.s_addr = INADDR_ANY;
      else
        inet_pton(AF_INET, pfw->listen_ip, &saddr4.sin_addr);

      pfw->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (pfw->fd < 0)
        {
          LOG_ERROR(app->logger, "%s: %s",
              pfw->name, N_("failed to create client socket"));

          return FALSE;
        }

      opt = 1;
      setsockopt(pfw->fd, SOL_SOCKET, SO_REUSEADDR, (const gchar *) &opt,
          sizeof(opt));

      if (bind(pfw->fd, (struct sockaddr *) &saddr4, sizeof(struct sockaddr_in))
          < 0)
        {
          LOG_ERROR(app->logger, "%s: %s",
              pfw->name, N_("failed to bind client socket"));

          return FALSE;
        }

      if (listen(pfw->fd, pfw->backlog) < 0)
        {
          LOG_ERROR(app->logger, "%s: %s",
              pfw->name, N_("failed to listen on client socket"));

          return FALSE;
        }

      fcntl(pfw->fd, F_SETFL, O_NONBLOCK);
    }

  pfw->w = g_new0(ev_io, 1);
  pfw->w->data = pfw;
  ev_io_init(pfw->w, accept_event, pfw->fd, EV_READ);
  LOG_DEBUG(app->logger, "%s: %s (pfw=%p)",
      pfw->name, N_("accept watcher created"), pfw);

  ev_io_start(pfw->ev_loop, pfw->w);
  LOG_DEBUG(app->logger,
      "%s: %s (fd=%d, event=EV_READ, data=%p)",
      pfw->name, N_("accept watcher started"),
      pfw->w->fd, pfw->w->data);

  if (pfw->af == AF_INET6)
    LOG_INFO(app->logger, "%s: %s ([%s]:%hu)",
        pfw->name, N_("socket is listening"), pfw->listen_ip, pfw->listen_port);
  else
    LOG_INFO(app->logger, "%s: %s (%s:%hu)",
        pfw->name, N_("socket is listening"), pfw->listen_ip, pfw->listen_port);

  ev_loop(pfw->ev_loop, 0);

  return TRUE;
}

static void
exit_main_loop(void)
{
  GSList *item;
  pfw_t *pfw;

  LOG_DEBUG(app->logger, "%s", N_("Exit main loop event"));

  for (item = app->pfwds; item; item = item->next)
    {
      pfw = (pfw_t *) item->data;

      ev_io_stop(pfw->ev_loop, pfw->w);
      LOG_DEBUG(app->logger, "%s: %s",
          pfw->name, N_("watcher stopped"));

      close(pfw->fd);

      g_free(pfw->w);
      LOG_DEBUG(app->logger, "%s: %s",
          pfw->name, N_("watcher cleaned"));

      if (pfw->af == AF_INET6)
        LOG_INFO(app->logger, "%s: %s [%s]:%hu",
            pfw->name, N_("socket closed"), pfw->listen_ip, pfw->listen_port);
      else
        LOG_INFO(app->logger, "%s: %s %s:%hu",
            pfw->name, N_("socket closed"), pfw->listen_ip, pfw->listen_port);

      ev_loop_destroy(pfw->ev_loop);
      LOG_DEBUG (app->logger, "%s: %s", pfw->name, N_("child event loop destroyed"));
    }

  ev_loop_destroy(EV_DEFAULT_UC);
  LOG_DEBUG(app->logger, "%s", N_("main event loop destroyed"));
}

static void
accept_event(EV_P_ ev_io *w, gint revents)
  {
    LOG_DEBUG(app->logger, "%s (fd=%d, data=%p)",
        N_("new accept event"), w->fd,w->data);

    pfw_t *pfw = (pfw_t *)w->data;
    if (pfw == NULL)
      {
        LOG_ERROR(app->logger, "%s", N_("no data found, ignoring event"));

        ev_io_stop(EV_DEFAULT_UC, w);
        LOG_DEBUG(app->logger, "%s", N_("watcher stopped"));

        g_free(w);

        return;
      }

    ev_io *c_w, *s_w;
    pfw_io_t *c_data, *s_data;
    gint c, s;
    gchar c_ip[IPV6_MAXLEN];
    short c_port;
    gchar *ip;

    if (pfw->af == AF_INET6)
      {
        struct sockaddr_in6 sin6;
        socklen_t len;
        gint opt;

        memset(&sin6, 0, sizeof (struct sockaddr_in6));
        len = sizeof(struct sockaddr_in6);

        c = accept(w->fd, (struct sockaddr *) &sin6, &len);
        if (c < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to accept new client"));

            return;
          }

        if (!inet_ntop(AF_INET6, &sin6.sin6_addr, c_ip, sizeof(c_ip)))
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to resolv client address"));

            close(c);

            return;
          }

        c_port = htons(sin6.sin6_port);

        ip = g_strdup_printf("[%s]", c_ip);
        if (!pfwd_check_access(pfw, c_ip))
          {
            LOG_INFO(app->logger, "%s: %s (%s)",
                pfw->name, N_("client address denied"), ip);

            g_free(ip);
            close(c);

            return;
          }

        LOG_INFO(app->logger, "%s: %s (%s)",
                        pfw->name, N_("client address allowed"), ip);

        g_free(ip);

        fcntl(c, F_SETFL, O_NONBLOCK);
        opt = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));

        s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to create server socket"));

            close(c);

            return;
          }

        memset(&sin6, 0, sizeof(struct sockaddr_in6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = INADDR_ANY;

        if (bind(s, (struct sockaddr *) &sin6, sizeof(struct sockaddr_in6)) < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to bind server socket"));

            close(s);
            close(c);

            return;
          }

        if (strcmp(pfw->forward_ip, IPV6_ANY) == 0)
        sin6.sin6_addr = in6addr_any;
        else
        inet_pton(AF_INET6, pfw->forward_ip, &sin6.sin6_addr);
        sin6.sin6_port = htons(pfw->forward_port);

        if (connect(s, (struct sockaddr *) &sin6,
                sizeof(struct sockaddr_in6)) < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to connect server socket"));

            close(s);
            close(c);

            return;
          }

        fcntl(s, F_SETFL, O_NONBLOCK);
        opt = 0;
        setsockopt(s, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
      }
    else
      {
        struct sockaddr_in sin4;
        socklen_t len;
        gint opt;

        memset(&sin4, 0, sizeof (struct sockaddr_in));
        len = sizeof(struct sockaddr_in);

        c = accept(w->fd, (struct sockaddr *) &sin4, &len);
        if (c < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to accept new client"));

            return;
          }

        if (!inet_ntop(AF_INET, &sin4.sin_addr, c_ip, sizeof(c_ip)))
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to resolv client address"));

            close(c);

            return;
          }

        c_port = htons(sin4.sin_port);

        ip = g_strdup_printf("%s", c_ip);
        if (!pfwd_check_access(pfw, c_ip))
          {
            LOG_INFO(app->logger, "%s: %s (%s)",
                pfw->name, N_("client address denied"), ip);

            g_free(ip);
            close(c);

            return;
          }

        LOG_INFO(app->logger, "%s: %s (%s)",
                        pfw->name, N_("client address allowed"), ip);

        g_free(ip);

        fcntl(c, F_SETFL, O_NONBLOCK);
        opt = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));

        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to create server socket"));

            close(c);

            return;
          }

        memset(&sin4, 0, sizeof(struct sockaddr_in));
        sin4.sin_family = AF_INET;
        sin4.sin_port = INADDR_ANY;

        if (bind(s, (struct sockaddr *) &sin4, sizeof(struct sockaddr_in)) < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to bind server socket"));

            close(s);
            close(c);

            return;
          }

        inet_pton(AF_INET, pfw->forward_ip, &(sin4.sin_addr));
        sin4.sin_port = htons(pfw->forward_port);

        if (connect(s, (struct sockaddr *) &sin4, sizeof(struct sockaddr_in))
            < 0)
          {
            LOG_ERROR(app->logger, "%s: %s",
                pfw->name, N_("failed to connect server socket"));

            close(s);
            close(c);

            return;
          }

        fcntl(s, F_SETFL, O_NONBLOCK);
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
    c_data->buf = g_new0(gchar, pfw->buf_size);
    LOG_DEBUG(app->logger, "%s: %s (c_fd=%d, s_fd=%d, buf=%p, buf_size=%d)",
        pfw->name, N_("client watcher created"), c_data->c_fd, c_data->s_fd,
        c_data->buf, pfw->buf_size);

    ev_io_init(c_w, read_event, c, EV_READ);
    ev_io_start(pfw->ev_loop, c_w);
    LOG_DEBUG(app->logger, "%s: %s (fd=%d, event=EV_READ, data=%p)",
        pfw->name, N_("client watcher started"),
        c_w->fd, c_w->data);

    s_w = g_new0(ev_io, 1);
    s_data = g_new0(pfw_io_t, 1);
    s_w->data = s_data;
    s_data->pfw = pfw;
    s_data->c_fd = c;
    g_strlcpy(s_data->c_ip, c_ip, sizeof(c_data->c_ip));
    s_data->c_port = c_port;
    s_data->s_fd = s;
    s_data->buf = g_new0(gchar, pfw->buf_size);
    LOG_DEBUG(app->logger, "%s: %s (c_fd=%d, s_fd=%d, buf=%p, buf_size=%d)",
        pfw->name, N_("server watcher created"), s_data->c_fd, s_data->s_fd,
        s_data->buf, pfw->buf_size);

    ev_io_init(s_w, read_event, s, EV_READ);
    ev_io_start(pfw->ev_loop, s_w);
    LOG_DEBUG(app->logger, "%s: %s (fd=%d, event=EV_READ, data=%p)",
        pfw->name, N_("server watcher started"), s_w->fd, s_w->data);

    if (pfw->af == AF_INET6)
    LOG_INFO(app->logger, "%s: %s ([%s]:%hu => [%s]:%hu)",
        pfw->name, N_("new client connection"),
        c_ip, c_port, pfw->forward_ip, pfw->forward_port);
    else
    LOG_INFO(app->logger, "%s: %s (%s:%hu => %s:%hu)",
        pfw->name, N_("new client connection"),
        c_ip, c_port, pfw->forward_ip, pfw->forward_port);
  }

static void
read_event(EV_P_ ev_io *w, gint revents)
  {
    LOG_DEBUG(app->logger, "%s (fd=%d, data=%p)",
        N_("new read event"), w->fd, w->data);

    gint n;

    pfw_io_t *pfw_io = (pfw_io_t *)w->data;
    if (pfw_io == NULL)
      {
        LOG_ERROR(app->logger, "%s", N_("no data found, ignoring event"));

        ev_io_stop(EV_DEFAULT_UC, w);
        LOG_DEBUG(app->logger, "%s", N_("watcher stopped"));

        g_free(w);

        return;
      }

    LOG_DEBUG(app->logger, "%s: %s (c_fd=%d, s_fd=%d)",
        pfw_io->pfw->name, N_("event data"), pfw_io->c_fd, pfw_io->s_fd);

    n = read(w->fd, pfw_io->buf, pfw_io->pfw->buf_size);
    LOG_DEBUG(app->logger, "%s: %s=%d", pfw_io->pfw->name, N_("bytes readed"), n);
  if (n <= 0)
    {
      ev_io_stop(pfw_io->pfw->ev_loop, w);
      LOG_DEBUG(app->logger, "%s: %s", pfw_io->pfw->name, N_("watcher stopped"));

      close(pfw_io->s_fd);
      close(pfw_io->c_fd);

      if (w->fd == pfw_io->c_fd)
        {
          if (pfw_io->pfw->af == AF_INET6)
            LOG_INFO(app->logger, "%s: %s ([%s]:%hu => [%s]:%hu)",
                pfw_io->pfw->name, N_("client connection closed"),
                pfw_io->c_ip, pfw_io->c_port, pfw_io->pfw->forward_ip,
                pfw_io->pfw->forward_port);
          else
            LOG_INFO(app->logger, "%s: %s (%s:%hu => %s:%hu)",
                pfw_io->pfw->name, N_("client connection closed"),
                pfw_io->c_ip, pfw_io->c_port, pfw_io->pfw->forward_ip,
                pfw_io->pfw->forward_port);
        }

      g_free(pfw_io->buf);
      g_free(pfw_io);
      g_free(w);

      return;
    }

  if (w->fd == pfw_io->c_fd)
    n = write(pfw_io->s_fd, pfw_io->buf, n);
  else
    n = write(pfw_io->c_fd, pfw_io->buf, n);
  LOG_DEBUG(app->logger, "%s: %s=%d", pfw_io->pfw->name, N_("bytes written"),
      n);
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
              LOG_DEBUG(app->logger, "%s (%s)",
                  N_("address matches deny rule"), ip);

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
              LOG_DEBUG(app->logger, "%s (%s)",
                  N_("address matches allow rule"), ip);

              return TRUE;
            }
        }
    }

  if (allow)
    {
      LOG_DEBUG(app->logger, "%s (%s)",
          N_("address matches default deny rule"), ip);

      return FALSE;
    }

  LOG_DEBUG(app->logger, "%s (%s)",
      N_("address matches default allow rule"), ip);

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
  gboolean ret;

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

  ret = g_option_context_parse(context, &argc, &argv, &error);

  help = g_option_context_get_help(context, TRUE, NULL);

  g_option_context_free(context);

  if (!ret)
    {
      g_print("%s", help);

      g_free(help);
      exit(1);
    }

  g_free(help);

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
  LOG_INFO(app->logger, "%s", N_("SIGPIPE received, continuing execution"));
}

void
sighup(gint sig)
{
  LOG_INFO(app->logger, "%s", N_("SIGHUP received, reloading configuration"));

  reload_config();
}

void
sigint(gint sig)
{
  LOG_INFO(app->logger, "%s", N_("SIGINT received, exiting"));

  exit(0);
}

void
sigterm(gint sig)
{
  LOG_INFO(app->logger, "%s", N_("SIGTERM received, exiting"));

  exit(0);
}

void
cleanup(void)
{
  gboolean daemon;
  GError *error = NULL;

  if (app && app->settings)
    {
      daemon = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_DAEMONIZE, &error);
      if (error)
        daemon = CONFIG_KEY_MAIN_DAEMONIZE_DEFAULT;
      if (daemon)
        {
          gchar *lock_file, *pid_file;
          lock_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
              CONFIG_KEY_MAIN_LOCKFILE, NULL);
          if (lock_file)
            {
              g_unlink(lock_file);
              g_free(lock_file);
            }
          pid_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
              CONFIG_KEY_MAIN_PIDFILE, NULL);
          if (pid_file)
            {
              g_unlink(pid_file);
              g_free(pid_file);
            }
        }
    }

  if (app->logger)
    log_message(app->logger, LOG_LEVEL_INFO, "%s %s", PACKAGE, N_("stopped"));

  if (app)
    {
      if (app->logger)
        log_destroy_logger(app->logger);

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
              g_free(pfw->listen_ip);
              g_free(pfw->forward_ip);
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
}

gint
main(gint argc, gchar *argv[])
{
  gboolean daemon;
  gint ret;
  GError *error = NULL;

  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, PACKAGE_LOCALE_DIR);
  textdomain(PACKAGE);

  g_thread_init(NULL);

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
      g_printerr("%s\n", "Failed to create logger");

      exit(-2);
    }

  daemon = g_key_file_get_boolean(app->settings, CONFIG_GROUP_MAIN,
      CONFIG_KEY_MAIN_DAEMONIZE, &error);
  if (error)
    daemon = CONFIG_KEY_MAIN_DAEMONIZE_DEFAULT;
  if (daemon)
    {
      gchar *lock_file, *pid_file, *user, *group;

      lock_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_LOCKFILE, NULL);
      if (!lock_file)
        lock_file = g_strdup(CONFIG_KEY_MAIN_LOCKFILE_DEFAULT);

      pid_file = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_PIDFILE, NULL);

      if (!pid_file)
        pid_file = g_strdup(CONFIG_KEY_MAIN_PIDFILE_DEFAULT);

      user = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_USER, NULL);
      if (!user)
        user = g_strdup(CONFIG_KEY_MAIN_USER_DEFAULT);

      group = g_key_file_get_string(app->settings, CONFIG_GROUP_MAIN,
          CONFIG_KEY_MAIN_GROUP, NULL);
      if (!group)
        group = g_strdup(CONFIG_KEY_MAIN_GROUP_DEFAULT);

      ret = daemonize(lock_file, pid_file, user, group);

      g_free(lock_file);
      g_free(pid_file);
      g_free(user);
      g_free(group);

      if (ret < 0)
        {
          log_message(app->logger, LOG_LEVEL_ERROR, "%s: %d",
              N_("Failed to daemonize, error code"), ret);

          exit(-4);
        }
    }

  signal(SIGPIPE, sigpipe);
  signal(SIGHUP, sighup);
  signal(SIGINT, sigint);
  signal(SIGTERM, sigterm);

  log_message(app->logger, LOG_LEVEL_INFO, "%s %s", PACKAGE, N_("started"));

  if (!run_main_loop())
    exit(-5);

  return 0;
}
