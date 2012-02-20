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

#include "log.h"
#include "log_syslog.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

extern char *__progname;

static struct
{
  const char *name;
  LogSyslogFacility facility;
} log_syslog_facilities[] =
  {
    { "DAEMON", LOG_SYSLOG_FACILITY_DAEMON },
    { "USER", LOG_SYSLOG_FACILITY_USER },
    { "LOCAL0", LOG_SYSLOG_FACILITY_LOCAL0 },
    { "LOCAL1", LOG_SYSLOG_FACILITY_LOCAL1 },
    { "LOCAL2", LOG_SYSLOG_FACILITY_LOCAL2 },
    { "LOCAL3", LOG_SYSLOG_FACILITY_LOCAL3 },
    { "LOCAL4", LOG_SYSLOG_FACILITY_LOCAL4 },
    { "LOCAL5", LOG_SYSLOG_FACILITY_LOCAL5 },
    { "LOCAL6", LOG_SYSLOG_FACILITY_LOCAL6 },
    { "LOCAL7", LOG_SYSLOG_FACILITY_LOCAL7 } };

handler_t *
log_handler_syslog_create()
{
  handler_t *handler = malloc(sizeof(handler_t));
  if (!handler)
    return NULL;

  memset (handler, 0, sizeof(handler_t));

  handler->type = LOG_HANDLER_TYPE_SYSLOG;
  handler->options = NULL;

  return handler;
}

void
_log_handler_syslog_init(handler_t *handler)
{
  char *facility_name;
  LogSyslogFacility syslog_facility;
  char *ident;
  int logopt, facility;

  ident = log_handler_get_option(handler, LOG_HANDLER_SYSLOG_OPTION_IDENT);
  if (!ident)
    ident = __progname;

  logopt = 0;
  if (log_handler_is_option_enabled(handler, LOG_HANDLER_SYSLOG_OPTION_LOG_CONS)
      == 1)
    logopt |= LOG_CONS;
  if (log_handler_is_option_enabled(handler,
      LOG_HANDLER_SYSLOG_OPTION_LOG_NDELAY) == 1)
    logopt |= LOG_NDELAY;
  if (log_handler_is_option_enabled(handler,
      LOG_HANDLER_SYSLOG_OPTION_LOG_PERROR) == 1)
    logopt |= LOG_PERROR;
  if (log_handler_is_option_enabled(handler, LOG_HANDLER_SYSLOG_OPTION_LOG_PID)
      == 1)
    logopt |= LOG_PID;
  if (!logopt)
    logopt = LOG_PID;

  facility_name = log_handler_get_option(handler,
      LOG_HANDLER_SYSLOG_OPTION_FACILITY);

  if (facility_name)
    syslog_facility = _log_handler_syslog_get_facility_number(facility_name);
  else
    syslog_facility = LOG_SYSLOG_FACILITY_DAEMON;

  switch (syslog_facility)
    {
  case LOG_SYSLOG_FACILITY_DAEMON:
    facility = LOG_DAEMON;
    break;

  case LOG_SYSLOG_FACILITY_USER:
    facility = LOG_USER;
    break;

  case LOG_SYSLOG_FACILITY_AUTH:
    facility = LOG_AUTH;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL0:
    facility = LOG_LOCAL0;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL1:
    facility = LOG_LOCAL1;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL2:
    facility = LOG_LOCAL2;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL3:
    facility = LOG_LOCAL3;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL4:
    facility = LOG_LOCAL4;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL5:
    facility = LOG_LOCAL5;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL6:
    facility = LOG_LOCAL6;
    break;

  case LOG_SYSLOG_FACILITY_LOCAL7:
    facility = LOG_LOCAL7;
    break;

  default:
    facility = LOG_DAEMON;
    break;
    }

  openlog(ident, logopt, facility);
}

void
_log_handler_syslog_cleanup(handler_t *handler)
{
  closelog();

  _log_handler_free_options(handler);
}

LogSyslogFacility
_log_handler_syslog_get_facility_number(char *name)
{
  unsigned int i;

  if (name)
    {
      for (i = 0; log_syslog_facilities[i].name; i++)
        {
          if (strcmp(log_syslog_facilities[i].name, name) == 0)
            return log_syslog_facilities[i].facility;
        }
    }

  return -1;
}

const char *
_log_handler_syslog_get_facility_name(LogSyslogFacility facility)
{
  unsigned int i;

  for (i = 0; log_syslog_facilities[i].name; i++)
    {
      if (log_syslog_facilities[i].facility == facility)
        return log_syslog_facilities[i].name;
    }

  return NULL;
}

void
_log_handler_syslog_message(handler_t *handler, LogLevel level,
    const char *message)
{
  int priority;

  switch (level)
    {
  case LOG_LEVEL_EMERGENCY:
  case LOG_LEVEL_ALERT:
  case LOG_LEVEL_CRITICAL:
    priority = LOG_CRIT;
    break;

  case LOG_LEVEL_ERROR:
    priority = LOG_ERR;
    break;

  case LOG_LEVEL_WARNING:
  case LOG_LEVEL_NOTICE:
  case LOG_LEVEL_INFO:
    priority = LOG_INFO;
    break;

  case LOG_LEVEL_DEBUG:
    priority = LOG_DEBUG;
    break;

  default:
    priority = LOG_INFO;
    break;
    }

  syslog(priority, "%s", message);
}
