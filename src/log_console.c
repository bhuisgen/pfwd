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

/*
 * $Id$
 */

#include "log.h"
#include "log_console.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

handler_t *
log_handler_console_create()
{
  handler_t *handler = malloc (sizeof(handler_t));
  if (!handler)
    return NULL;

  memset (handler, 0, sizeof(handler_t));

  handler->type = LOG_HANDLER_TYPE_CONSOLE;
  handler->options = NULL;

  return handler;
}

void
_log_handler_console_init(handler_t *handler)
{
}

void
_log_handler_console_cleanup(handler_t *handler)
{
  _log_handler_free_options(handler);
}

void
_log_handler_console_message(handler_t *handler, LogLevel level,
    const char *message)
{
  time_t t;
  struct tm *tm;
  const char *l;
  FILE *fd;

  time(&t);
  tm = localtime(&t);

  l = log_get_level_name(level);

  if (log_handler_is_option_enabled(handler,
      LOG_HANDLER_CONSOLE_OPTION_LOGALLTOSTDERR) == 1)
    fd = stderr;
  else if (log_handler_is_option_enabled(handler,
      LOG_HANDLER_CONSOLE_OPTION_LOGALLTOSTDOUT) == 1)
    fd = stdout;
  else if (level <= LOG_LEVEL_ERROR)
    fd = stderr;
  else
    fd = stdout;

  fprintf(fd, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n", tm->tm_year + 1900,
      tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, l, message);
}
