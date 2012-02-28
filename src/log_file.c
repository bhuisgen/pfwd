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
#include "log_file.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void
_log_handler_file_init(handler_t *handler)
{
}

void
_log_handler_file_cleanup(handler_t *handler)
{
}

void
_log_handler_file_message(handler_t *handler, LogLevel level,
    const char *message)
{
  time_t t;
  struct tm *tm;
  const char *l;
  char *logfile;
  FILE *fd;

  logfile = log_handler_get_option(handler, LOG_HANDLER_FILE_OPTION_LOGFILE);
  if (!logfile)
    return;

  time(&t);
  tm = localtime(&t);

  l = log_get_level_name(level);

  fd = fopen(logfile, "a");
  if (!fd)
    return;

  fprintf(fd, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n", tm->tm_year + 1900,
      tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, l, message);

  fclose(fd);
}
