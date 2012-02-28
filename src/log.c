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
#include "log_console.h"
#include "log_file.h"
#include "log_syslog.h"
#include "utils.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct
{
  const char *name;
  LogLevel level;
} log_levels[] =
  {
    { "EMERGENCY", LOG_LEVEL_EMERGENCY },
    { "ALERT", LOG_LEVEL_ALERT },
    { "CRITICAL", LOG_LEVEL_CRITICAL },
    { "ERROR", LOG_LEVEL_ERROR },
    { "WARNING", LOG_LEVEL_WARNING },
    { "NOTICE", LOG_LEVEL_NOTICE },
    { "INFO", LOG_LEVEL_INFO },
    { "DEBUG", LOG_LEVEL_DEBUG }, };

void
_log_handler_free_options(handler_t *handler);

handler_t *
log_handler_create(int type)
{
  handler_t *handler = malloc(sizeof(handler_t));
  if (!handler)
    return NULL;

  memset (handler, 0, sizeof(handler_t));

  handler->type = type;
  handler->options = NULL;

  return handler;
}

void
log_handler_destroy(handler_t *handler)
{
  _log_handler_free_options(handler);
  free(handler);
}

char *
log_handler_get_option(handler_t *handler, const char *name)
{
  handler_option_t *option = NULL;
  char *value = NULL;

  for (option = handler->options; option; option = option->next)
    {
      if (strcmp(option->name, name) == 0)
        {
          value = option->value;

          break;
        }
    }

  return value;
}

int
log_handler_set_option(handler_t *handler, const char *name, const char *value)
{
  handler_option_t *option;
  int ret = -1;

  option = handler->options;

  do
    {
      if (!option)
        {
          option = malloc(sizeof(handler_option_t));
          if (!option)
            break;

          memset(option, 0, sizeof (handler_option_t));

          option->name = strdup(name);
          if (!option->name)
            {
              free(option);

              break;
            }

          option->value = strdup(value);
          if (!option->value)
            {
              free(option->name);
              free(option);

              break;
            }

          option->next = NULL;

          if (!handler->options)
            handler->options = option;

          ret = 0;

          break;
        }

      if (strcmp(option->name, name) == 0)
        {
          if (option->value)
            free(option->value);

          option->value = strdup(value);

          ret = 0;

          break;
        }
    }
  while ((option = option->next));

  return ret;
}

int
log_handler_is_option_enabled(handler_t *handler, const char *name)
{
  char *value;

  value = log_handler_get_option(handler, name);
  if (!value)
    return -1;

  if ((strcasecmp(value, "yes") == 0) || (strcasecmp(value, "on") == 0)
      || (strcasecmp(value, "1") == 0))
    return 1;

  return 0;
}

int
log_handler_is_option_disabled(handler_t *handler, const char *name)
{
  char *value;

  value = log_handler_get_option(handler, name);
  if (!value)
    return -1;

  if ((strcasecmp(value, "no") == 0) || (strcasecmp(value, "off") == 0)
      || (strcasecmp(value, "0") == 0))
    return 1;

  return 0;
}

void
_log_handler_free_options(handler_t *handler)
{
  handler_option_t *option, *next;

  option = handler->options;

  while (option)
    {
      next = option->next;

      free(option->name);
      free(option->value);
      free(option);

      option = next;
    }

  handler->options = NULL;
}

logger_t *
log_create_logger(handler_t *handler, LoggerLevel level)
{
  logger_t *logger;

  logger = malloc(sizeof(logger_t));
  if (!logger)
    return NULL;

  memset(logger, 0, sizeof(logger_t));

  logger->handler = handler;
  logger->level = level;

  switch (handler->type)
    {
  case LOG_HANDLER_TYPE_CONSOLE:
    {
      _log_handler_console_init(handler);

      break;
    }
  case LOG_HANDLER_TYPE_FILE:
    {
      _log_handler_file_init(handler);

      break;
    }
  case LOG_HANDLER_TYPE_SYSLOG:
    {
      _log_handler_syslog_init(handler);

      break;
    }
  default:
    {
      free(logger);
      logger = NULL;

      break;
    }
    }

  return logger;
}

void
log_destroy_logger(logger_t *logger)
{
  switch (logger->handler->type)
    {
  case LOG_HANDLER_TYPE_CONSOLE:
    {
      _log_handler_console_cleanup(logger->handler);

      break;
    }
  case LOG_HANDLER_TYPE_FILE:
    {
      _log_handler_file_cleanup(logger->handler);

      break;
    }
  case LOG_HANDLER_TYPE_SYSLOG:
    {
      _log_handler_syslog_cleanup(logger->handler);

      break;
    }
  default:
    {
      break;
    }
    }

  log_handler_destroy(logger->handler);

  free(logger);
}

LogLevel
log_get_level_number(char *name)
{
  unsigned int i;

  if (name)
    {
      for (i = 0; log_levels[i].name; i++)
        {
          if (strcmp(log_levels[i].name, name) == 0)
            return log_levels[i].level;
        }

    }

  return -1;
}

const char *
log_get_level_name(LogLevel level)
{
  unsigned int i;

  for (i = 0; log_levels[i].name; i++)
    {
      if (log_levels[i].level == level)
        return log_levels[i].name;
    }

  return NULL;
}

void
log_message(logger_t *logger, LogLevel level, const char *format, ...)
{
  va_list list;
  char *message;

  if (!logger->handler || (logger->level == LOGGER_LEVEL_NONE))
    return;

  switch (level)
    {
  case LOG_LEVEL_EMERGENCY:
    {
      if (logger->level < LOGGER_LEVEL_EMERGENCY)
        return;

      break;
    }

  case LOG_LEVEL_ALERT:
    {
      if (logger->level < LOGGER_LEVEL_ALERT)
        return;

      break;
    }

  case LOG_LEVEL_CRITICAL:
    {
      if (logger->level < LOGGER_LEVEL_CRITICAL)
        return;

      break;
    }

  case LOG_LEVEL_ERROR:
    {
      if (logger->level < LOGGER_LEVEL_ERROR)
        return;

      break;
    }

  case LOG_LEVEL_WARNING:
    {
      if (logger->level < LOGGER_LEVEL_WARNING)
        return;

      break;
    }

  case LOG_LEVEL_NOTICE:
    {
      if (logger->level < LOGGER_LEVEL_NOTICE)
        return;

      break;
    }

  case LOG_LEVEL_INFO:
    {
      if (logger->level < LOGGER_LEVEL_INFO)
        return;

      break;
    }

  case LOG_LEVEL_DEBUG:
    {
      if (logger->level < LOGGER_LEVEL_DEBUG)
        return;

      break;
    }
    }

  va_start(list, format);
  message = strdup_vprintf(format, list);
  if (!message)
    return;
  va_end(list);

  switch (logger->handler->type)
    {
  case LOG_HANDLER_TYPE_CONSOLE:
    _log_handler_console_message(logger->handler, level, message);
    break;

  case LOG_HANDLER_TYPE_FILE:
    _log_handler_file_message(logger->handler, level, message);
    break;

  case LOG_HANDLER_TYPE_SYSLOG:
    _log_handler_syslog_message(logger->handler, level, message);
    break;

  default:
    break;
    }

  free(message);
}
