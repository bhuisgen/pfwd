/*
 * pfwd - a port forwarding tool
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

#ifndef LOG_H_
#define LOG_H_

typedef enum
{
  LOGGER_LEVEL_NONE = 0,
  LOGGER_LEVEL_EMERGENCY = 10,
  LOGGER_LEVEL_ALERT = 20,
  LOGGER_LEVEL_CRITICAL = 30,
  LOGGER_LEVEL_ERROR = 40,
  LOGGER_LEVEL_WARNING = 50,
  LOGGER_LEVEL_NOTICE = 60,
  LOGGER_LEVEL_INFO = 70,
  LOGGER_LEVEL_DEBUG = 80,
  LOGGER_LEVEL_ALL = 100
} LoggerLevel;

typedef enum
{
  LOG_LEVEL_EMERGENCY = 0,
  LOG_LEVEL_ALERT = 1,
  LOG_LEVEL_CRITICAL = 2,
  LOG_LEVEL_ERROR = 3,
  LOG_LEVEL_WARNING = 4,
  LOG_LEVEL_NOTICE = 5,
  LOG_LEVEL_INFO = 6,
  LOG_LEVEL_DEBUG = 7,
} LogLevel;

typedef struct _handler_option_t
{
  char *name;
  char *value;
  struct _handler_option_t *next;
} handler_option_t;

typedef struct _handler_t
{
  unsigned int type;
  handler_option_t *options;
} handler_t;

#define LOG_HANDLER_TYPE_CONSOLE        0
#define LOG_HANDLER_TYPE_FILE           1
#define LOG_HANDLER_TYPE_SYSLOG         2

typedef struct _logger_t
{
  handler_t *handler;
  LoggerLevel level;
} logger_t;


handler_t *
log_handler_create();
void
log_handler_destroy(handler_t *handler);
char *
log_handler_get_option(handler_t *handler, const char *name);
int
log_handler_set_option(handler_t *handler, const char *name, const char *value);
int
log_handler_is_option_enabled(handler_t *handler, const char *name);
int
log_handler_is_option_disabled(handler_t *handler, const char *name);
logger_t *
log_create_logger(handler_t *handler, LoggerLevel level);
void
log_destroy_logger(logger_t *logger);
LogLevel
log_get_level_number(char *name);
const char *
log_get_level_name(LogLevel level);
void
log_message(logger_t *logger, LogLevel level, const char *format, ...);

#endif /* LOG_H_ */
