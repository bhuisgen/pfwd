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

#ifndef LOG_SYSLOG_H_
#define LOG_SYSLOG_H_

#define LOG_HANDLER_SYSLOG_OPTION_IDENT         "SyslogHandler.Ident"
#define LOG_HANDLER_SYSLOG_OPTION_FACILITY      "SyslogHandler.Facility"
#define LOG_HANDLER_SYSLOG_OPTION_LOG_CONS      "SyslogHandler.LogToConsole"
#define LOG_HANDLER_SYSLOG_OPTION_LOG_NDELAY    "SyslogHandler.LogWithNoDelay"
#define LOG_HANDLER_SYSLOG_OPTION_LOG_PERROR    "SyslogHandler.LogToErrorStream"
#define LOG_HANDLER_SYSLOG_OPTION_LOG_PID       "SyslogHandler.LogWithPID"

typedef enum
{
  LOG_SYSLOG_FACILITY_DAEMON,
  LOG_SYSLOG_FACILITY_USER,
  LOG_SYSLOG_FACILITY_AUTH,
  LOG_SYSLOG_FACILITY_LOCAL0,
  LOG_SYSLOG_FACILITY_LOCAL1,
  LOG_SYSLOG_FACILITY_LOCAL2,
  LOG_SYSLOG_FACILITY_LOCAL3,
  LOG_SYSLOG_FACILITY_LOCAL4,
  LOG_SYSLOG_FACILITY_LOCAL5,
  LOG_SYSLOG_FACILITY_LOCAL6,
  LOG_SYSLOG_FACILITY_LOCAL7,
} LogSyslogFacility;

void
_log_handler_syslog_init(handler_t *handler);
void
_log_handler_syslog_cleanup(handler_t *handler);
LogSyslogFacility
_log_handler_syslog_get_facility_number(char *name);
const char *
_log_handler_syslog_get_facility_name(LogSyslogFacility facility);
void
_log_handler_syslog_message(handler_t *handler, LogLevel level,
    const char *message);

#endif /* LOG_SYSLOG_H_ */
