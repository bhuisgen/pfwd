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

#ifndef LOG_FILE_H_
#define LOG_FILE_H_

#define LOG_HANDLER_FILE_OPTION_LOGFILE                 "FileHandler.LogFile"

void
_log_handler_file_init(handler_t *handler);
void
_log_handler_file_cleanup(handler_t *handler);
void
_log_handler_file_message(handler_t *handler, LogLevel level, const char *message);

#endif /* LOG_FILE_H_ */
