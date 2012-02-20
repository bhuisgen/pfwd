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

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>

char *
strdup_printf(const char *format, ...)
{
  char* buffer;

  va_list ap;
  va_start(ap, format);

  buffer = strdup_vprintf(format, ap);

  va_end(ap);

  return buffer;
}

char *
strdup_vprintf(const char *format, va_list args)
{
  va_list args2;
  int size;
  char *buffer;

  va_copy(args2, args);
  size = vsnprintf(NULL, 0, format, args2) + 1;
  va_end(args2);

  buffer = malloc(size + 1);
  if (!buffer)
    return NULL;

  vsnprintf(buffer, size, format, args);

  return (buffer);
}
