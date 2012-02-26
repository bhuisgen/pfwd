/*
 * fmond - file monitoring daemon
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

#include "common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
daemonize(const char *pid_file, const char *user, const char *group)
{
  pid_t pid, ppid, sid;
  int fd;
  int ret;
  char str_pid[12];

  if (getppid() == 1)
    return 0;

  if (user && group && ((getuid() == 0) || (geteuid() == 0)))
    {
      struct passwd *pwd;
      struct group *grp;

      pwd = getpwnam(user);
      if (!pwd)
        return (-1);

      grp = getgrnam(group);
      if (!grp)
        return (-2);

      if ((setregid(grp->gr_gid, grp->gr_gid) != 0) || (setreuid(pwd->pw_uid,
          pwd->pw_uid) != 0))
        return (-3);
    }

  pid = fork();
  if (pid < 0)
    return (-4);
  if (pid > 0)
    exit(EXIT_SUCCESS);

  ppid = getppid();

  signal(SIGCHLD, SIG_DFL);
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGTERM, SIG_DFL);

  umask(022);

  sid = setsid();
  if (sid < 0)
    return (-5);

  if (chdir("/tmp") < 0)
    return (-6);

  if (!freopen("/dev/null", "r", stdin))
    perror("freopen");

  if (!freopen("/dev/null", "w", stdout))
    perror("freopen");

  if (!freopen("/dev/null", "w", stderr))
    perror("freopen");

  if (pid_file)
    {
      fd = open(pid_file, O_RDWR | O_CREAT | O_EXCL, 0640);
      if (fd < 0)
        return (-7);

      snprintf(str_pid, 12, "%d\n", getpid());
      ret = write(fd, str_pid, strlen(str_pid));
      close(fd);
      if (ret < 0)
        return (-8);
    }

  return (0);
}
