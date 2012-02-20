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

#include "common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
daemonize(const char *lock_file, const char *pid_file, const char *user,
    const char *group)
{
  if (getppid() == 1)
    return 0;

  pid_t pid, sid;
  int fd;
  int ret;
  char str_pid[12];

  if (lock_file)
    {
      fd = open(lock_file, O_RDWR | O_CREAT, 0644);
      if (fd < 0)
        return (-1);

      ret = lockf(fd, F_TEST, 0);
      close(fd);
      if (ret != 0)
        return (-2);
    }

  pid = fork();
  if (pid < 0)
    return (-3);
  if (pid > 0)
    exit(EXIT_SUCCESS);

  signal(SIGCHLD, SIG_DFL);
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGTERM, SIG_DFL);

  umask(022);

  sid = setsid();
  if (sid < 0)
    return (-4);

  if (chdir("/tmp") < 0)
    return (-5);

  if (!freopen("/dev/null", "r", stdin))
    perror("freopen");

  if (!freopen("/dev/null", "w", stdout))
    perror("freopen");

  if (!freopen("/dev/null", "w", stderr))
    perror("freopen");

  if (user && group && ((getuid() == 0) || (geteuid() == 0)))
    {
      struct passwd *pwd;
      struct group *grp;

      pwd = getpwnam(user);
      if (!pwd)
        return (-6);

      grp = getgrnam(group);
      if (!grp)
        return (-7);

      if ((setregid(grp->gr_gid, grp->gr_gid) != 0) || (setreuid(pwd->pw_uid,
          pwd->pw_uid) != 0))
        return (-8);
    }

  if (lock_file)
    {
      fd = open(lock_file, O_RDWR | O_CREAT, 0644);
      if (fd < 0)
        return (-9);

      ret = lockf(fd, F_TLOCK, 0);
      if (ret != 0)
        return (-10);
    }

  if (pid_file)
    {
      fd = open(pid_file, O_RDWR | O_CREAT, 0644);
      if (fd < 0)
        return (-11);

      snprintf(str_pid, 12, "%d\n", pid);
      ret = write(fd, str_pid, strlen(str_pid));
      close(fd);
      if (ret < 0)
        return (-12);
    }

  return (0);
}
