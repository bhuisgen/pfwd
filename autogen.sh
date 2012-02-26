#!/bin/sh

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
   echo
   echo "**Error**: You must have \`autoconf' installed to."
   echo "Download the appropriate package for your distribution,"
   echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
   exit;
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
   echo
   echo "**Error**: You must have \`automake' installed to."
   echo "Download the appropriate package for your distribution,"
   echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
   exit;
}

echo "Generating configuration files, please wait..."
echo;
gettextize -c;
aclocal -I m4;
autoheader;
automake -a -c;
autoconf
