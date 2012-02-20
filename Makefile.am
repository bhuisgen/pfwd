SUBDIRS = src po doc

pfwd_docdir = @PACKAGE_DOC_DIR@

pfwd_doc_DATA = AUTHORS COPYING ChangeLog INSTALL NEWS README

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = config.rpath m4/ChangeLog

dist-hook:

bzdist: dist
	gunzip -c $(distdir).tar.gz | bzip2 > $(distdir).tar.bz2;
