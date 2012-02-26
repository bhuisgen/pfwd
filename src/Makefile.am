prefix = @prefix@
datadir = @datadir@
docdir = @docdir@
localedir = $(datadir)/locale
sysconfdir = @sysconfdir@

DEFS = \
	-DPREFIX=\"$(prefix)\" \
	-DLOCALEDIR=\"$(localedir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	@DEFS@

INCLUDES = \
	${DEPS_CFLAGS}

sbin_PROGRAMS = \
	pfwd

noinst_HEADERS = \
	common.h \
	daemon.h \
	gettext.h \
	log.h \
	log_console.h \
	log_file.h \
	log_syslog.h \
	pfwd.h \
	utils.h

pfwd_SOURCES = \
	daemon.c \
	log.c \
	log_console.c \
	log_file.c \
	log_syslog.c \
	pfwd.c \
	utils.c

pfwd_LDADD = \
    $(DEPS_LIBS) \
	$(INTLLIBS)

EXTRA_DIST = \
	$(pfwd_SOURCES)
