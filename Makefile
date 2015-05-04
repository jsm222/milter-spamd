# $Id: Makefile,v 1.1.1.1 2007/01/11 15:53:57 dhartmei Exp $

PROG=	milter-spamd
SRCS=	milter-spamd.c
MAN=	milter-spamd.8

CFLAGS+=	-Wall -Wstrict-prototypes -g
CFLAGS+=	-I/usr/src/gnu/usr.sbin/sendmail/include
LDADD+=		-lmilter -lpthread

.include <bsd.prog.mk>

.if defined(WANT_LDAP)
LDADD+=		-L/usr/local/lib -lldap_r -llber
.endif
