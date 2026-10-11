PROG=	heartbeatd
SRCS=	heartbeatd.c
CFLAGS+= -I/usr/local/include
LDADD+= -lpcap -lcrypto -L/usr/local/lib -lmemcached
MAN =

BINDIR?=	/usr/local/sbin
RCDIR?=		/etc/rc.d

afterinstall:
	${INSTALL} ${INSTALL_COPY} -o root -g wheel -m 555 \
	    ${.CURDIR}/${PROG}.rc ${DESTDIR}${RCDIR}/${PROG}

.include <bsd.prog.mk>
