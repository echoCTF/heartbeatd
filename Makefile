PROG=	heartbeatd
SRCS=	heartbeatd.c
CFLAGS+= -I/usr/local/include
LDADD+= -lpcap -lcrypto -L/usr/local/lib -lmemcached
MAN =

.include <bsd.prog.mk>
