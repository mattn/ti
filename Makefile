SRCS=	ti.c
PROG=	ti

CPPFLAGS+=	`pkg-config --cflags libcurl`
LDADD+=		`pkg-config --libs libcurl` -lexpat

.include <bsd.prog.mk>
