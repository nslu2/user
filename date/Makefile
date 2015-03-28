PROG=	date
SRCS=	date.c
#SRCS += strftime.c localtime.c asctime.c
CFLAGS += -I . -I.. -I ./lib -DLOCALEDIR=\"usr/local/locale\" -DHAVE_CONFIG_H
#---------------
OBJS	+= ${SRCS:.c=.o}
#---------------
all:	dir ${PROG}
#---------------

dir:
	make -C lib ||exit 1;

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $^

${PROG}: ${OBJS}
	${CC} $(LDFLAGS) -o ${PROG} ${OBJS} -L ./lib -lfetish ${LDLIBS}
	arm-linux-strip date
#---------------
clean:
	rm -f lib/*.o *.o ${PROG}
	rm -f lib/libfetish*
#---------------
romfs: 
	$(ROMFSINST) ./lib/libfetish.so.0.0 /lib
	$(ROMFSINST) -s libfetish.so.0.0 /lib/libfetish.so.0
	$(ROMFSINST) -s libfetish.so.0 /lib/libfetish.so
	$(ROMFSINST) date /bin/date
	$(ROMFSINST) date /usr/sbin
#---------------
# End of Makefile
