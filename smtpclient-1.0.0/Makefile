
OBJS = smtpclient_main.o smtpclient_getopt.o smtpclient_errno.o smtpclient_vers.o dns.o

LIBS = -lresolv

all: smtpclient

smtpclient: $(OBJS)
	${CC} $(LDFLAGS) -o smtpclient ${OBJS} $(LIBS) $(LDLIBS)
	arm-linux-strip smtpclient

romfs:
	$(ROMFSINST) /usr/sbin/smtpclient

clean:
	rm -f *.[oa] *.elf *~ core smtpclient *.gdb

