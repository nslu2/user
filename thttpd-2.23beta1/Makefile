
EXEC = thttpd
OBJS = thttpd.o libhttpd.o fdwatch.o mmc.o timers.o match.o \
	tdate_parse.o


CFLAGS += -DHAVE__PROGNAME=1 -DHAVE_FCNTL_H=1 -DHAVE_GRP_H=1 -DHAVE_MEMORY_H=1 -DHAVE_PATHS_H=1 -DHAVE_POLL_H=1 -DHAVE_SYS_POLL_H=1 -DTIME_WITH_SYS_TIME=1 -DHAVE_DIRENT_H=1 -DHAVE_LIBCRYPT=1 -DHAVE_STRERROR=1 -DHAVE_WAITPID=1 -DHAVE_VSNPRINTF=1 -DHAVE_DAEMON=1 -DHAVE_SETSID=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DHAVE_GAI_STRERROR=1 -DHAVE_UNISTD_H=1 -DHAVE_GETPAGESIZE=1 -DHAVE_SELECT=1 -DHAVE_POLL=1 -DHAVE_TM_GMTOFF=1 -DHAVE_SOCKADDR_STORAGE=1 -DHAVE_SOCKADDR_IN6=1 -D_FILE_OFFSET_BITS=64 -D_LINKSYS_ -DHAVE_MMAP=1
CFLAGS += -I../library/include

LIBS =	-L ../library/lib -lcrypt  -lfilesharing -lprofile -lsamba -lhd -lnetwork -llog -lschl # -lsetled -lleds -lbuzzer
all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS) $(LDLIBS)
	arm-linux-strip thttpd

romfs:
	$(ROMFSINST) /usr/sbin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.io *.bak *.o

thttpd.o:	config.h version.h libhttpd.h fdwatch.h mmc.h timers.h match.h
libhttpd.o:	config.h version.h libhttpd.h \
		mmc.h timers.h match.h tdate_parse.h
fdwatch.o:	fdwatch.h
mmc.o:		mmc.h libhttpd.h
timers.o:	timers.h
match.o:	match.h
tdate_parse.o:	tdate_parse.h
