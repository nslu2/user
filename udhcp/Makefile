# udhcp makefile

# Uncomment this to get a shared binary. Call as udhcpd for the server,
# and udhcpc for the client
# COMBINED_BINARY=1

VER := 0.9.6

# Uncomment this to output messages to stdout.
# CFLAGS += -DSYSLOG

CFLAGS += -DVERSION='"$(VER)"'

OBJS_SHARED = options.o socket.o packet.o pidfile.o
#DHCPD_OBJS = dhcpd.o arpping.o files.o leases.o serverpacket.o
DHCPC_OBJS = dhcpc.o clientpacket.o script.o arpping.o

EXEC1 = #udhcpd
OBJS1 = #$(DHCPD_OBJS) $(OBJS_SHARED)

EXEC2 = udhcpc
OBJS2 = $(DHCPC_OBJS) $(OBJS_SHARED)

EXEC3 = #dumpleases
OBJS3 = #dumpleases.o


all: $(EXEC2) #$(EXEC1) $(EXEC3)

$(OBJS1) $(OBJS2) $(OBJS3): *.h Makefile
$(EXEC1) $(EXEC2) $(EXEC3): Makefile

#$(EXEC1): $(OBJS1)
#	$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDLIBS)

$(EXEC2): $(OBJS2)
	$(CC) $(LDFLAGS) -o $@ $(OBJS2) $(LDLIBS)
	arm-linux-strip udhcpc

#$(EXEC3): $(OBJS3)
#	$(CC) $(LDFLAGS) -o $@ $(OBJS3) $(LDLIBS)

romfs:
#	$(ROMFSINST) /bin/$(EXEC1)
	$(ROMFSINST) /sbin/$(EXEC2)
#	$(ROMFSINST) /bin/$(EXEC3)

clean:
	rm -f ${EXEC1} ${EXEC2} ${EXEC3} *.o core

