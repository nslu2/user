
EXEC = crond

all: $(EXEC)

crond: cron.o cron-parent.o bitstring.h Makefile
	$(CC) $(LDFLAGS) -o $@ cron.o cron-parent.o $(LDLIBS$(LDLIBS_$@))
	arm-linux-strip crond

romfs:
	$(ROMFSINST) crond /usr/sbin/crond

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
