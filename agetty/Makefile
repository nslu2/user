# Makefile for agetty

EXEC = agetty
OBJS = agetty.o
CFLAGS += -D__USE_BSD

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	arm-linux-strip agetty

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	rm -f $(EXEC) *.gdb *.elf *.o
