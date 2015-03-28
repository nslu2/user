
EXEC = ftp
OBJS = cmds.o cmdtab.o domacro.o ftp.o glob.o main.o ruserpass.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	arm-linux-strip ftp
romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o

