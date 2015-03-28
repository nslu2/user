###########################################################
CC=arm-linux-gcc

KOPTS     = -D__KERNEL__ -Wall -Wstrict-prototypes -O2 -D_KERNEL_2_4_ -DMODULE
KOPTS-2   = $(DEBUGOPTS) -D_BUTTON_IO_REVERSE_ 
KFLAGS  = $(KOPTS) $(KOPTS-2) -I ../../linux/include -D_BUTTON_DEBUG_


all: clean $(OBJS)
	$(CC) $(KFLAGS) $(CFLAGS) -D_BUTTON_DEBUG_ -c -o pbuttons.o power_buttons.c
	$(CC) $(KFLAGS) $(CFLAGS) -D_BUTTON_DEBUG_ -c -o rbuttons.o reset_buttons.c
		
romfs:
	$(ROMFSINST) pbuttons.o /lib/modules/pbuttons.o 
	$(ROMFSINST) rbuttons.o /lib/modules/rbuttons.o
	
clean: 
	rm -f *.[oad] *.bak
