#
# Author: Noel V Aguilar
# CGI-LIB Library
# Release 1.4
#
# This library is free softare; you can redistribute it
# and/or modify it.
#
# You can compile this library by simply running 'make'
# and then copy the cgi-lib.a to the your lib directory
# and the cgi-lib.h and html-lib.h files into your
# include directory manually.  This will allow the linker
# to automatically include the library or you can copy the
# files to where your development is being done and link it
# manually.
#
# For updates or to report bugs please go to:
# http://www.geocities.com/SiliconValley/Vista/6493/
#
# This library is distributed in the hope that it will be
# useful but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
:wq
:# PURPOSE.
#

CFLAGS +=-fPIC -Wall -c
# AR=ar
ARFLAGS=rc
objs = getdate.o posixver.o closeout.o version-etc.o gettime.o settime.o strftime.o argmatch.o posixtm.o xmalloc.o quotearg.o quote.o
all: libfetish

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $^

libfetish: $(objs)
	$(CC) -shared -Wl,-soname,libfetish.so.0 -o libfetish.so.0.0 $(objs)
	arm-linux-strip libfetish.so.0.0
	ln -sf libfetish.so.0.0 libfetish.so.0
	ln -sf libfetish.so.0 libfetish.so

clean:
	echo Cleaning up
	rm -f *.o
	rm -f libfetish*

romfs:
	$(ROMFSINST) libfetish.so.0.0 /lib
	$(ROMFSINST) -s libfetish.so.0.0 /lib/libfetish.so.0
	$(ROMFSINST) -s libfetish.so.0 /lib/libfetish.so

