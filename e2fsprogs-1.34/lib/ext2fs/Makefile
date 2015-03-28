#Makefile
#CFLAGS += -c
# AR=ar
#ARFLAGS=rc
include ../../MCONFIG
DEBUGFS_LIB_OBJS = bb_compat.o cmp_bitmaps.o fileio.o \
	inode_io.o namei.o write_bb_file.o

RESIZE_LIB_OBJS = rs_bitmap.o dupfs.o test_io.o

E2IMAGE_LIB_OBJS = imager.o

objs= $(DEBUGFS_LIB_OBJS) $(RESIZE_LIB_OBJS) $(E2IMAGE_LIB_OBJS) \
	ext2_err.o \
	alloc.o \
	alloc_stats.o \
	alloc_tables.o \
	badblocks.o \
	bb_inode.o \
	bitmaps.o \
	bitops.o \
	block.o \
	bmap.o \
	check_desc.o \
	closefs.o \
	dblist.o \
	dblist_dir.o \
	dirblock.o \
	dirhash.o \
	dir_iterate.o \
	expanddir.o \
	ext_attr.o \
	finddev.o \
	flushb.o \
	freefs.o \
	gen_bitmap.o \
	get_pathname.o \
	getsize.o \
	getsectsize.o \
	icount.o \
	initialize.o \
	inline.o \
	inode.o \
	ismounted.o \
	link.o \
	llseek.o \
	lookup.o \
	mkdir.o \
	mkjournal.o \
	native.o \
	newdir.o \
	openfs.o \
	read_bb.o \
	read_bb_file.o \
	rw_bitmaps.o \
	swapfs.o \
	unix_io.o \
	unlink.o \
	valid_blk.o \
	version.o

#DEFS = -DLOCALEDIR=\"$(localedir)\"  -DENABLE_HTREE=1 -DENABLE_SWAPFS=1 -DPACKAGE=\"e2fsprogs\" -DVERSION=\"1.34\" -DHAVE_INTTYPES_H_WITH_UINTMAX=1 -DHAVE_STDINT_H_WITH_UINTMAX=1 -DHAVE_UNSIGNED_LONG_LONG=1 -DSTDC_HEADERS=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_UNISTD_H=1 -DHAVE_GETPAGESIZE=1 -DHAVE_MMAP=1 -DINTDIV0_RAISES_SIGFPE=1 -DHAVE_INTTYPES_H=1 -DHAVE_ARGZ_H=1 -DHAVE_LIMITS_H=1 -DHAVE_LOCALE_H=1 -DHAVE_NL_TYPES_H=1 -DHAVE_MALLOC_H=1 -DHAVE_STDDEF_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_UNISTD_H=1 -DHAVE_SYS_PARAM_H=1 -DHAVE_FEOF_UNLOCKED=1 -DHAVE_FGETS_UNLOCKED=1 -DHAVE_GETC_UNLOCKED=1 -DHAVE_GETCWD=1 -DHAVE_GETEGID=1 -DHAVE_GETEUID=1 -DHAVE_GETGID=1 -DHAVE_GETUID=1 -DHAVE_MEMPCPY=1 -DHAVE_MUNMAP=1 -DHAVE_PUTENV=1 -DHAVE_SETENV=1 -DHAVE_SETLOCALE=1 -DHAVE_STPCPY=1 -DHAVE_STRCASECMP=1 -DHAVE_STRDUP=1 -DHAVE_STRTOUL=1 -DHAVE_TSEARCH=1 -DHAVE___ARGZ_COUNT=1 -DHAVE___ARGZ_STRINGIFY=1 -DHAVE___ARGZ_NEXT=1 -DHAVE_ICONV=1 -DICONV_CONST= -DHAVE_LANGINFO_CODESET=1 -DHAVE_LC_MESSAGES=1 -DENABLE_NLS=1 -DHAVE_GETTEXT=1 -DHAVE_DCGETTEXT=1 -DHAVE_STDLIB_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_ERRNO_H=1 -DHAVE_MALLOC_H=1 -DHAVE_MNTENT_H=1 -DHAVE_PATHS_H=1 -DHAVE_DIRENT_H=1 -DHAVE_GETOPT_H=1 -DHAVE_SETJMP_H=1 -DHAVE_SIGNAL_H=1 -DHAVE_TERMIOS_H=1 -DHAVE_LINUX_FD_H=1 -DHAVE_LINUX_MAJOR_H=1 -DHAVE_SYS_IOCTL_H=1 -DHAVE_SYS_MOUNT_H=1 -DHAVE_SYS_SOCKET_H=1 -DHAVE_SYS_SYSMACROS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_SYS_RESOURCE_H=1 -DHAVE_NET_IF_H=1 -DHAVE_NETINET_IN_H=1 -DHAVE_VPRINTF=1 -DHAVE_RECLEN_DIRENT=1 -DHAVE_TYPE_SSIZE_T=1 -DHAVE_LSEEK64_PROTOTYPE=1 -DSIZEOF_SHORT=2 -DSIZEOF_INT=4 -DSIZEOF_LONG=4 -DSIZEOF_LONG_LONG=8 -DHAVE_GETRUSAGE=1 -DHAVE_LLSEEK=1 -DHAVE_LSEEK64=1 -DHAVE_OPEN64=1 -DHAVE_STRTOULL=1 -DHAVE_STRCASECMP=1 -DHAVE_SRANDOM=1 -DHAVE_FCHOWN=1 -DHAVE_MALLINFO=1 -DHAVE_FDATASYNC=1 -DHAVE_STRNLEN=1 -DHAVE_STRPTIME=1 -DHAVE_SYSCONF=1 -DHAVE_PATHCONF=1 -DHAVE_POSIX_MEMALIGN=1 -DHAVE_MEMALIGN=1 -DHAVE_VALLOC=1 -DHAVE_DLOPEN=1 -DHAVE_EXT2_IOCTLS=1
#CFLAGS += $(DEFS) -I. -I../../lib -I../../library/include -DHAVE_CONFIG_H -D_FILE_OFFSET_BITS=64

all: libext2fs

#%.o: %.c
#	$(CC) $(CFLAGS) $<

libext2fs: $(objs)
	$(CC) -shared -Wl,-soname,libext2fs.so.0 -o libext2fs.so.0.0 $(objs)
	arm-linux-strip libext2fs.so.0.0
	ln -sf libext2fs.so.0.0 libext2fs.so.0
	ln -sf libext2fs.so.0 libext2fs.so

clean:
	echo Cleaning up
	rm -f *.o
	rm -f libext2fs*

$(OBJS): ../../MCONFIG

romfs:
	$(ROMFSINST) libext2fs.so.0.0 /lib
	$(ROMFSINST) -s libext2fs.so.0.0 /lib/libext2fs.so.0
	$(ROMFSINST) -s libext2fs.so.0 /lib/libext2fs.so

