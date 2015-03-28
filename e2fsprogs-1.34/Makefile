#---------------
SUB =
SUB += lib/et
SUB += lib/e2p
SUB += lib/ext2fs
SUB += lib/uuid
SUB += lib/blkid
SUB += e2fsck
SUB += misc
#.EXPORT_ALL_VARIABLES:
#---------------
all:	${SUB}
#---------------
 ${SUB}::
	${MAKE} ${MFLAGS} -C $@ || exit 1
#---------------
all romfs:
	for i in $(SUB) ; do $(MAKE) -C $$i $@ || exit $? ; done
#---------------
clean:
	rm -f *.[oa] *~ core
	for i in $(SUB) ; do ${MAKE} -C $$i clean || exit 1; done

#---------------
# End of file Makefile
