# Generated automatically from Makefile.in by configure.
PROGS	= edquota quotacheck quotaon
#PROGS         = quotacheck quotaon quota quot repquota warnquota quotastats xqmstats edquota setquota convertquota rpc.rquotad
CFLAGS       += -DBSD_BEHAVIOUR -DRPC_SETQUOTA -DRPC -DALT_FORMAT -g -O2 -D_GNU_SOURCE -Wall -D_FILE_OFFSET_BITS=64
EXT2LIBS      = -L ../../e2fsprogs-1.34/lib/ext2fs -L ../../e2fsprogs-1.34/lib/et -lext2fs -lcom_err
RPCSRC        = rquota.h rquota_xdr.c rquota_clnt.c
VERSIONDEF    = -DQUOTA_VERSION=\"3.01\"
LIBS          = -lwrap -lnsl
#LDFLAGS       =

#
# Uncomment the two lines below to add tcp_wrapper support for rpc.rquotad
# Then add lines to /etc/hosts.allow and /etc/hosts.deny
# like: "rquotad: ALL@ALL except my.host.i.want.com" in hosts.deny means
#        only the host designated can get info from rquotad
# NOTE: I used gethostbyaddr(), so you may need FQDN or merely host name
# depending on how your resolver returns first. IP Addresses will work as well.
#
CFLAGS       += -DHOSTS_ACCESS
CFLAGS       += $(VERSIONDEF)

INSTALL       = /usr/bin/install -c
LN            = ln -sf
ROOTDIR       =
SUPER_OWNER   = root
BIN_OWNER     = bin
BIN_GROUP     = bin
DEF_SUID_MODE = 4511
DEF_BIN_MODE = 555
DEF_SBIN_MODE = 555
DEF_MAN_MODE  = 444
RPCGEN        = rpcgen

prefix        = /usr/local
bindir        = $(prefix)/bin
sbindir       = $(prefix)/sbin
mandir        = ${prefix}/man
includedir    = $(prefix)/include
root_sbindir  = /sbin
locale_dir    = $(prefix)/share/locale

RPCCLNTOBJS = rquota_xdr.o rquota_client.o rquota_clnt.o
IOOBJS = quotaio.o quotaio_v1.o quotaio_v2.o quotaio_rpc.o quotaio_xfs.o
IOOBJS += $(RPCCLNTOBJS)
LIBOBJS = bylabel.o common.o quotasys.o pot.o $(IOOBJS)
LIBOBJS +=
INCLUDE = common.h quotasys.h bylabel.h mntopt.h

all: $(PROGS)

clean:
	-rm -f core *.o $(PROGS)

clobber: clean
	-rm -f $(PROGS) Makefile config.{status,cache,log}

realclean: clobber
	-rm -f $(RPCSRC) po/*.mo

pot:
	xgettext -k_ -d pot *.c

mo: po
	for n in $(shell ls po/*.po); do \
	msgfmt -o po/`basename $$n .po`.mo $$n; \
	done

inst_mo: mo
	mkdir -p $(locale_dir)
	for n in $(shell ls po/*.po | sed 's/\.po/\.mo/'); do \
	l=`basename $$n .mo`; \
	$(INSTALL) -m 755 -d $(ROOTDIR)$(locale_dir)/$$l; \
	$(INSTALL) -m 755 -d $(ROOTDIR)$(locale_dir)/$$l/LC_MESSAGES; \
	$(INSTALL) -m 644 $$n $(ROOTDIR)$(locale_dir)/$$l/LC_MESSAGES/quota.mo; \
	done

install: all inst_mo
	-$(INSTALL) -m $(DEF_SBIN_MODE) \
	quotacheck quotaon convertquota $(ROOTDIR)$(root_sbindir)
	$(LN) quotaon $(ROOTDIR)$(root_sbindir)/quotaoff
	chown -h $(BIN_OWNER):$(BIN_GROUP) $(ROOTDIR)$(root_sbindir)/quotaoff
	-$(INSTALL) -m $(DEF_SBIN_MODE) \
	edquota repquota warnquota quotastats setquota quot xqmstats \
	$(ROOTDIR)$(sbindir)
	-$(INSTALL) -m 755 -d $(ROOTDIR)$(includedir)/rpcsvc
	-$(INSTALL) -m 644 rquota.h rquota.x $(ROOTDIR)$(includedir)/rpcsvc
	-$(INSTALL) -s -m $(DEF_SBIN_MODE) quota $(ROOTDIR)$(bindir)
	-$(INSTALL) -s -m $(DEF_SBIN_MODE) rpc.rquotad $(ROOTDIR)$(sbindir)
	-$(INSTALL) -m $(DEF_MAN_MODE) *.1 $(ROOTDIR)$(mandir)/man1
	-$(INSTALL) -m $(DEF_MAN_MODE) *.2 $(ROOTDIR)$(mandir)/man2
	-$(INSTALL) -m $(DEF_MAN_MODE) *.3 $(ROOTDIR)$(mandir)/man3
	-$(INSTALL) -m $(DEF_MAN_MODE) *.8 $(ROOTDIR)$(mandir)/man8
romfs:
	$(ROMFSINST) edquota /usr/bin
	$(ROMFSINST) quotacheck /usr/bin
	$(ROMFSINST) quotaon /usr/bin
	$(ROMFSINST) -s quotaon /usr/bin/quotaoff

quotaon: $(INCLUDE) quotaon.o quotaon_xfs.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ quotaon.o quotaon_xfs.o $(LIBOBJS) $(LDLIBS)
	arm-linux-strip quotaon

quotacheck: $(INCLUDE) quotacheck.o quotacheck_v1.o quotacheck_v2.o quotacheck.h $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ quotacheck.o quotacheck_v1.o quotacheck_v2.o $(EXT2LIBS) $(LIBOBJS) $(LDLIBS)
	arm-linux-strip quotacheck

quota: $(INCLUDE) rquota.h quota.o quotaops.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ quota.o quotaops.o $(LIBOBJS) $(LDLIBS)
	arm-linux-strip quota

quot: $(INCLUDE) quot.h quot.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ quot.o $(LIBOBJS)

repquota: $(INCLUDE) repquota.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ repquota.o $(LIBOBJS)

warnquota: $(INCLUDE) common.h warnquota.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ warnquota.o $(LIBOBJS)

quotastats: quotastats.o pot.o
	$(CC) $(LDFLAGS) -o $@ quotastats.o pot.o

xqmstats: xqmstats.o common.o pot.o
	$(CC) $(LDFLAGS) -o $@ xqmstats.o common.o pot.o

edquota: $(INCLUDE) quotaops.h quotaio.h edquota.o quotaops.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ edquota.o quotaops.o $(LIBOBJS) $(LDLIBS)
	arm-linux-strip edquota

setquota: $(INCLUDE) setquota.o quotaops.o rquota.h $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ setquota.o quotaops.o $(LIBOBJS)

convertquota: $(INCLUDE) convertquota.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ convertquota.o $(LIBOBJS)

rpc.rquotad: $(INCLUDE) rquota.h rquota_server.o rquota_svc.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ rquota_server.o rquota_svc.o $(LIBOBJS) $(LIBS)

pot.o: pot.c pot.h
	$(CC) $(CFLAGS) -c $<

rquota.h: rquota.x
	$(RPCGEN) -h -o $@ $<

rquota_xdr.c: rquota.x
	$(RPCGEN) -c -o $@ $<

rquota_xdr.o: rquota_xdr.c rquota.h
	$(CC) $(CFLAGS) -Wno-unused -c $<

rquota_clnt.c: rquota.x
	$(RPCGEN) -l -o $@ $<
