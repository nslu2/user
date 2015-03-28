/*
 * QUOTA    An implementation of the diskquota system for the LINUX operating
 *          system. QUOTA is implemented using the BSD systemcall interface
 *          as the means of communication with the user level. Should work for
 *          all filesystems because of integration into the VFS layer of the
 *          operating system. This is based on the Melbourne quota system wich
 *          uses both user and group quota files.
 *
 *          Rquota service handlers.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: rquota_svc.c,v 1.1.1.1 2004/03/24 19:54:17 sure Exp $
 *
 *          This program is free software; you can redistribute it and/or
 *          modify it under the terms of the GNU General Public License as
 *          published by the Free Software Foundation; either version 2 of
 *          the License, or (at your option) any later version.
 */
                                                                                                          
#include <rpc/rpc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/pmap_clnt.h>	/* for pmap_unset */
#include <stdio.h>
#include <stdlib.h>		/* getenv, exit */
#include <string.h>		/* strcmp */
#include <memory.h>
#include <unistd.h>

#ifdef __STDC__
#define SIG_PF void(*)(int)
#endif

#include "pot.h"
#include "common.h"
#include "rquota.h"
#include "quotasys.h"

char *progname;

/*
 * Global authentication credentials.
 */
struct authunix_parms *unix_cred;

char **argvargs;
int argcargs;
static void rquotaprog_1(struct svc_req *rqstp, register SVCXPRT * transp)
{
	union {
		getquota_args rquotaproc_getquota_1_arg;
		setquota_args rquotaproc_setquota_1_arg;
		getquota_args rquotaproc_getactivequota_1_arg;
		setquota_args rquotaproc_setactivequota_1_arg;
	} argument;
	char *result;
	xdrproc_t xdr_argument, xdr_result;
	char *(*local) (char *, struct svc_req *);

	/*
	 * Don't bother authentication for NULLPROC.
	 */
	if (rqstp->rq_proc == NULLPROC) {
		(void)svc_sendreply(transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;
	}

	/*
	 * First get authentication.
	 */
	switch (rqstp->rq_cred.oa_flavor) {
	  case AUTH_UNIX:
		  unix_cred = (struct authunix_parms *)rqstp->rq_clntcred;
		  break;
	  case AUTH_NULL:
	  default:
		  svcerr_weakauth(transp);
		  return;
	}

	switch (rqstp->rq_proc) {
	  case RQUOTAPROC_GETQUOTA:
		  xdr_argument = (xdrproc_t) xdr_getquota_args;
		  xdr_result = (xdrproc_t) xdr_getquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_getquota_1_svc;
		  break;

	  case RQUOTAPROC_SETQUOTA:
		  xdr_argument = (xdrproc_t) xdr_setquota_args;
		  xdr_result = (xdrproc_t) xdr_setquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_setquota_1_svc;
		  break;

	  case RQUOTAPROC_GETACTIVEQUOTA:
		  xdr_argument = (xdrproc_t) xdr_getquota_args;
		  xdr_result = (xdrproc_t) xdr_getquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_getactivequota_1_svc;
		  break;

	  case RQUOTAPROC_SETACTIVEQUOTA:
		  xdr_argument = (xdrproc_t) xdr_setquota_args;
		  xdr_result = (xdrproc_t) xdr_setquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_setactivequota_1_svc;
		  break;

	  default:
		  svcerr_noproc(transp);
		  return;
	}
	(void)memset((char *)&argument, 0, sizeof(argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t) & argument)) {
		svcerr_decode(transp);
		return;
	}
	result = (*local) ((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t) & argument)) {
		errstr(_("unable to free arguments"));
		exit(1);
	}
	return;
}

static void rquotaprog_2(struct svc_req *rqstp, register SVCXPRT * transp)
{
	union {
		ext_getquota_args rquotaproc_getquota_2_arg;
		ext_setquota_args rquotaproc_setquota_2_arg;
		ext_getquota_args rquotaproc_getactivequota_2_arg;
		ext_setquota_args rquotaproc_setactivequota_2_arg;
	} argument;
	char *result;
	xdrproc_t xdr_argument, xdr_result;
	char *(*local) (char *, struct svc_req *);

	/*
	 * Don't bother authentication for NULLPROC.
	 */
	if (rqstp->rq_proc == NULLPROC) {
		(void)svc_sendreply(transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;
	}

	/*
	 * First get authentication.
	 */
	switch (rqstp->rq_cred.oa_flavor) {
	  case AUTH_UNIX:
		  unix_cred = (struct authunix_parms *)rqstp->rq_clntcred;
		  break;
	  case AUTH_NULL:
	  default:
		  svcerr_weakauth(transp);
		  return;
	}

	switch (rqstp->rq_proc) {
	  case RQUOTAPROC_GETQUOTA:
		  xdr_argument = (xdrproc_t) xdr_ext_getquota_args;
		  xdr_result = (xdrproc_t) xdr_getquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_getquota_2_svc;
		  break;

	  case RQUOTAPROC_SETQUOTA:
		  xdr_argument = (xdrproc_t) xdr_ext_setquota_args;
		  xdr_result = (xdrproc_t) xdr_setquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_setquota_2_svc;
		  break;

	  case RQUOTAPROC_GETACTIVEQUOTA:
		  xdr_argument = (xdrproc_t) xdr_ext_getquota_args;
		  xdr_result = (xdrproc_t) xdr_getquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_getactivequota_2_svc;
		  break;

	  case RQUOTAPROC_SETACTIVEQUOTA:
		  xdr_argument = (xdrproc_t) xdr_ext_setquota_args;
		  xdr_result = (xdrproc_t) xdr_setquota_rslt;
		  local = (char *(*)(char *, struct svc_req *))rquotaproc_setactivequota_2_svc;
		  break;

	  default:
		  svcerr_noproc(transp);
		  return;
	}
	(void)memset((char *)&argument, 0, sizeof(argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t) & argument)) {
		svcerr_decode(transp);
		return;
	}
	result = (*local) ((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t) & argument)) {
		errstr(_("unable to free arguments"));
		exit(1);
	}
	return;
}

int main(int argc, char **argv)
{
	register SVCXPRT *transp;

	argcargs = argc;
	argvargs = argv;

	gettexton();
	progname = basename(argv[0]);

	warn_new_kernel(-1);

	(void)pmap_unset(RQUOTAPROG, RQUOTAVERS);
	(void)pmap_unset(RQUOTAPROG, EXT_RQUOTAVERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		errstr(_("cannot create udp service."));
		exit(1);
	}
	if (!svc_register(transp, RQUOTAPROG, RQUOTAVERS, rquotaprog_1, IPPROTO_UDP)) {
		errstr(_("unable to register (RQUOTAPROG, RQUOTAVERS, udp)."));
		exit(1);
	}
	if (!svc_register(transp, RQUOTAPROG, EXT_RQUOTAVERS, rquotaprog_2, IPPROTO_UDP)) {
		errstr(_("unable to register (RQUOTAPROG, EXT_RQUOTAVERS, udp)."));
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		errstr(_("cannot create tcp service."));
		exit(1);
	}
	if (!svc_register(transp, RQUOTAPROG, RQUOTAVERS, rquotaprog_1, IPPROTO_TCP)) {
		errstr(_("unable to register (RQUOTAPROG, RQUOTAVERS, tcp)."));
		exit(1);
	}
	if (!svc_register(transp, RQUOTAPROG, EXT_RQUOTAVERS, rquotaprog_2, IPPROTO_TCP)) {
		errstr(_("unable to register (RQUOTAPROG, EXT_RQUOTAVERS, tcp)."));
		exit(1);
	}

	daemon(1, 1);
	svc_run();
	errstr(_("svc_run returned"));
	exit(1);
	/* NOTREACHED */
}
