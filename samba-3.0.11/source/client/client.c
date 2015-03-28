/* 
   Unix SMB/CIFS implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#define NO_SYSLOG

#include "includes.h"
#include "ntpass.h"

extern BOOL in_client;
pstring global_myname_1;
static pstring workgroup;
DOM_SID domain_sid;

#define USENMB

static void fetch_machine_sid(struct cli_state *cli)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_OK;
	uint32 info_class = 5;
	char *domain_name = NULL;
	static BOOL got_domain_sid;
	TALLOC_CTX *mem_ctx;
	DOM_SID *dom_sid = NULL;

	if (got_domain_sid) return;

	if (!(mem_ctx=talloc_init("fetch_machine_sid")))
	{
		DEBUG(0,("fetch_machine_sid: talloc_init returned NULL!\n"));
		goto error;
	}


	if (!cli_nt_session_open (cli, PI_LSARPC)) {
		fprintf(stderr, "could not initialise lsa pipe\n");
		goto error;
	}
	
	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	result = cli_lsa_query_info_policy(cli, mem_ctx, &pol, info_class, 
					   &domain_name, &dom_sid);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	got_domain_sid = True;
	sid_copy( &domain_sid, dom_sid );

	cli_lsa_close(cli, mem_ctx, &pol);
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return;

 error:
	fprintf(stderr, "could not obtain sid for domain %s\n", cli->domain);

	if (!NT_STATUS_IS_OK(result)) {
		fprintf(stderr, "error: %s\n", nt_errstr(result));
	}

	exit(1);
}


int do_connect(char *server, char *username, char *password)
{

	struct cli_state *c;
	struct nmb_name called, calling;
	struct in_addr ip;
	static int max_protocol = PROTOCOL_NT1;
	static int port = SMB_PORT2;
	static int name_type = 0x20;	

	make_nmb_name(&calling, global_myname_1, 0x0);
	if(is_ipaddress(server))
		make_nmb_name(&called , "*SMBSERVER", 0x20);
	else
		make_nmb_name(&called , server, name_type);

	zero_ip(&ip);
	
	if (!(c=cli_initialise(NULL)) || (cli_set_port(c, port) == 0) ||
	    !cli_connect(c, server, &ip)) {
		return NTPASS_CONNECT_ERR;
	}

	c->protocol = max_protocol;

	if (!cli_session_request(c, &calling, &called)) {
		cli_shutdown(c);
		return NTPASS_SESSION_REQ_ERR;
	}

	if (!cli_negprot(c)) {
		cli_shutdown(c);
		return NAPASS_PROTOCOL_NEG_ERR;
	}
	
	if (c->protocol < PROTOCOL_LANMAN2 ||
	    !(c->sec_mode & 1)) {
		cli_shutdown(c);
		return NTPASS_SERVER_NOT_USER_SECURITY_ERR;
	}
	
	if (!cli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup)) {
		cli_shutdown(c);
		return NTPASS_USER_LOGIN_ERR;
	}
	if ((SVAL(c->inbuf,smb_vwv2) & 1) != 0) {
		cli_ulogoff(c);
		cli_shutdown(c);
		return NTPASS_SERVER_ALLOW_GUEST_ERR;
	}
	cli_ulogoff(c);
	cli_shutdown(c);
	return NTPASS_USER_PASS_OK;
}

int NTPASS(char *server, char *username, char *password)
{
	pstring term_code;
	pstring new_name_resolve_order;
	
#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	*new_name_resolve_order = 0;
	TimeInit();
	in_client = True;   /* Make sure that we tell lp_load we are */
	lp_load(dyn_CONFIGFILE,True,False,False);
	pstrcpy(workgroup,lp_workgroup());
	load_interfaces();
	get_myname((*global_myname_1)?NULL:global_myname_1);  
	if(*new_name_resolve_order)
		lp_set_name_resolve_order(new_name_resolve_order);

	
	return do_connect(server,username,password);
}


int NT_get_domain_users(char *server, char *username, char *password, int *num, struct nt_user **nu)
{
	struct in_addr 		server_ip;
	NTSTATUS nt_status;
	struct cli_state	*cli;
	TALLOC_CTX *mem_ctx;
	POLICY_HND connect_pol, domain_pol;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 info1;
	uint32 max_entries=100, num_entries, i;
	const uint32 info_level=1;
	uint32 start_idx = 0, max_size = 0xffff;
	struct nt_user *head=NULL,*aitem=NULL,*pitem=NULL;
	int ret=0;
	struct timeval oldtime,currenttime;	
	
	TimeInit();
	lp_load(dyn_CONFIGFILE,True,False,False);
	pstrcpy(workgroup,lp_workgroup());
	load_interfaces();

	get_myname((*global_myname_1)?NULL:global_myname_1);
	strupper_m(global_myname_1);
	
	if (!resolve_name(server, &server_ip, 0x20))  {
		DEBUG(1,("Unable to resolve %s\n", server));
		return 1;
	}
	
	nt_status = cli_full_connection(&cli, global_myname_1, server, 
					&server_ip, 0,
					"IPC$", "IPC",  
					username, workgroup,
					password, strlen(password), Undefined, NULL);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
		return 1;
	}
	
	fetch_machine_sid(cli);
	if (!(mem_ctx = talloc_init("NT_get_domain_users"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		ret=1;
		goto done;
	}

	if (!cli_nt_session_open(cli, PI_SAMR)) {
		DEBUG(0, ("Could not initialise %s\n",PIPE_SAMR));
		ret=1;
		goto done;
	}
	
	nt_status = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, &connect_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ret=1;
		goto done;
	}
	
	nt_status = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS, 
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ret=1;
		goto done;
	}

	
	ZERO_STRUCT(ctr);
	ZERO_STRUCT(info1);
	ctr.sam.info1 = &info1;
	cli->timeout=120000;
	gettimeofday(&oldtime,NULL);
	do{
		nt_status = cli_samr_query_dispinfo(cli, mem_ctx, &domain_pol,
			&start_idx, info_level,
			&num_entries, max_entries, max_size, &ctr);
	
		*num+=num_entries;
		
		for(i=0;i<num_entries;i++){
			SAM_ENTRY1 *e1;
			SAM_STR1 *s1;
			fstring tmp;
			
			e1=&ctr.sam.info1->sam[i];
			s1=&ctr.sam.info1->str[i];
			
			unistr2_to_ascii(tmp, &s1->uni_acct_name, sizeof(tmp)-1);
			
			aitem=malloc(sizeof(struct nt_user));
			if(aitem==NULL)
				continue;
			aitem->u_name=strdup(tmp);
			aitem->u_rid=e1->rid_user;
			aitem->flag=0;
			aitem->next=NULL;
			if(head==NULL){
				head=aitem;
				pitem=head;
			}
			else{
				pitem->next=aitem;
				pitem=pitem->next;
			}
		}
		gettimeofday(&currenttime,NULL);
		if(currenttime.tv_sec-oldtime.tv_sec>1200)
			break;
	}
	while(!NT_STATUS_IS_OK(nt_status));

	if(head)
		*nu=head;
done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);
	cli_shutdown(cli);
	return ret;
}

int NT_get_all_grps(char *server, char *username, char *password, int *num, struct nt_grp **ng)
{
	struct in_addr 		server_ip;
	NTSTATUS nt_status;
	struct cli_state	*cli;
	TALLOC_CTX *mem_ctx;
	POLICY_HND connect_pol, domain_pol;
	uint32 i,num_dom_groups,num_builtin_groups;
	struct acct_info *dom_groups;
	uint32 start_idx = 0;
	const uint32 size = 0xffff;
	DOM_SID global_sid_Builtin;
	struct nt_grp *head=NULL,*aitem=NULL,*pitem=NULL;
	int ret=0;
	
	TimeInit();
	lp_load(dyn_CONFIGFILE,True,False,False);
	
	pstrcpy(workgroup,lp_workgroup());
	load_interfaces();

	get_myname((*global_myname_1)?NULL:global_myname_1);
	strupper_m(global_myname_1);
	
	if (!resolve_name(server, &server_ip, 0x20))  {
		DEBUG(1,("Unable to resolve %s\n", server));
		return 1;
	}
	
	nt_status = cli_full_connection(&cli, global_myname_1, server, 
					&server_ip, 0,
					"IPC$", "IPC",  
					username, workgroup,
					password, strlen(password), Undefined, NULL);	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
		return 1;
	}
	
	fetch_machine_sid(cli);
	
	if (!(mem_ctx = talloc_init("NT_get_all_grps"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		ret=1;
		goto done;
	}

	if (!cli_nt_session_open(cli, PI_SAMR)) {
		DEBUG(0, ("Could not initialise %s\n",PIPE_SAMR));
		ret=1;
		goto done;
	}
	
	nt_status = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, &connect_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ret=1;
		goto done;
	}
	
	string_to_sid(&global_sid_Builtin, "S-1-5-32");
	nt_status = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
		MAXIMUM_ALLOWED_ACCESS,
		&global_sid_Builtin, &domain_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("error open.\n");
		ret=1;
		goto done;
	}
	start_idx = 0;
	nt_status = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
					  &start_idx, size,
					  &dom_groups, &num_builtin_groups);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("error get builtin group.\n");
		ret=1;
		goto done;
	}
	
	for(i=0;i<num_builtin_groups;i++){
		aitem=malloc(sizeof(struct nt_grp));
		
		aitem->g_name=strdup(dom_groups[i].acct_name);
		aitem->g_rid=dom_groups[i].rid;
		aitem->next=NULL;
		if(head==NULL){
			head=aitem;
			pitem=head;
		}
		else{
			pitem->next=aitem;
			pitem=pitem->next;
		}
	}

	nt_status = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, &connect_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ret=1;
		goto done;
	}
	nt_status = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS, 
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ret=1;
		goto done;
	}
	start_idx = 0;
	num_dom_groups=0;
	
	nt_status = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
					  &start_idx, size,
					  &dom_groups, &num_dom_groups);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("server has no domain groups.\n");
	}
	for(i=0;i<num_dom_groups;i++){
		aitem=malloc(sizeof(struct nt_grp));
		
		aitem->g_name=strdup(dom_groups[i].acct_name);
		aitem->g_rid=dom_groups[i].rid;
		aitem->next=NULL;
		if(head==NULL){
			head=aitem;
			pitem=head;
		}
		else{
			pitem->next=aitem;
			pitem=pitem->next;
		}
	}
	

	*num=num_builtin_groups+num_dom_groups;
	if(head)
		*ng=head;

done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);
	cli_shutdown(cli);
	return ret;
}

void NT_free_users(struct nt_user *nu)
{
	struct nt_user *p,*q;
	
	p=nu;
	while(p){
		q=p->next;
		SAFE_FREE(p->u_name);
		SAFE_FREE(p);
		p=q;
	}
	return;
}

void NT_free_all_grps(struct nt_grp *ng)
{
	struct nt_grp *p,*q;
	
	p=ng;
	while(p){
		q=p->next;
		SAFE_FREE(p->g_name);
		SAFE_FREE(p);
		p=q;
	}
	return;
}

#if 0
int main(int argc,char **argv)
{
	int num=0,ret=0;
	struct nt_user *nu=NULL;
	struct nt_grp *ng=NULL,*p;
	time_t t1,t2;
	
	time(&t1);
#if 0	
	if(argc!=4){
		printf("Usage: %s <server> <user> <pass>\n",argv[0]);
		return -1;
	}
	
	NT_get_domain_users(argv[1],argv[2],argv[3],&num,&nu);
	printf("%d\n",num);
	while(nu)
	{
		printf("%s 0x%x\n",nu->u_name,nu->u_rid);
		nu=nu->next;
	}
	NT_free_users(nu);
#endif	

#if 0
	NT_get_all_grps(argv[1],argv[2],argv[3],&num,&ng);
	printf("%d\n",num);
	while(ng)
	{
		printf("%s 0x%x\n",ng->g_name,ng->g_rid);
		ng=ng->next;
	}
	NT_free_all_grps(ng);

	NT_get_user_grps(argv[1],argv[2],argv[3],&num,&ng);
	printf("num=%d\n",num);
	p=ng;
	while(p)
	{
		printf("%s 0x%x\n",p->g_name,p->g_rid);
		p=p->next;
	}
#endif

#if 1
	ret=NTPASS(argv[1],argv[2],argv[3]);
	if(ret)
		printf("Password is wrong.\n");
	else
		printf("Password is right.\n");
#endif
	time(&t2);
	printf("run time is %d\n",(int)(t2-t1));
	return 0;
}
#endif

int NT_get_user_grps(char *server, char *username, char *password, int *num,struct nt_grp **grps)
{
	struct in_addr 		server_ip;
	NTSTATUS nt_status;
	struct cli_state	*cli;
	TALLOC_CTX *mem_ctx;
	POLICY_HND connect_pol, domain_pol;
	uint32 i;
	DOM_SID global_sid_Builtin,tmp_sid;
	DOM_SID2 sid;
	uint32 num_builtin,num_dom,num_users,num_grps;
	nt_user *nu=NULL,*p;
	uint32 user_rid=0;
	uint32 *alias_rids;
	nt_grp *ng;
	struct nt_grp *head=NULL,*aitem=NULL,*pitem=NULL;
#undef strcasecmp	
	NT_get_domain_users(server,username,password,&num_users,&nu);
	if(!nu)
		return -1;
	p=nu;
	while(p){
		if(strcasecmp(p->u_name,username)==0){
			user_rid=p->u_rid;
			break;
		}
		p=p->next;
	}
	NT_free_users(nu);
	
	NT_get_all_grps(server,username,password,&num_grps,&ng);
	
	
	TimeInit();
	lp_load(dyn_CONFIGFILE,True,False,False);
	
	pstrcpy(workgroup,lp_workgroup());
	load_interfaces();

	get_myname((*global_myname_1)?NULL:global_myname_1);
	strupper_m(global_myname_1);
	
	if (!resolve_name(server, &server_ip, 0x20))  {
		DEBUG(1,("Unable to resolve %s\n", server));
		return 1;
	}
	
	nt_status = cli_full_connection(&cli, global_myname_1, server, 
					&server_ip, 0,
					"IPC$", "IPC",  
					username, workgroup,
					password, strlen(password), Undefined, NULL);	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
		return 1;
	}
	
	fetch_machine_sid(cli);
	
	if (!(mem_ctx = talloc_init("NT_get_all_grps"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		goto done;
        }

	if (!cli_nt_session_open(cli, PI_SAMR)) {
		DEBUG(0, ("Could not initialise %s\n",PIPE_SAMR));
		goto done;
	}
	
	nt_status = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, &connect_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}
	
	string_to_sid(&global_sid_Builtin, "S-1-5-32");
	nt_status = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
		MAXIMUM_ALLOWED_ACCESS,
		&global_sid_Builtin, &domain_pol);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("error open.\n");
		goto done;
	}
	
	sid_copy(&tmp_sid, &domain_sid);
	sid_append_rid(&tmp_sid, user_rid);
	init_dom_sid2(&sid, &tmp_sid);
	
	nt_status = cli_samr_query_useraliases(cli, mem_ctx, &domain_pol, 1, &sid, &num_builtin, &alias_rids);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	for (i = 0; i < num_builtin; i++) {
		nt_grp *p=ng;
		
		while(p){
			if(p->g_rid==alias_rids[i]){
				aitem=malloc(sizeof(struct nt_grp));
				
				aitem->g_name=strdup(p->g_name);
				aitem->g_rid=p->g_rid;
				aitem->next=NULL;
				if(head==NULL){
					head=aitem;
					pitem=head;
				}
				else{
					pitem->next=aitem;
					pitem=pitem->next;
				}
				break;
			}
			p=p->next;
		}
	}
		

	nt_status = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
		MAXIMUM_ALLOWED_ACCESS,
		&domain_sid, &domain_pol);	
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	nt_status = cli_samr_query_useraliases(cli, mem_ctx, &domain_pol, 1, &sid, &num_dom, &alias_rids);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	for (i = 0; i < num_dom; i++) {
		nt_grp *p=ng;
		
		while(p){
			if(p->g_rid==alias_rids[i]){
				aitem=malloc(sizeof(struct nt_grp));
				
				aitem->g_name=strdup(p->g_name);
				aitem->g_rid=p->g_rid;
				aitem->next=NULL;
				if(head==NULL){
					head=aitem;
					pitem=head;
				}
				else{
					pitem->next=aitem;
					pitem=pitem->next;
				}
				break;
			}
			p=p->next;
		}
	}
	
	NT_free_all_grps(ng);
	
	*num=num_builtin+num_dom;
	*grps=head;
done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);
	cli_shutdown(cli);
	return 0;
}
