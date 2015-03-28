#ifndef _NTPASS_H_
#define	_NTPASS_H_

#define	NTPASS_CONNECT_ERR			1
#define	NTPASS_SESSION_REQ_ERR			2
#define	NAPASS_PROTOCOL_NEG_ERR			3
#define	NTPASS_SERVER_NOT_USER_SECURITY_ERR	4
#define	NTPASS_SERVER_ALLOW_GUEST_ERR		5
#define	NTPASS_USER_LOGIN_ERR			6
#define	NTPASS_USER_PASS_OK			0

int NTPASS(char *server, char *user, char *password);

typedef struct nt_user
{
	char *u_name;
	unsigned int u_rid;
	char flag;
	struct nt_user *next;
}nt_user;

typedef struct nt_grp
{
	char *g_name;
	unsigned int g_rid;
	char flag;
	struct nt_grp *next;
}nt_grp;

int NT_get_domain_users(char *server, char *username, char *password, int *num, struct nt_user **nu);
void NT_free_users(struct nt_user *nu);

int NT_get_all_grps(char *server, char *username, char *password, int *num, struct nt_grp **ng);
void NT_free_all_grps(struct nt_grp *ng);

int NT_get_user_grps(char *server, char *username, char *password, int *num,struct nt_grp **grps);

#endif
