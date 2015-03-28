/* script.c
 *
 * Functions to call the DHCP client notification scripts
 *
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "options.h"
#include "dhcpd.h"
#include "dhcpc.h"
#include "packet.h"
#include "options.h"
#include "debug.h"

/* get a rough idea of how long an option will be (rounding up...) */
static int run_bound(char **msg);

static int run_deconfig(void);

static int max_option_length(char *option, struct dhcp_option *type)
{
	int size = 0;

	switch (type->flags & TYPE_MASK) {
	case OPTION_IP:
	case OPTION_IP_PAIR:
		size = (option[OPT_LEN - 2] / 4) * sizeof("255.255.255.255 ");
		break;
	case OPTION_STRING:
		size = option[OPT_LEN - 2] + 1;
		break;
	case OPTION_BOOLEAN:
		size = option[OPT_LEN - 2] * sizeof("yes ");
		break;
	case OPTION_U8:
		size = option[OPT_LEN - 2] * sizeof("255 ");
		break;
	case OPTION_U16:
		size = (option[OPT_LEN - 2] / 2) * sizeof("65535 ");
		break;
	case OPTION_S16:
		size = (option[OPT_LEN - 2] / 2) * sizeof("-32768 ");
		break;
	case OPTION_U32:
		size = (option[OPT_LEN - 2] / 4) * sizeof("4294967295 ");
		break;
	case OPTION_S32:
		size = (option[OPT_LEN - 2] / 4) * sizeof("-2147483684 ");
		break;
	}

	return size;
}


/* Fill dest with the text of option 'option'. */
static void fill_options(char *dest, unsigned char *option, struct dhcp_option *type_p)
{
	int type, optlen;
	u_int16_t val_u16;
	int16_t val_s16;
	u_int32_t val_u32;
	int32_t val_s32;
	int len = option[OPT_LEN - 2];

	dest += sprintf(dest, "%s=", type_p->name);

	type = type_p->flags & TYPE_MASK;
	optlen = option_lengths[type];
	for(;;) {
		switch (type) {
		case OPTION_IP:	/* Works regardless of host byte order. */
			dest += sprintf(dest, "%d.%d.%d.%d",
					option[0], option[1],
					option[2], option[3]);
 			break;
		case OPTION_IP_PAIR:
			dest += sprintf(dest, "%d.%d.%d.%d, %d.%d.%d.%d",
					option[0], option[1],
					option[2], option[3],
					option[4], option[5],
					option[6], option[7]);
			break;
		case OPTION_BOOLEAN:
			dest += sprintf(dest, *option ? "yes" : "no");
			break;
		case OPTION_U8:
			dest += sprintf(dest, "%u", *option);
			break;
		case OPTION_U16:
			memcpy(&val_u16, option, 2);
			dest += sprintf(dest, "%u", ntohs(val_u16));
			break;
		case OPTION_S16:
			memcpy(&val_s16, option, 2);
			dest += sprintf(dest, "%d", ntohs(val_s16));
			break;
		case OPTION_U32:
			memcpy(&val_u32, option, 4);
			dest += sprintf(dest, "%lu", (unsigned long) ntohl(val_u32));
			break;
		case OPTION_S32:
			memcpy(&val_s32, option, 4);
			dest += sprintf(dest, "%ld", (long) ntohl(val_s32));
			break;
		case OPTION_STRING:
			memcpy(dest, option, len);
			dest[len] = '\0';
			return;	 /* Short circuit this case */
		}
		option += optlen;
		len -= optlen;
		if (len <= 0) break;
		*(dest++) = ' ';
	}
}


static char *find_env(const char *prefix, char *defaultstr)
{
	extern char **environ;
	char **ptr;
	const int len = strlen(prefix);

	for (ptr = environ; *ptr != NULL; ptr++) {
		if (strncmp(prefix, *ptr, len) == 0)
		return *ptr;
	}
	return defaultstr;
}


/* put all the paramaters into an environment */
static char **fill_envp(struct dhcpMessage *packet)
{
	int num_options = 0;
	int i, j;
	unsigned char *addr;
	char **envp, *temp;
	char over = 0;

	if (packet == NULL)
		num_options = 0;
	else {
		for (i = 0; options[i].code; i++)
			if (get_option(packet, options[i].code))
				num_options++;
		if (packet->siaddr) num_options++;
		if ((temp = get_option(packet, DHCP_OPTION_OVER)))
			over = *temp;
		if (!(over & FILE_FIELD) && packet->file[0]) num_options++;
		if (!(over & SNAME_FIELD) && packet->sname[0]) num_options++;
	}

	envp = malloc((num_options + 5) * sizeof(char *));
	envp[0] = malloc(strlen("interface=") + strlen(client_config.interface) + 1);
	sprintf(envp[0], "interface=%s", client_config.interface);
	envp[1] = malloc(sizeof("ip=255.255.255.255"));
	envp[2] = find_env("PATH", "PATH=/bin:/usr/bin:/sbin:/usr/sbin");
	envp[3] = find_env("HOME", "HOME=/");

	if (packet == NULL) {
		envp[4] = NULL;
		return envp;
	}

	addr = (unsigned char *) &packet->yiaddr;
	sprintf(envp[1], "ip=%d.%d.%d.%d",
		addr[0], addr[1], addr[2], addr[3]);
	for (i = 0, j = 4; options[i].code; i++) {
		if ((temp = get_option(packet, options[i].code))) {
			envp[j] = malloc(max_option_length(temp, &options[i]) +
					strlen(options[i].name) + 2);
			fill_options(envp[j], temp, &options[i]);
			j++;
		}
	}
	if (packet->siaddr) {
		envp[j] = malloc(sizeof("siaddr=255.255.255.255"));
		addr = (unsigned char *) &packet->yiaddr;
		sprintf(envp[j++], "siaddr=%d.%d.%d.%d",
			addr[0], addr[1], addr[2], addr[3]);
	}
	if (!(over & FILE_FIELD) && packet->file[0]) {
		/* watch out for invalid packets */
		packet->file[sizeof(packet->file) - 1] = '\0';
		envp[j] = malloc(sizeof("boot_file=") + strlen(packet->file));
		sprintf(envp[j++], "boot_file=%s", packet->file);
	}
	if (!(over & SNAME_FIELD) && packet->sname[0]) {
		/* watch out for invalid packets */
		packet->sname[sizeof(packet->sname) - 1] = '\0';
		envp[j] = malloc(sizeof("sname=") + strlen(packet->sname));
		sprintf(envp[j++], "sname=%s", packet->sname);
	}
	envp[j] = NULL;
	return envp;
}


/* Call a script with a par file and env vars */
void run_script(struct dhcpMessage *packet)
{
	int pid;
	char **envp;

	/* call script */
	if(packet==NULL)  {
			run_deconfig();
			return ;
		}
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
		return;
	} else if (pid == 0) {
		envp = fill_envp(packet);

		/*  */

		/*ifconfig interface */
		run_bound(envp);
		exit(1);
	}
}

static int run_bound(char ** msg)
{
	char buf[128],buf1[100];
	char temp[17] = "";
	int num;
	char *p0,*p1;
	int ipflag=0,maskflag=0,routeflag=0;
	int tmp0,tmp1,tmp2,tmp3;
	unsigned char ip[5],nmask[5],bcast[5];

	for(num=0;msg[num]!=NULL;num++)
		{
			if((p0 = strstr(msg[num],"ip=" ))!=NULL) {
				p0 += strlen("ip=");
				strcpy(temp,p0);
				ipflag=1;
				sscanf(temp,"%d.%d.%d.%d",&tmp0,&tmp1,&tmp2,&tmp3);
				ip[0]=(unsigned char)tmp0;ip[1]=(unsigned char)tmp1;
				ip[2]=(unsigned char)tmp2;ip[3]=(unsigned char)tmp3;
				ip[4]='\0';
				sprintf(buf,"/sbin/ifconfig %s %s &> /dev/null",client_config.interface,temp);
				system(buf);
				continue;
			}
			if((p0 = strstr(msg[num],"subnet="))!=NULL) {
				p0 += strlen("subnet=");
				strcpy(temp,p0);
				maskflag=1;
				sscanf(temp,"%d.%d.%d.%d",&tmp0,&tmp1,&tmp2,&tmp3);
				nmask[0]=(unsigned char)tmp0;nmask[1]=(unsigned char)tmp1;
				nmask[2]=(unsigned char)tmp2;nmask[3]=(unsigned char)tmp3;
				nmask[4]='\0';
				sprintf(buf,"%s %s %s %s &> /dev/null","/sbin/ifconfig",client_config.interface,"netmask",temp);
				system(buf);
				continue;
				}
			if((p0 = strstr(msg[num],"router="))!=NULL) {
				p0 += strlen("router=");
				strcpy(temp,p0);
				sprintf(buf,"/sbin/route del default gw 0.0.0.0 dev %s 2> /dev/null ",client_config.interface);
				system(buf);
				sprintf(buf,"/sbin/route add default gw %s  dev %s 2> /dev/null ",temp,client_config.interface);
				system(buf);
				strcpy(buf1,buf);
				routeflag=1;
				continue;
				}
			if((p0 =strstr(msg[num],"dns="))!=NULL) {
				p0 += strlen("dns=");
				if((p1 = strchr(p0,' '))==NULL) {
					strcpy(temp,p0);
					sprintf(buf,"echo nameserver %s > %s",temp,"/etc/resolv.conf");
					system(buf);
					continue;
				}
				*p1=0;
				strcpy(temp,p0);
				sprintf(buf,"echo nameserver %s > %s",temp,"/etc/resolv.conf");
				system(buf);
				p0 = p1 +1;
				/*dns2*/
				if((p1 = strchr(p0,' '))==NULL) {
					strcpy(temp,p0);
					sprintf(buf,"echo nameserver %s >> %s",temp,"/etc/resolv.conf");
					system(buf);
					continue;
				}
				*p1=0;
				strcpy(temp,p0);
				sprintf(buf,"echo nameserver %s >> %s",temp,"/etc/resolv.conf");
				system(buf);
				p0 = p1 +1;
				/*dns3*/
				p1=strchr(p0,' ');
				if(p1)
					*p1=0;
				strcpy(temp,p0);
				sprintf(buf,"echo nameserver %s >> %s",temp,"/etc/resolv.conf");
				system(buf);
				p0 = p1 +1;

				continue;
			}
		}
		if(maskflag&&ipflag)	{
			bcast[0]=(~nmask[0])|ip[0];bcast[1]=(~nmask[1])|ip[1];
			bcast[2]=(~nmask[2])|ip[2];bcast[3]=(~nmask[3])|ip[3];
			sprintf(buf,"/sbin/ifconfig %s broadcast %d.%d.%d.%d &> /dev/null",
				client_config.interface,bcast[0],bcast[1],bcast[2],bcast[3]);
			system(buf);
			if(routeflag){
				sprintf(buf,"/sbin/route del default gw 0.0.0.0 dev %s 2> /dev/null ",client_config.interface);
				system(buf);				
				system(buf1);
			}
		}
	return 0;
}

static int run_deconfig(void)
{
	char buf[50];
	int ret;

	sprintf(buf,"%s %s %s >/dev/null","/sbin/ifconfig" ,client_config.interface,"0.0.0.0");
	ret=system(buf);

	return ret;
}


