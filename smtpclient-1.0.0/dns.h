#define U_32	unsigned long int
#define U_16	unsigned short int
#define U_8		unsigned char
#define PACKETSZ	1500

#define DNS_SOFT -1
#define DNS_HARD -2
#define DNS_MEM -3

typedef struct HEADER1{
	U_16	id;
	U_16	flag;
	U_16	qn;
	U_16	rrn;
	U_16	aun;
	U_16	adn;
}HEADER1;

typedef struct MX{
	char *name;
	unsigned short p;
}MX;

int
dns_mxip (char *host,struct MX **host_s,int *num);
