#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "dns.h"

static union {
    HEADER1 hdr;
    unsigned char buf[PACKETSZ];
} response;

static char name[MAXDNAME];
static char *pStart, *responseend, *responsepos;
static int numanswers;
unsigned short pref;

void
alloc_free (char *x)
{
    free (x);
}

static unsigned short
getshort (unsigned char *c)
{
    unsigned short u;
    u = c[0];
    return (u << 8) + c[1];
}

static int
findmx (int wanttype)
{
    unsigned short rrtype;
    unsigned short rrdlen;
    int i;

    if (numanswers <= 0)
        return 2;
    --numanswers;
    if (responsepos == responseend)
        return DNS_SOFT;

    i = dn_expand (response.buf, responseend, responsepos, name, MAXDNAME);

    if (i < 0)
        return DNS_SOFT;
    responsepos += i;

    i = responseend - responsepos;
    if (i < 4 + 3 * 2)
        return DNS_SOFT;
    rrtype = getshort (responsepos);
    rrdlen = getshort (responsepos + 8);
    responsepos += 10;
    if (rrtype == wanttype) {
        if (rrdlen < 3)
            return DNS_SOFT;
        pref = (responsepos[0] << 8) + responsepos[1];
        if (dn_expand
            (response.buf, responseend, responsepos + 2, name, MAXDNAME) < 0)
            return DNS_SOFT;
        responsepos += rrdlen;
        return 1;
    }
    responsepos += rrdlen;
    return 0;
}

int
dns_mxip (char *host, struct MX **host_s, int *num)
{
    int alen;
    int nummx;
    int n, i, j, r;
    struct MX *mx;
    int an;

    res_init ();
    alen = res_query (host, C_IN, T_MX, response.buf, sizeof (response));
    if (alen <= 0)
        return -1;
    if (alen >= sizeof (response))
        alen = sizeof (response);
    pStart = (char *) response.buf + sizeof (HEADER);
    responseend = (char *) response.buf + alen;
    responsepos = pStart;
    n = ntohs (response.hdr.qn);
    while (n-- > 0) {
        i = dn_expand (response.buf, responseend, responsepos, name,
                       MAXDNAME);
        if (i < 0)
            return DNS_SOFT;
        responsepos += i;
        i = responseend - responsepos;
        if (i < QFIXEDSZ)       /* QFIXEDSZ = 4 */
            return DNS_SOFT;
        responsepos += QFIXEDSZ;
    }
    numanswers = ntohs (response.hdr.rrn);
    if (numanswers == 0)
        return DNS_SOFT;
    an = numanswers;
    mx = (struct MX *) malloc (numanswers * sizeof (struct MX));
    if (!mx)
        return DNS_MEM;
    nummx = 0;
    while ((r = findmx (T_MX)) != 2) {
        if (r == DNS_SOFT) {
            alloc_free ((char *) mx);
            return DNS_SOFT;
        }
        if (r == 1) {
            mx[nummx].p = pref;
            mx[nummx].name = 0;
            mx[nummx].name = (char *) malloc (strlen (name) + 1);
            if (!mx[nummx].name) {
                while (nummx > 0)
                    alloc_free (mx[--nummx].name);
                alloc_free ((char *) mx);
                return DNS_MEM;
            }
            strcpy (mx[nummx].name, name);
        }
        ++nummx;
    }
    *host_s = mx;
    *num = an;
    return 0;
}
