#include <pcap.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
//#include "ip_helper.h"

#define FILTER_LEN  64 /* max length of a filter parameter */
#define NUM_FILTERS 128 /* max number of filters */
#define MAX_CIDR 19 /* 255.255.255.255/32\0 */
#define MAX_ALIAS 33 /* max length of subnet alias + \0 */

#define MAXBUF 2048 /* Length of log message buffer */

#ifdef __OpenBSD__
#define CIDRSTAT_PRIVSEP_USER "_cidrstat"
#else
#define CIDRSTAT_PRIVSEP_USER "cidrstat"
#endif

/* Define available commands */
#define CMD_GETCOUNTERS		1

#define _BSD_SOURCE 1

struct counters
{
	unsigned int network;
	unsigned int mask;
	char cidr[MAX_CIDR];
	char alias[MAX_ALIAS];
	unsigned long long pkts_in;
	unsigned long long bytes_in;
	unsigned long long pkts_out;
	unsigned long long bytes_out;
};

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
		#if BYTE_ORDER == LITTLE_ENDIAN
			u_int	ip_hl:4,	/* header length */
				ip_v:4;		/* version */
		#endif
		#if BYTE_ORDER == BIG_ENDIAN
			u_int	ip_v:4,		/* version */
				ip_hl:4;	/* header length */
		#endif
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

