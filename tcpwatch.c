#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#include <signal.h>
#include <poll.h>
#include <pcap.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <time.h>
#include <stdint.h>	/* Definition of uint64_t */

#define MAXBUF 2048	/* Length of log message buffer */
#define SNAP_LEN 1518	/* Packet capture snaplength */
#define INTV_MIN 1ULL	/* milliseconds */
#define INTV_MAX 18446744073709ULL	/* milliseconds */

char *iface = NULL;
char *bpf = NULL;
int i, waitfirst = 0, daemonize = 1;
uint64_t interval = 1000ULL;
int log_facility = LOG_DAEMON;

/* Signal handler flags */
static int exit_request = 0;

/* from tcpdump.c */
char *copy_argv(register char **argv)
{
	register char **p;
	register u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		fprintf(stderr, "copy_argv: malloc\n");

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

/* from Pound */
void logmsg(const int priority, const char *fmt, ...)
{
	char buf[MAXBUF + 1];
	va_list ap;

	buf[MAXBUF] = '\0';
	va_start(ap, fmt);
	vsnprintf(buf, MAXBUF, fmt, ap);
	va_end(ap);

	if(daemonize)
		syslog(log_facility | priority, "%s", buf);
	else
		fprintf(stderr, "%s\n", buf);

	return;
}

/* from
 * http://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 */
int getcmdline(int argc, char **argv)
{
	int c;

	opterr = 0;

	while((c = getopt(argc, argv, "i:w:fD")) != -1)
		switch (c)
		{
			case 'i':
				iface = optarg;
				break;
			case 'w':
				/* milliseconds */
				interval = strtoll(optarg, NULL, 10);
				if(interval < INTV_MIN)
				{
					fprintf(stderr, "Interval must be >= %lld ms\n", INTV_MIN);
					//usage();
					exit(EXIT_FAILURE);
				}
				break;
			case 'f':
				waitfirst = 1;
				break;
			case 'D':
				daemonize = 0;
				break;
			case '?':
				if(optopt == 'i' || optopt == 'w')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if(isprint (optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				//usage();
				exit(EXIT_FAILURE);
			default:
				//usage();
				exit(EXIT_FAILURE);
		}

	/* the rest is the bpf */
	bpf = copy_argv(&argv[optind]);

	return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	(void) args; /* avoid warning about unused parameter */ 
	(void) header; /* avoid warning about unused parameter */ 
	(void) packet; /* avoid warning about unused parameter */ 
}

static void sighand_exit(int signum)
{
	(void) signum;
	logmsg(LOG_WARNING, "Received SIGTERM; scheduling exit.");
	exit_request = 1;
}

int main (int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	struct bpf_program fp;

	getcmdline(argc, argv);

	/* open capture device */
	descr = pcap_open_live(iface, SNAP_LEN, 0, 0, errbuf);
	if (descr == NULL) {
		fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* apply the filter */
	if (pcap_compile(descr, &fp, bpf, 0, 0) == -1) {
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(descr));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(descr));
		exit(EXIT_FAILURE);
	}

	/* prepare timer */
	struct itimerspec new_value;
	int tfd;
	uint64_t exp;
	ssize_t s;

	/* prepare interval */
	interval *= 1000000; /* ms to ns */

	new_value.it_value.tv_sec = interval / 1000000000;
	new_value.it_value.tv_nsec = interval % 1000000000;
	new_value.it_interval.tv_sec = interval / 1000000000;
	new_value.it_interval.tv_nsec = interval % 1000000000;

	tfd = timerfd_create(CLOCK_REALTIME, 0);
	if (tfd == -1)
	{
		fprintf(stderr, "timerfd_create failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (timerfd_settime(tfd, 0, &new_value, NULL) == -1)
	{
		fprintf(stderr, "timerfd_settime failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	signal(SIGTERM, sighand_exit);
	signal(SIGINT, sighand_exit);

	/* prepare for poll loop */
	int gotpacket = 0, inoutage = 0;	/* state switches */
	struct timespec ostart, oend;	/* outage start/end timestamps */
	char errmsg[1024];	/* XXX - arbitrary size */
	int error = 0;
	int nfds;
	struct pollfd pfd[1];

	/* stuff to poll */
	pfd[0].fd = pcap_fileno(descr);
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;
	pfd[1].fd = tfd;
	pfd[1].events = POLLIN;
	pfd[1].revents = 0;

	if (daemonize && daemon(0, 0))
		fprintf(stderr, "daemon() failed. Staying in foreground.\n");

	openlog("tcpwatch", LOG_CONS, LOG_DAEMON);
	logmsg(LOG_NOTICE, "Starting with %llums deadline and filter: `%s'", interval/1000000, bpf);

	/* Main loop */
	for(;;)
	{
		nfds = poll(pfd, 2, 200);
		if (nfds == -1 || (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL))) {
			if (errno != EINTR)
			{
				logmsg(LOG_ERR, "Poll error: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		/* Handle packet arrivals */
		if (pfd[0].revents) {
			/* Reading a packet from the fd is tricky, so
			 * we leave all that work to pcap_dispatch
			 * (which in turn calls pcap_read_packet to do
			 * the actual reading).
			 */
			(void)pcap_dispatch(descr, -1, (pcap_handler)got_packet, NULL);

			if(inoutage)
			{
				if (clock_gettime(CLOCK_REALTIME, &oend) == -1)
				{
					logmsg(LOG_ERR, "clock_gettime failed: %s", strerror(errno));
					exit_request = 1;
				}

				/* Calculate timediff */
				oend.tv_sec -= ostart.tv_sec;
				oend.tv_nsec -= ostart.tv_nsec;

				/* Add elapsed timer. FIXME: Optional? */
				/*
				oend.tv_sec += new_value.it_interval.tv_sec;
				oend.tv_nsec += new_value.it_interval.tv_nsec;
				if(oend.tv_nsec >= 1000000000)
				{
					oend.tv_sec++;
					oend.tv_nsec -= 1000000000;
				}
				else */if(oend.tv_nsec < 0)
				{
					oend.tv_sec--;
					oend.tv_nsec += 1000000000;
				}

				interval = oend.tv_sec * 1000 + oend.tv_nsec / 1000000;
				logmsg(LOG_INFO, "Outage recovered after %llu ms", interval);

				inoutage = 0;
			}
			gotpacket = 1;
		}

		/* Handle timer */
		if (pfd[1].revents) {
			s = read(tfd, &exp, sizeof(uint64_t));
			if (s != sizeof(uint64_t))
				logmsg(LOG_DEBUG, "Timer fd read fail.");
			if(!gotpacket && !inoutage)
			{
				if (clock_gettime(CLOCK_REALTIME, &ostart) == -1)
				{
					logmsg(LOG_ERR, "clock_gettime failed: %s", strerror(errno));
					exit_request = 1;
				}
				logmsg(LOG_DEBUG, "Outage detected: No packet within deadline.");

				inoutage = 1;
			}
			gotpacket = 0;
		}

		if (error)
			logmsg(LOG_WARNING, errmsg);

		if (exit_request)
		{
			logmsg(LOG_WARNING, "Exiting on system/user request.");
			break;
		}
	}

	logmsg(LOG_DEBUG, "Closing packet capture device.");
	pcap_close(descr);
	exit(EXIT_SUCCESS);
	return 0;
}
