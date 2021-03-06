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
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>	/* Definition of uint64_t */

#define MAXBUF 2048	/* Length of log message buffer */
#define SNAP_LEN 1518	/* Packet capture snaplength */
#define INTV_MIN 1ULL	/* milliseconds */
#define INTV_MAX 18446744073709ULL	/* milliseconds */
#define TSTAMPFMT "%Y-%m-%dT%H:%M:%S"

char *iface = NULL;
char *bpf = NULL;
int i, daemonize = 1;
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

void usage(char* prog)
{
	printf("Usage: %s -i <iface> [options]\n", prog);
	printf("Options:\n");
	printf("  -w n   Set deadline to n milliseconds.\n");
	printf("  -D     Run in foreground. Log to stderr.\n");
}

/* from
 * http://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 */
int getcmdline(int argc, char **argv)
{
	int c;

	opterr = 0;

	while((c = getopt(argc, argv, "hi:w:fD")) != -1)
		switch (c)
		{
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 'i':
				iface = optarg;
				break;
			case 'w':
				/* milliseconds */
				interval = strtoll(optarg, NULL, 10);
				if(interval < INTV_MIN)
				{
					fprintf(stderr, "Fatal: Interval must be >= %lld ms\n", INTV_MIN);
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'D':
				daemonize = 0;
				break;
			case '?':
				if(optopt == 'i' || optopt == 'w')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if(isprint (optopt))
					fprintf(stderr, "Fatal: Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Fatal: Unknown option character `\\x%x'.\n", optopt);
				usage(argv[0]);
				exit(EXIT_FAILURE);
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}

	/* iface arg is required */
	if(iface == NULL)
	{
		fprintf(stderr, "Fatal: No interface specified.\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* the rest is the bpf, even if empty */
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
	struct timeval tstart, tend;
	uint64_t tdiff;
	time_t ttmp;
	char tstamp[20];
	suseconds_t ustmp;
	pid_t pid;

	getcmdline(argc, argv);

	/* open capture device */
	descr = pcap_open_live(iface, SNAP_LEN, 1, 0, errbuf);
	if (descr == NULL) {
		fprintf(stderr, "pcap_open_live failed (%s): %s\n", iface, errbuf);
		exit(EXIT_FAILURE);
	}

	/* apply the filter */
	if (pcap_compile(descr, &fp, bpf, 0, 0) == -1) {
		fprintf(stderr, "pcap_compile failed (%s): %s\n", iface, pcap_geterr(descr));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed (%s): %s\n", iface, pcap_geterr(descr));
		exit(EXIT_FAILURE);
	}

	signal(SIGTERM, sighand_exit);
	signal(SIGINT, sighand_exit);

	/* prepare for poll loop */
	int inoutage = 0;	/* state switch */
	char errmsg[1024];	/* XXX - arbitrary size */
	int error = 0;
	int nfds;
	struct pollfd pfd[1];

	/* stuff to poll */
	pfd[0].fd = pcap_fileno(descr);
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;

	if (daemonize && daemon(0, 0))
		fprintf(stderr, "daemon() failed. Staying in foreground.\n");

	/* Get pid after forking. The pid is simply used to identify
	 * instances of the program running simultaneously.
	 */
	pid = getpid();

	if (daemonize)
		openlog("tcpwatch", LOG_CONS, LOG_DAEMON);
	logmsg(LOG_NOTICE, "Starting with %llums deadline and filter: `%s'", interval, bpf);

	/* Main loop */
	for(;;)
	{
		nfds = poll(pfd, 1, interval);
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
				if (gettimeofday(&tend, NULL) == -1)
				{
					logmsg(LOG_ERR, "gettimeofday failed: %s", strerror(errno));
					exit_request = 1;
				}

				ttmp = time(NULL);
				strftime(tstamp, sizeof(tstamp), TSTAMPFMT, localtime(&ttmp));
				ustmp = tend.tv_usec;

				/* Calculate timediff */
				tend.tv_sec -= tstart.tv_sec;
				tend.tv_usec -= tstart.tv_usec;

				if(tend.tv_usec < 0)
				{
					tend.tv_sec--;
					tend.tv_usec += 1000000;
				}

				tdiff = tend.tv_sec * 1000 + tend.tv_usec / 1000;
				logmsg(LOG_INFO, "(PID %d) %s.%03ld Outage recovered (%llu ms downtime).",
						pid,
						tstamp,
						ustmp/1000,
						tdiff);

				inoutage = 0;
			}
		}

		/* Handle poll timeout */
		if(!nfds)
		{
			if(!inoutage)
			{
				if (gettimeofday(&tstart, NULL) == -1)
				{
					logmsg(LOG_ERR, "gettimeofday failed: %s", strerror(errno));
					exit_request = 1;
				}
				ttmp = time(NULL);
				strftime(tstamp, sizeof(tstamp), TSTAMPFMT, localtime(&ttmp));
				logmsg(LOG_DEBUG, "(PID %d) %s.%03ld Outage detected (%llu ms deadline).",
						pid,
						tstamp,
						tstart.tv_usec/1000,
						interval);
				inoutage = 1;
			}
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
