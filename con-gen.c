#include "./bsd44/socket.h"
#include "./bsd44/tcp_var.h"
#include "./bsd44/udp_var.h"
#include "./bsd44/icmp_var.h"
#include "./bsd44/if_ether.h"
#include "./gbtcp/timer.h"
#include <getopt.h>
#include <pthread.h>
#ifndef __linux__
#include <pthread_np.h>
#endif

static int connections = 0;
static int nclients;
static int concurrency = 1;
static int nflag = 0;
static int Nflag;
static int burst_size = 256;
static int so_debug_flag;
static int verbose;
static char http[1500];
static int http_len;
static be16_t port;
static struct nm_desc *nmd;
static struct timer report_timer;
static uint64_t report_time;
int tx_full;
int if_mtu = 552;
uint64_t tsc_hz;
uint64_t tsc_mhz;
uint64_t nanosec;
uint64_t tsc;
u_char eth_laddr[6];
u_char eth_faddr[6];
uint32_t ip_laddr_min, ip_laddr_max;
uint32_t ip_faddr_min, ip_faddr_max;
uint64_t if_ibytes;
uint64_t if_ipackets;
uint64_t if_obytes;
uint64_t if_opackets;
uint64_t if_imcasts;

struct dllist so_txq;
struct	tcpstat tcpstat;
struct  udpstat udpstat;
uint32_t tcp_now;		/* for RFC 1323 timestamps */
static uint64_t tcp_nowage;
struct	icmpstat icmpstat;

int print_stat(int);
void print_conns();

static const char *
norm2(char *buf, double val, char *fmt, int normalize)
{
	char *units[] = { "", "K", "M", "G", "T" };
	u_int i;
	if (normalize)
		for (i = 0; val >=1000 && i < sizeof(units)/sizeof(char *) - 1; i++)
			val /= 1000;
	else
		i=0;
	sprintf(buf, fmt, val, units[i]);
	return buf;
}

static const char *
norm(char *buf, double val, int normalize)
{
	if (normalize) {
		return norm2(buf, val, "%.3f %s", normalize);
	} else {
		return norm2(buf, val, "%.0f %s", normalize);
	}
}

union tsc {
	uint64_t u_64;
	struct {
		uint32_t lo_32;
		uint32_t hi_32;
	};
};

static uint64_t
rdtsc()
{
	union tsc tsc;

	asm volatile("rdtsc" :
		"=a" (tsc.lo_32),
		"=d" (tsc.hi_32));
	return tsc.u_64;
}


static int done;

static void
sighandler(int signum)
{
	done = 1;
}

union cli {
	struct {
		int cli_connected;
		int cli_rnrn;
	};
	uint64_t cli_u64;
};

union srv {
	struct {
		int srv_rnrn;
	};
	uint64_t srv_u64;	
};

static int
search_rnrn(const char *s, int len, int *ctx)
{
	int i;

	for (i = 0; i < len; ++i) {
		assert(*ctx < 4);
		if (s[i] == ("\r\n\r\n")[*ctx]) {
			(*ctx)++;
			if (*ctx == 4) {
				return 1;
			}
		} else if (s[i] == '\r') {
			*ctx = 1;
		} else {
			*ctx = 0;
		}
	}
	return 0;
}

static void cli_process(struct socket *, short,
                        struct sockaddr_in *, void *, int);
static void srv_process(struct socket *, short,
                        struct sockaddr_in *, void *, int);

static int
cli_connect()
{
	int rc;
	struct sockaddr_in addr;
	struct socket *so;

	rc = usr_socket(IPPROTO_TCP, &so);
	if (rc < 0) {
		return rc;
	}
	so->so_userfn = cli_process;
	so->so_user = 0;
	if (so_debug_flag) {
		sosetopt(so, SO_DEBUG);
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip_faddr_min);
	addr.sin_port = port;
	rc = usr_connect(so, &addr);
	if (rc == 0) {
		nclients++;
	} else {
		usr_close(so);
	}
	return rc;
}

static void
udp_echo(struct socket *so, short events,
         struct sockaddr_in *addr, void *dat, int len)
{
	usr_sendto(so, dat, len, MSG_NOSIGNAL, addr);
}


static void
srv_accept(struct socket *so, short events,
           struct sockaddr_in *addr, void *dat, int len)
{
	int rc;
	struct socket *aso;

	do {
		rc = usr_accept(so, &aso);
		if (rc == 0) {
			aso->so_user = 0;
			aso->so_userfn = srv_process;
		}
	} while (rc != -EWOULDBLOCK);
}

static int
srv_listen(int proto)
{
	int rc;
	struct socket *so;

	rc = usr_socket(proto, &so);
	if (rc < 0) {
		return rc;
	}
	if (so_debug_flag) {
		sosetopt(so, SO_DEBUG);
	}
	so->so_userfn = proto == IPPROTO_TCP ? srv_accept : udp_echo;
	so->so_user = 0;
	rc = usr_bind(so, port);
	if (rc) {
		goto err;
	}
	if (proto == IPPROTO_TCP) {
		rc = usr_listen(so);
		if (rc) {
			goto err;
		}
	}
	return 0;
err:
	usr_close(so);
	return rc;
}

static void
con_close(struct socket *so, int isclient)
{
	usr_close(so);
	connections++;
	if (nflag) {
		if (connections == nflag) {
			done = 1;
		}
	}
	if (isclient) {
		nclients--;
		while (nclients < concurrency) {
			cli_connect();
		}
	}
}

static void
cli_process(struct socket *so, short events,
            struct sockaddr_in *addr, void *dat, int len)
{
	int rc;
	union cli *cli;

	cli = (union cli *)&so->so_user;
	if (cli->cli_connected == 0) {
		if (events|POLLOUT) {
			cli->cli_connected = 1;
			rc = usr_sendto(so, http, http_len, MSG_NOSIGNAL, NULL);
			assert(rc == http_len);
		}
	}
	if (len) {
		rc = search_rnrn(dat, len, &cli->cli_rnrn);
		if (rc) {
			goto close;
		}
	}
	if ((events & POLLERR) || ((events & POLLIN) && len == 0)) {
close:
		con_close(so, 1);
	}
}

static void
srv_process(struct socket *so, short events,
            struct sockaddr_in *addr, void *dat, int len)
{
	int rc;
	union srv *srv;

	srv = (union srv *)&so->so_user;
	if (len) {
		rc = search_rnrn(dat, len, &srv->srv_rnrn);
		if (rc) {
			rc = usr_sendto(so, http, http_len, MSG_NOSIGNAL, NULL);
			assert(rc == http_len);
			goto close;

		}
	}
	if ((events & POLLERR) || ((events & POLLIN) && len == 0)) {
close:
		con_close(so, 0);
	}
}


//void domaininit();

void ether_input(struct ether_header *eh, int len);

struct netmap_ring *
not_empty_txr(struct netmap_slot **pslot)
{
	int i;
	struct netmap_ring *txr;

	if (tx_full) {
		return NULL;
	}
	for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; ++i) {
		txr = NETMAP_TXRING(nmd->nifp, i);
		if (!nm_ring_empty(txr)) {
			if (pslot != NULL) {
				*pslot = txr->slot + txr->cur;
				(*pslot)->len = 0;
			}
			return txr;	
		}
	}
	tx_full = 1;
	return NULL;
}

static void
rx()
{
	int i, j, n, len;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;
	struct ether_header *et;

	for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(nmd->nifp, i);
		n = nm_ring_space(rxr);
		if (n > burst_size) {
			n = burst_size;
		}
		for (j = 0; j < n; ++j) {
			slot = rxr->slot + rxr->cur;
			et = (struct ether_header *)NETMAP_BUF(rxr, slot->buf_idx);
			et->ether_type = ntohs(et->ether_type);
			len = slot->len - sizeof(*et);
			assert(len >= 0);
			ether_input(et, len);
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
	}
}

void
process_events()
{
	int rc;
	uint64_t t;
	char buf[32];
	struct pollfd pfds[2];
	struct socket *so;

	pfds[0].fd = nmd->fd;
	pfds[0].events = POLLIN;
	if (tx_full) {
		pfds[0].events |= POLLOUT;
	}
	pfds[1].fd = STDIN_FILENO;
	pfds[1].events = POLLIN;
	poll(pfds, 2, 10);
	t = rdtsc();
	if (t > tsc) {
		tsc = t;
		nanosec = 1000 * tsc / tsc_mhz;
		while (nanosec >= tcp_nowage + TM_1SEC/PR_SLOWHZ) {
			tcp_now++;
			tcp_nowage += TM_1SEC/PR_SLOWHZ;
		}
	}
	timer_checktimo();
	if (pfds[0].revents & POLLIN) {
		rx();
	}
	if (pfds[0].revents & POLLOUT) {
		tx_full = 0;
	}
	while (!dllist_empty(&so_txq)) {
		so = DLLIST_FIRST(&so_txq, struct socket, so_txlist);
		if (not_empty_txr(NULL) == NULL) {
			break;
		}
		rc = tcp_output_real(sototcpcb(so));
		if (rc <= 0) {
			DLLIST_REMOVE(so, so_txlist);
			so->so_state &= ~SS_ISTXPENDING;
			sofree(so);
		}
	}
	if (pfds[1].revents & POLLIN) {
		rc = read(STDOUT_FILENO, buf, sizeof(buf));
		if (rc > 1) {
			switch (buf[0]) {
			case 's':
				print_stat(verbose);
				break;
			case 'c':
				print_conns();
				break;
			}
		}
	}
}

void
panic3(const char *file, int line, const char *format, ...)
{
	va_list ap;

	fprintf(stderr, "%s:%d: ", file, line);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	abort();
}

void *
xmalloc(unsigned long size)
{
	void *ptr;

	ptr = malloc(size);
	return ptr;
}

void
xfree(void *addr, int type)
{
	free(addr);
}

static int
iprange_scanf(uint32_t *pmin, uint32_t *pmax, const char *s)
{
	char *p;
	int rc;
	struct in_addr min, max;
	char buf[2*INET_ADDRSTRLEN + 2];

	strncpy(buf, s, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
	p = strchr(buf, '-');
	if (p != NULL) {
		*p = '\0';
	}
	rc = inet_aton(buf, &min);
	if (!rc) {
		return -EINVAL;
	}
	NTOHL(min.s_addr);
	if (p == NULL) {
		max = min;
	} else {
		rc = inet_aton(p + 1, &max);
		if (!rc) {
			return -EINVAL;
		}
		NTOHL(max.s_addr);
		if (min.s_addr > max.s_addr) {
			return -EINVAL;
		}
	}
	*pmin = min.s_addr;
	*pmax = max.s_addr;
	return 0;		
}

#ifdef __linux__
typedef cpu_set_t cpuset_t;
#endif

static int
set_affinity(int cpu_id)
{
	int rc;
	cpuset_t x;

	CPU_ZERO(&x);
	CPU_SET(cpu_id, &x);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(x), &x);
	if (rc) {
		fprintf(stderr, "pthread_setaffinity_np(%d) failed", cpu_id);
		return -rc;
	}
	return 0;
}

int in_init();

int
init(const char *ifname)
{
	int len, rc;
	uint64_t t;
	char nbuf[IFNAMSIZ + 16];

	srand(getpid() ^ time(NULL));


	dllist_init(&so_txq);

	len = strlen(ifname);
	if (len >= IFNAMSIZ) {
		return EINVAL;
	}
	snprintf(nbuf, sizeof(nbuf), "netmap:%s", ifname);
	nmd = nm_open(nbuf, NULL, 0, NULL);
	if (nmd == NULL) {
		rc = errno;
		fprintf(stderr, "nm_open('%s') failed (%s)\n",
		        nbuf, strerror(rc));
		return rc;
	}

	t = rdtsc();
	usleep(10000);
	tsc = rdtsc();
	tsc_hz = (tsc - t) * 100;
	tsc_mhz = tsc_hz / 1000000;
	assert(tsc_hz);
	nanosec = 1000 * tsc / tsc_mhz;
	tcp_now = 1;
	tcp_nowage = nanosec;
	timer_modinit();
	rc = in_init();
	if (rc) {
		exit(10);
	}

	return 0;
}

static void
report(struct timer *timer)
{
	static int n;
	static uint64_t old_ipackets, old_ibytes;
	static uint64_t old_opackets, old_obytes;
	static uint64_t old_closed, old_sndrexmitpack;
	double dt, ipps, ibps, opps, obps, cps, rxmtps;
	char b1[40], b2[40], b3[40], b4[40], b5[40], b6[40];

	if (n == 0) {
		printf("%-10s%-10s%-10s%-10s%-10s%s\n",
		       "ipps", "ibps", "opps", "obps", "cps",  "rxmtps");
	}
	n++;
	if (n == 20) {
		n = 0;
	}
	dt = (double)(nanosec - report_time) / TM_1SEC;
	report_time = nanosec;
	ipps = (if_ipackets - old_ipackets) / dt;
	old_ipackets = if_ipackets;
	ibps = (if_ibytes - old_ibytes) / dt;
	old_ibytes = if_ibytes;
	opps = (if_opackets - old_opackets) / dt;
	old_opackets = if_opackets;
	obps = (if_obytes - old_obytes) / dt;
	old_obytes = if_obytes;
	cps = (tcpstat.tcps_closed - old_closed) / dt;
	old_closed = tcpstat.tcps_closed;
	rxmtps = (tcpstat.tcps_sndrexmitpack - old_sndrexmitpack) / dt;
	old_sndrexmitpack = tcpstat.tcps_sndrexmitpack;
	norm(b1, ipps, Nflag);
	norm(b2, ibps, Nflag);
	norm(b3, opps, Nflag);
	norm(b4, obps, Nflag);
	norm(b5, cps, Nflag);
	norm(b6, rxmtps, Nflag);
	printf("%-10s%-10s%-10s%-10s%-10s%s\n",
	       b1, b2, b3, b4, b5, b6);
	timer_set(timer, TM_1SEC, report);
}

static void
usage()
{
	printf(
	"Usage: con-gen [options] { -i interface }\n"
	"\n"
	"Options:\n"
	"\t-h,--help: Print this help\n"
	"\t-v,--verbose: Be verbose\n"
	"\t-i {interface}:  To operate on\n"
	"\t-p {port}:  Server port (default: 80)\n"
	"\t-s {ip[:port[-ip:port]]}: Source ip-port range\n"
	"\t-d {ip[:port[-ip:port]]): Destination ip-port range\n"
	"\t-S {hwaddr}: Source ethernet address\n"
	"\t-D {hwaddr}: Destination ethernet address\n"
	"\t-c {num}: Number of parallel connections\n"
	"\t-a {cpu-id}: Set affinity\n"
	"\t-n {num}: Number of connections to perform\n"
	"\t-b {num}: Burst size\n"
	"\t-L: Operate in server mode\n"
	"\t--so-debug: Enable SO_DEBUG option\n"
	"\t--udp: Use UDP instead of TCP\n"
	"\t--tcp-wscale: Use wscale TCP option\n"
	"\t--tcp-timestamps: Use timestamp TCP option\n"
	"\t--tcp-fin-timeout {seconds}: Specify FIN timeout\n"
	"\t--tcp-timewait-timeout {seconds}: Specify TIME_WAIT timeout\n"
	);
}

static struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "verbose", no_argument, 0, 'v' },
	{ "udp", no_argument, 0, 0 },
	{ "so-debug", no_argument, 0, 0 },
	{ "tcp-wscale", optional_argument, 0, 0 },
	{ "tcp-timestamps", optional_argument, 0, 0 },
	{ "tcp-fin-timeout", required_argument, 0, 0 },
	{ "tcp-timewait-timeout", required_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

int
main(int argc, char **argv)
{
	int rc, opt, Lflag, option_index, udp_flag;
	long long optval;
	const char *ifname;
	char hostname[64];
	const char *optname;

	port = htons(80);
	Lflag = 0;
	udp_flag = 0;
	ifname = NULL;
	iprange_scanf(&ip_laddr_min, &ip_laddr_max, "10.0.0.1");
	iprange_scanf(&ip_faddr_min, &ip_faddr_max, "10.1.0.1");
	ether_scanf(eth_laddr, "00:00:00:00:00:00");
	ether_scanf(eth_faddr, "ff:ff:ff:ff:ff:ff");
	while ((opt = getopt_long(argc, argv,
	                          "hvi:s:d:S:D:a:n:b:c:p:NL",
	                          long_options, &option_index)) != -1) {
		optval = optarg ? strtoll(optarg, NULL, 10) : 0;
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "udp")) {
				udp_flag = 1;
			} else if (!strcmp(optname, "so-debug")) {
				so_debug_flag = 1;
			} else if (!strcmp(optname, "tcp-wscale")) {
				if (optarg == NULL) {
					tcp_do_wscale = 1;
				} else {
					tcp_do_wscale = optval;
				}
			} else if (!strcmp(optname, "tcp-timestamps")) {
				if (optarg == NULL) {
					tcp_do_timestamps = 1;
				} else {
					tcp_do_timestamps = optval;
				}
			} else if (!strcmp(optname, "tcp-fin-timeout")) {
				if (optval < 30) {
					goto invalidarg;
				}
				tcp_fintimo = optval * TM_1SEC;
				break;
			} else if (!strcmp(optname, "tcp-timewait-timeout")) {
				tcp_twtimo = optval * TM_1SEC;
				break;
			}
			break;
		case 'h':
			usage();
			return 0;
		case 'v':
			verbose++;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 's':
			rc = iprange_scanf(&ip_laddr_min, &ip_laddr_max, optarg);
			if (rc) {
				goto invalidarg;
			}
			break;
		case 'd':
			rc = iprange_scanf(&ip_faddr_min, &ip_faddr_max, optarg);
			if (rc) {
				goto invalidarg;
			}
			break;
		case 'S':
			rc = ether_scanf(eth_laddr, optarg);
			if (rc) {
				goto invalidarg;
			}
			break;
		case 'D':
			rc = ether_scanf(eth_faddr, optarg);
			if (rc) {
				goto invalidarg;
			}
			break;
		case 'a':
			rc = set_affinity(optval);
			if (rc) {
				goto invalidarg;
			}
			break;
		case 'n':
			nflag = optval;
			break;
		case 'b':
			burst_size = strtoul(optarg, NULL, 10);
			if (!burst_size) {
				goto invalidarg;
			}
			break;
		case 'c':
			concurrency = strtoul(optarg, NULL, 10);
			if (!concurrency) {
				goto invalidarg;
			}
			break;
		case 'p':
			port = htons(strtoul(optarg, NULL, 10));
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'L':
			Lflag = 1;
			break;
		default:
invalidarg:
			fprintf(stderr, "invalid argument '-%c': %s\n",
			        opt, optarg);
			return 2;
		}
	}
	if (ifname == NULL) {
		usage();
		return 1;
	}
	init(ifname);
	signal(SIGINT, sighandler);

	rc = gethostname(hostname, sizeof(hostname));
	if (rc == -1) {
		fprintf(stderr, "gethostname() failed (%s)\n",
		        strerror(errno));
		strcpy(hostname, "127.0.0.1");
	} else {
		hostname[sizeof(hostname) - 1] = '\0';
	}
	if (udp_flag) {
		srv_listen(IPPROTO_UDP);
	} else if (Lflag) {
		http_len = snprintf(http, sizeof(http), 
			"HTTP/1.0 200 OK\r\n"
			"Server: con-gen\r\n"
			"Content-Type: text/html\r\n"
			"Connection: close\r\n"
			"Hi\r\n\r\n");
		srv_listen(IPPROTO_TCP);
	} else {
		http_len = snprintf(http, sizeof(http),
			"GET / HTTP/1.0\r\n"
			"Host: %s\r\n"
			"User-Agent: con-gen\r\n"
			"\r\n",
			hostname);
		cli_connect();
	}
	report_time = nanosec;
	timer_init(&report_timer);
	timer_set(&report_timer, TM_1SEC, report);
	while (!done) {
		process_events();
	}
	print_stat(verbose);
	return 0;
}
