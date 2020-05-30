#include "./bsd44/socket.h"
//#include "./bsd44/tcp_var.h"
//#include "./bsd44/udp_var.h"
//#include "./bsd44/icmp_var.h"
#include "./bsd44/if_ether.h"
#include "./bsd44/ip.h"
#include "./gbtcp/timer.h"
#include "netstat.h"
#include <getopt.h>
#include <pthread.h>
#ifndef __linux__
#include <pthread_np.h>
#endif

int nflag = 0;
int concurrency = 1;

static int Nflag;
static int burst_size = 256;
static struct timer report_timer;
static uint64_t report_time;
static int report_bytes_flag;
int if_mtu = 552;
uint64_t tsc_hz;
uint64_t tsc_mhz;
uint64_t nanosec;
uint64_t tsc;
uint64_t if_ibytes;
uint64_t if_ipackets;
uint64_t if_obytes;
uint64_t if_opackets;
uint64_t if_imcasts;

uint32_t tcp_now;		/* for RFC 1323 timestamps */
static uint64_t tcp_nowage;

void bsd_eth_in(void *, int);
void bsd_flush();
void bsd_server_listen(int);
void bsd_client_connect();
uint32_t bsd_socket_hash(struct dlist *);

void toy_eth_in(void *, int);
void toy_flush();
void toy_server_listen(int);
void toy_client_connect();
uint32_t toy_socket_hash(struct dlist *);

void toy_eth_in(void *, int);
void toy_flush();
void toy_server_listen(int);
void toy_client_connect();
uint32_t toy_socket_hash(struct dlist *);

static const char *
norm2(char *buf, double val, char *fmt, int normalize)
{
	char *units[] = { "", "k", "m", "g", "t" };
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
		return norm2(buf, val, "%.3f%s", normalize);
	} else {
		return norm2(buf, val, "%.0f%s", normalize);
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

static void
sighandler(int signum)
{
	done = 1;
}


static void
rx()
{
	int i, j, n;
	void *buf;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;

	for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(nmd->nifp, i);
		n = nm_ring_space(rxr);
		if (n > burst_size) {
			n = burst_size;
		}
		for (j = 0; j < n; ++j) {
			DEV_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			buf = NETMAP_BUF(rxr, slot->buf_idx);
			if (slot->len >= 14) {
				if (use_toy) {
					toy_eth_in(buf, slot->len);
				} else {
					bsd_eth_in(buf, slot->len);
				}
			}
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
		while (nanosec >= tcp_nowage + NANOSECONDS_SECOND/PR_SLOWHZ) {
			tcp_now++;
			tcp_nowage += NANOSECONDS_SECOND/PR_SLOWHZ;
		}
	}
	check_timers();
	if (pfds[0].revents & POLLIN) {
		rx();
	}
	if (pfds[0].revents & POLLOUT) {
		tx_full = 0;
	}
	if (use_toy) {
		toy_flush();
	} else {
		bsd_flush();
	}
	if (pfds[1].revents & POLLIN) {
		rc = read(STDOUT_FILENO, buf, sizeof(buf));
		if (rc > 1) {
			switch (buf[0]) {
			case 's':
				pr_stats(verbose);
				break;
			case 'c':
				pr_sockets();
				break;
			}
		}
	}
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

int
init(const char *ifname)
{
	int i, rc, len;
	uint64_t t;
	char nbuf[IFNAMSIZ + 16];

	srand(getpid() ^ time(NULL));
	dlist_init(&so_txq);
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
	timer_mod_init();
	n_if_addrs = ip_laddr_max - ip_laddr_min + 1;
	assert(n_if_addrs > 0);
	if (n_if_addrs > 100) {
		n_if_addrs = 100;
	}
	if_addrs = xmalloc(n_if_addrs * sizeof(struct if_addr));
	for (i = 0; i < n_if_addrs; ++i) {
		ifaddr_init(if_addrs + i);
	}
	htable_init(&in_htable, 1024,
	            use_toy ? toy_socket_hash : bsd_socket_hash);
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
	char cps_b[40], ipps_b[40], ibps_b[40], opps_b[40], obps_b[40];
	char rxmtps_b[40];

	if (n == 0) {
		printf("%-10s%-10s", "cps", "ipps");
		if (report_bytes_flag) {
			printf("%-10s", "ibps");
		}
		printf("%-10s", "opps");
		if (report_bytes_flag) {
			printf("%-10s","obps");
		}
		printf("%s\n", "rxmtps");
	}
	n++;
	if (n == 20) {
		n = 0;
	}
	dt = (double)(nanosec - report_time) / NANOSECONDS_SECOND;
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
	norm(cps_b, cps, Nflag);
	norm(ipps_b, ipps, Nflag);
	norm(ibps_b, ibps, Nflag);
	norm(opps_b, opps, Nflag);
	norm(obps_b, obps, Nflag);
	norm(rxmtps_b, rxmtps, Nflag);
	printf("%-10s%-10s", cps_b, ipps_b);
	if (report_bytes_flag) {
		printf("%-10s", ibps_b);
	}
	printf("%-10s", opps_b);
	if (report_bytes_flag) {
		printf("%-10s", obps_b);
	}
	printf("%s\n", rxmtps_b);
	timer_set(timer, NANOSECONDS_SECOND, report);
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
	"\t-s {ip[-ip]]}: Source ip range\n"
	"\t-d {ip[:port[-ip:port]]): Destination ip range\n"
	"\t-S {hwaddr}: Source ethernet address\n"
	"\t-D {hwaddr}: Destination ethernet address\n"
	"\t-c {num}: Number of parallel connections\n"
	"\t-a {cpu-id}: Set affinity\n"
	"\t-n {num}: Number of connections to perform\n"
	"\t-b {num}: Burst size\n"
	"\t-L: Operate in server mode\n"
	"\t--so-debug: Enable SO_DEBUG option\n"
	"\t--udp: Use UDP instead of TCP\n"
	"\t--toy: Use top tcp/ip stack instead of bsd4.4 (it is a bit faster)\n"
	"\t--ip-in-cksum: On/Off IP input checksum calculation\n"
	"\t--ip-out-cksum: On/Off IP output checksum calculation\n"
	"\t--tcp-in-cksum: On/Off TCP input checksum calculation\n"
	"\t--tcp-wscale: On/Off wscale TCP option\n"
	"\t--tcp-timestamps: On/Off timestamp TCP option\n"
	"\t--tcp-fin-timeout {seconds}: Specify FIN timeout\n"
	"\t--tcp-timewait-timeout {seconds}: Specify TIME_WAIT timeout\n"
	"\t--report-bytes: On/Off byte statistic in report\n"
	);
}

static struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "verbose", no_argument, 0, 'v' },
	{ "udp", no_argument, 0, 0 },
	{ "toy", no_argument, 0, 0 },
	{ "so-debug", no_argument, 0, 0 },
	{ "ip-in-cksum", optional_argument, 0, 0 },
	{ "ip-out-cksum", optional_argument, 0, 0 },
	{ "tcp-in-cksum", optional_argument, 0, 0 },
	{ "tcp-out-cksum", optional_argument, 0, 0 },
	{ "tcp-wscale", optional_argument, 0, 0 },
	{ "tcp-timestamps", optional_argument, 0, 0 },
	{ "tcp-fin-timeout", required_argument, 0, 0 },
	{ "tcp-timewait-timeout", required_argument, 0, 0 },
	{ "report-bytes", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

int
main(int argc, char **argv)
{
	int rc, opt, ipproto, option_index, udp_flag;
	long long optval;
	const char *ifname;
	char hostname[64];
	const char *optname;

	pflag_port = htons(80);
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
			} else if (!strcmp(optname, "toy")) {
				use_toy = 1;
			} else if (!strcmp(optname, "so-debug")) {
				so_debug_flag = 1;
			} else if (!strcmp(optname, "ip-in-cksum")) {
				if (optarg == NULL) {
					ip_do_incksum = 1;
				} else {
					ip_do_incksum = optval;
				}
			} else if (!strcmp(optname, "ip-out-cksum")) {
				if (optarg == NULL) {
					ip_do_outcksum = 1;
				} else {
					ip_do_outcksum = optval;
				}
			} else if (!strcmp(optname, "tcp-in-cksum")) {
				if (optarg == NULL) {
					tcp_do_incksum = 1;
				} else {
					tcp_do_incksum = optval;
				}
			} else if (!strcmp(optname, "tcp-out-cksum")) {
				if (optarg == NULL) {
					tcp_do_outcksum = 1;
				} else {
					tcp_do_outcksum = optval;
				}
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
					goto err;
				}
				tcp_fintimo = optval * NANOSECONDS_SECOND;
				break;
			} else if (!strcmp(optname, "tcp-timewait-timeout")) {
				tcp_twtimo = optval * NANOSECONDS_SECOND;
				break;
			} else if (!strcmp(optname, "report-bytes")) {
				report_bytes_flag = 1;
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
				goto err;
			}
			break;
		case 'd':
			rc = iprange_scanf(&ip_faddr_min, &ip_faddr_max, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'S':
			rc = ether_scanf(eth_laddr, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'D':
			rc = ether_scanf(eth_faddr, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'a':
			rc = set_affinity(optval);
			if (rc) {
				goto err;
			}
			break;
		case 'n':
			nflag = optval;
			break;
		case 'b':
			burst_size = strtoul(optarg, NULL, 10);
			if (!burst_size) {
				goto err;
			}
			break;
		case 'c':
			concurrency = strtoul(optarg, NULL, 10);
			if (!concurrency) {
				goto err;
			}
			break;
		case 'p':
			pflag_port = htons(strtoul(optarg, NULL, 10));
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'L':
			Lflag = 1;
			break;
		default:
err:
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
	if (Lflag) {
		http_len = snprintf(http, sizeof(http), 
			"HTTP/1.0 200 OK\r\n"
			"Server: con-gen\r\n"
			"Content-Type: text/html\r\n"
			"Connection: close\r\n"
			"Hi\r\n\r\n");
	} else {
		http_len = snprintf(http, sizeof(http),
			"GET / HTTP/1.0\r\n"
			"Host: %s\r\n"
			"User-Agent: con-gen\r\n"
			"\r\n",
			hostname);
	}
	if (Lflag || udp_flag) {
		ipproto = udp_flag ? IPPROTO_UDP: IPPROTO_TCP;
		if (use_toy) {
			toy_server_listen(ipproto);
		} else {
			bsd_server_listen(ipproto);
		}
	} else {
		if (use_toy) {
			toy_client_connect();
		} else {
			bsd_client_connect();
		}
	}
	report_time = nanosec;
	timer_init(&report_timer);
	timer_set(&report_timer, NANOSECONDS_SECOND, report);
	while (!done) {
		process_events();
	}
	pr_stats(verbose);
	return 0;
}
