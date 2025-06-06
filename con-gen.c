#include "./bsd44/socket.h"
#include "./bsd44/if_ether.h"
#include "./bsd44/ip.h"
#include "./gbtcp/timer.h"
#include "netstat.h"
#include <getopt.h>

struct report_data {
	uint64_t rd_ipackets;
	uint64_t rd_ibytes;
	uint64_t rd_opackets;
	uint64_t rd_obytes;
	uint64_t rd_closed;
	uint64_t rd_sndrexmitpack;
	struct timeval rd_tv;
};

static int m_done;
static int Nflag = 1;
static struct timeval report_tv;
static int report_bytes_flag;
static char http_request[1500];
static char http_reply[1500];
static int http_request_len;
static int http_reply_len;
static struct report_data report01;
static int n_reports;
static int n_reports_max;
static int g_fprint_report = 1;
static int print_banner = 1;
static int print_statistics = 1;

counter64_t if_ibytes;
counter64_t if_ipackets;
counter64_t if_obytes;
counter64_t if_opackets;
counter64_t if_imcasts;

static uint64_t tsc_mhz;

int n_counters = 1;

struct thread threads[N_THREADS_MAX];
int n_threads;
__thread struct thread *current;

static int g_transport = TRANSPORT_DEFAULT;
int g_udp;
int g_toy;

void bsd_flush(void);
void bsd_server_listen(int);
void bsd_client_connect(int proto);

void toy_flush(void);
void toy_server_listen(int);
void toy_client_connect(void);

static const char *
norm2(char *buf, double val, char *fmt, int normalize)
{
	char *units[] = { "", "k", "m", "g", "t" };
	u_int i;
	if (normalize) {
		for (i = 0; val >=1000 && i < sizeof(units)/sizeof(char *) - 1; i++) {
			val /= 1000;
		}
	} else {
		i = 0;
	}
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
rdtsc(void)
{
	union tsc tsc;

	asm volatile("rdtsc" :
		"=a" (tsc.lo_32),
		"=d" (tsc.hi_32));
	return tsc.u_64;
}

static int
scan_ip_range(uint32_t *pmin, uint32_t *pmax, const char *s)
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
		fprintf(stderr, "pthread_setaffinity_np(%d) failed\n", cpu_id);
		return -rc;
	}
	return 0;
}

uint32_t
ip_socket_hash(struct dlist *p)
{
	uint32_t h;
	struct ip_socket *so;

	so = cg_container_of(p, struct ip_socket, ipso_list);
	h = SO_HASH(so->ipso_faddr, so->ipso_lport, so->ipso_fport);
	return h;
}

static void
print_report_diffs(struct report_data *new, struct report_data *old)
{
	double dt, ipps, ibps, opps, obps, pps, bps, cps, rxmtps;
	char ipps_b[40], ibps_b[40];
	char opps_b[40], obps_b[40];
	char pps_b[40], bps_b[40];
	char cps_b[40];
	char rxmtps_b[40];

	dt = (new->rd_tv.tv_sec - old->rd_tv.tv_sec) +
			(new->rd_tv.tv_usec - old->rd_tv.tv_usec) / 1000000.0f;
	ipps = (new->rd_ipackets - old->rd_ipackets) / dt;
	opps = (new->rd_opackets - old->rd_opackets) / dt;
	ibps = (new->rd_ibytes - old->rd_ibytes) / dt;
	obps = (new->rd_obytes - old->rd_obytes) / dt;
	pps = ipps + opps;
	bps = ibps + obps;
	cps = (new->rd_closed - old->rd_closed) / dt;
	rxmtps = (new->rd_sndrexmitpack - old->rd_sndrexmitpack) / dt;
	norm(cps_b, cps, Nflag);
	norm(ipps_b, ipps, Nflag);
	norm(ibps_b, ibps, Nflag);
	norm(opps_b, opps, Nflag);
	norm(obps_b, obps, Nflag);
	norm(pps_b, pps, Nflag);
	norm(bps_b, bps, Nflag);
	norm(rxmtps_b, rxmtps, Nflag);
	printf("%-12s%-12s", cps_b, ipps_b);
	if (report_bytes_flag) {
		printf("%-12s", ibps_b);
	}
	printf("%-10s", opps_b);
	if (report_bytes_flag) {
		printf("%-12s", obps_b);
	}
	printf("%-10s", pps_b);
	if (report_bytes_flag) {
		printf("%-12s", bps_b);
	}
	printf("%-12s", rxmtps_b);
}

static void
print_report(void)
{
	int i;
	static int n;
	struct report_data new;
	int conns;

	if (!g_fprint_report) {
		return;
	}
	if (n == 0 && print_banner) {
		printf("%-12s%-12s", "cps", "ipps");
		if (report_bytes_flag) {
			printf("%-12s", "ibps");
		}
		printf("%-10s", "opps");
		if (report_bytes_flag) {
			printf("%-12s", "obps");
		}
		printf("%-10s", "pps");
		if (report_bytes_flag) {
			printf("%-12s", "bps");
		}
		printf("%-12s", "rxmtps");
		printf("%s\n", "conns");
	}
	conns = 0;
	for (i = 0; i < n_threads; ++i) {
		conns += threads[i].t_n_conns;
	}
	gettimeofday(&new.rd_tv, NULL);
	new.rd_ipackets = counter64_get(&if_ipackets);
	new.rd_opackets = counter64_get(&if_opackets);
	new.rd_ibytes = counter64_get(&if_ibytes);
	new.rd_obytes = counter64_get(&if_obytes);
	new.rd_closed = counter64_get(&tcpstat.tcps_closed);
	new.rd_sndrexmitpack = counter64_get(&tcpstat.tcps_sndrexmitpack);
	print_report_diffs(&new, &report01);
	report01 = new;
	printf("%d\n", conns);
	n++;
	if (n == 20) {
		n = 0;
	}
}

static void
quit(void)
{
	int i;

	m_done = 1;
	for (i = 0; i < n_threads; ++i) {
		threads[i].t_done = 1;
	}
}

static void
sighandler(int signum)
{

	switch (signum) {
	case SIGINT:
		quit();
		break;
	case SIGALRM:
		print_report();
		n_reports++;
		if (n_reports_max != 0 && n_reports == n_reports_max) {
			quit();
		} else {
			alarm(1);
		}
		break;
	}
}

static void
thread_init_dst_cache(struct thread *t)
{
	uint64_t i, n;
	int dst_cache_size;
	uint32_t h;
	uint32_t ip_laddr_connect;
	uint32_t ip_faddr_connect;
	uint16_t ip_lport_connect;
	be32_t laddr, faddr;
	be16_t lport, fport;
	struct ip_socket *so;

	t->t_dst_cache = malloc(t->t_dst_cache_size * sizeof(struct ip_socket));
	if (t->t_dst_cache == NULL) {
		panic(0, "Not enough memory to allocate dst cache");
	}

	ip_laddr_connect = t->t_ip_laddr_min;
	ip_lport_connect = EPHEMERAL_MIN;
	ip_faddr_connect = t->t_ip_faddr_min;
	dst_cache_size = 0;
	n = (t->t_ip_laddr_max - t->t_ip_laddr_min + 1) * 
		(t->t_ip_faddr_max - t->t_ip_faddr_min + 1) * NEPHEMERAL;

	for (i = 0; i < n; ++i) {
		laddr = htonl(ip_laddr_connect);
		faddr = htonl(ip_faddr_connect);
		lport = htons(ip_lport_connect);
		fport = t->t_port;
		if (ip_faddr_connect < t->t_ip_faddr_max) {
			ip_faddr_connect++;
		} else {
			ip_faddr_connect = t->t_ip_faddr_min;
			if (ip_lport_connect < EPHEMERAL_MAX) {
				ip_lport_connect++;
			} else {
				ip_lport_connect = EPHEMERAL_MIN;
				if (ip_laddr_connect < t->t_ip_laddr_max) {
					ip_laddr_connect++;
				} else {
					ip_laddr_connect = t->t_ip_laddr_min;
				}
			}
		}
		if (t->t_rss_queue_id < RSS_QUEUE_ID_MAX && t->t_rss_queue_num > 1) {
			h = rss_hash4(laddr, faddr, lport, fport, t->t_rss_key, t->t_rss_key_size);
			if ((h % t->t_rss_queue_num) != t->t_rss_queue_id) {
				continue;
			}
		}

		so = t->t_dst_cache + dst_cache_size;
		so->ipso_laddr = laddr;
		so->ipso_faddr = faddr;
		so->ipso_lport = lport;
		so->ipso_fport = fport;
		so->ipso_hash = SO_HASH(faddr, lport, fport);
		dst_cache_size++;
		if (dst_cache_size == t->t_dst_cache_size) {
			break;
		}
	}

	t->t_dst_cache_size = dst_cache_size;
	if (t->t_dst_cache_size < t->t_concurrency) {
		panic(0, "Not enough dst cache to perform concurrency (RSS is invalid)");
	}
}

static void
print_ifstat(FILE *out)
{
	uint64_t ipackets, opackets, ibytes, obytes;

	ipackets = counter64_get(&if_ipackets);
	opackets = counter64_get(&if_opackets);
	ibytes = counter64_get(&if_ibytes);
	obytes = counter64_get(&if_obytes);

	fprintf(out, "ipackets ibytes opackets obytes\n");
	fprintf(out, "%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"\n",
			ipackets, ibytes, opackets, obytes);
}

static void
main_process_req(int fd, FILE *out)
{
	int rc;
	char buf[32];

	rc = read(fd, buf, sizeof(buf));
	if (rc > 1) {
		switch (buf[0]) {
		case 's':
			print_stats(out, verbose);
			break;

		case 'c':
			print_sockets(out);
			break;

		case 'i':
			print_ifstat(out);
			break;
		}
	}
}

static void
main_routine(void)
{
	int rc, fd, fd2, pid, n_pfds;
	FILE *file;
	struct sockaddr_un a;
	struct pollfd pfds[2];

	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;
	n_pfds = 1;
	pid = getpid();
	a.sun_family = AF_UNIX;
	sprintf(a.sun_path, "/var/run/con-gen.%d.sock", pid);
	unlink(a.sun_path);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd >= 0) {
		rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
		if (rc == 0) {
			rc = listen(fd, 5);
			if (rc == 0) {
				pfds[n_pfds].fd = fd;
				pfds[n_pfds].events = POLLIN;
				n_pfds++;
			}
		}
	}
	gettimeofday(&report_tv, NULL);
	signal(SIGINT, sighandler);
	signal(SIGALRM, sighandler);
	gettimeofday(&report01.rd_tv, NULL);
	alarm(1);
	while (!m_done) {
		poll(pfds, n_pfds, -1);
		if (pfds[0].revents & POLLIN) {
			main_process_req(STDIN_FILENO, stdout);
		}
		if (n_pfds > 1 && (pfds[1].revents & POLLIN)) {
			fd2 = accept(fd, NULL, NULL);
			if (fd2 >= 0) {
				file = fdopen(fd2, "r+b");
				if (file != NULL) {
					main_process_req(fd2, file);
					fflush(file);
					fclose(file);
				}
				close(fd2);
			}
		}
	}
	unlink(a.sun_path);	
}

int
multiplexer_add(struct thread *t, int fd)
{
	int index;

	index = t->t_pfd_num;
	if (index == ARRAY_SIZE(t->t_pfds)) {
		panic(0, "Too many RSS queues");
	}
	t->t_pfd_num++;
	t->t_pfds[index].fd = fd;
	t->t_pfds[index].events = POLLIN;
	t->t_pfds[index].revents = 0;
	return index;
}

void
multiplexer_pollout(int index)
{
	assert(index < current->t_pfd_num);
	current->t_pfds[index].events |= POLLOUT;
}

int
multiplexer_get_events(int index)
{
	assert(index < current->t_pfd_num);
	return current->t_pfds[index].events;
}

static void
thread_process(void)
{
	int i;
	uint64_t t, age;
	struct packet *pkt;
	struct timespec to;
	struct pollfd pfds[ARRAY_SIZE(current->t_pfds)];

	io_tx();
	if (!current->t_busyloop) {
		memcpy(pfds, current->t_pfds, current->t_pfd_num * sizeof(struct pollfd));
		to.tv_sec = 0;
		to.tv_nsec = 20;
		ppoll(pfds, current->t_pfd_num, &to, NULL);
	}
	t = rdtsc();
	if (t > current->t_tsc) {
		current->t_time = 1000llu * t / tsc_mhz;
		age = current->t_tcp_nowage + NANOSECONDS_SECOND/PR_SLOWHZ;
		if (current->t_time >= age) {
			current->t_tcp_now++;
			current->t_tcp_nowage += NANOSECONDS_SECOND/PR_SLOWHZ;
		}
	}
	current->t_tsc = t;
	if (current->t_busyloop) {
		io_rx(INT_MAX);
	} else {
		for (i = 0; i < current->t_pfd_num; ++i) {
			if (pfds[i].revents & POLLIN) {
				spinlock_lock(&current->t_lock);
				io_rx(i);
				spinlock_unlock(&current->t_lock);
			}
			if (pfds[i].revents & POLLOUT) {
				current->t_pfds[i].events &= ~POLLOUT;
			}
		}
	}
	check_timers();
	while (!io_is_tx_throttled() && !dlist_is_empty(&current->t_pending_head)) {
		pkt = DLIST_FIRST(&current->t_pending_head, struct packet, pkt.list);
		DLIST_REMOVE(pkt, pkt.list);
		current->t_n_pending--;
		if (!io_tx_packet(pkt)) {
			DLIST_INSERT_HEAD(&current->t_available_head, pkt, pkt.list);
		}
	}
	if (g_toy) {
		toy_flush();
	} else {
		bsd_flush();
	}
}

static void *
thread_routine(void *udata)
{
	int proto;

	current = udata;

	if (current->t_affinity >= 0) {
		set_affinity(current->t_affinity);
	}

	current->t_tsc = rdtsc();
	current->t_time = 1000 * current->t_tsc / tsc_mhz;
	current->t_tcp_now = 1;
	current->t_tcp_nowage = current->t_time;

	init_timers();

	proto = g_udp ? IPPROTO_UDP : IPPROTO_TCP;

	if (current->t_Lflag) {
		if (g_toy) {
			toy_server_listen(proto);
		} else {
			bsd_server_listen(proto);
		}
	} else {
		if (g_toy) {
			toy_client_connect();
		} else {
			bsd_client_connect(proto);
		}
	}

	while (!current->t_done) {
		thread_process();
	}

	return NULL;
}

static void
usage(void)
{
	printf(
	"Usage: con-gen [options] { -i interface }\n"
	"\n"
	"Options:\n"
	"\t-h,--help: Print this help\n"
	"\t-v,--verbose:  Be verbose\n"
	"\t-i {interface}:  To operate on\n"
	"\t-p {port}:  Server port (default: 80)\n"
	"\t-s {ip[-ip]}:  Source ip range\n"
	"\t-d {ip[-ip]):  Destination ip range\n"
	"\t-S {hwaddr}:  Source ethernet address\n"
	"\t-D {hwaddr}:  Destination ethernet address\n"
	"\t-c {num}:  Number of parallel connections\n"
	"\t-a {cpu-id}:  Set CPU affinity\n"
	"\t-n {num}:  Number of connections of con-gen (0 meaning infinite)\n"
	"\t-N:  Do not normalize units (i.e., use bps, pps instead of Mbps, Kpps, etc.).\n"
	"\t-L:  Operate in server mode\n"
	"\t--so-debug:  Enable SO_DEBUG option on all sockets\n"
#ifdef HAVE_NETMAP
	"\t--netmap:  Use netmap transport\n"
#endif
#ifdef HAVE_PCAP
	"\t--pcap:  Use libpcap transport\n"
#endif
#ifdef HAVE_XDP
	"\t--xdp:  Use XDP transport\n"
#endif
#ifdef HAVE_DPDK
	"\t--dpdk:  USE DPDK transport\n"
#endif
	"\t--udp:  Use UDP instead of TCP\n"
	"\t--toy:  Use \"toy\" tcp/ip stack instead of bsd4.4 (it is a bit faster)\n"
	"\t--dst-cache:  Number of precomputed connect tuples (default: 100000)\n"
	"\t--ip-in-cksum {0|1}:  On/Off IP input checksum calculation\n"
	"\t--ip-out-cksum {0|1}:  On/Off IP output checksum calculation\n"
	"\t--tcp-in-cksum {0|1}:  On/Off TCP input checksum calculation\n"
	"\t--tcp-out-cksum {0|1}: On/Off TCP output checksum calculation\n"
	"\t--in-cksum {0|1}:  On/Off input checksum calculation\n"
	"\t--out-cksum {0|1}:  On/Off output checksum calculation\n"
	"\t--cksum {0|1}:  On/Off checksum calculation\n"
	"\t--tcp-wscale {0|1}:  On/Off wscale TCP option\n"
	"\t--tcp-timestamps {0|1}:  On/Off timestamp TCP option\n"
	"\t--tcp-fin-timeout {seconds}:  Specify FIN timeout\n"
	"\t--tcp-timewait-timeout {seconds}:  Specify TIME_WAIT timeout\n"
	"\t--report-bytes {0|1}:  On/Off byte statistic in report\n"
	"\t--reports {num}:  Number of reports of con-gen (0 meaning infinite)\n"
	"\t--print-report {0|1}:  On/Off printing report\n"
	"\t--print-banner {0|1}:  On/Off printing report banner every 20 seconds\n"
	"\t--print-statistics {0|1}:  On/Off printing statistics at the end of execution\n"
	);
}

static struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "verbose", no_argument, 0, 'v' },
	{ "udp", no_argument, 0, 0 },
	{ "toy", no_argument, 0, 0 },
	{ "dst-cache", required_argument, 0, 0 },
	{ "so-debug", no_argument, 0, 0 },
#ifdef HAVE_NETMAP
	{ "netmap", no_argument, 0, 0 },
#endif
#ifdef HAVE_PCAP
	{ "pcap", no_argument, 0, 0 },
#endif
#ifdef HAVE_XDP
	{ "xdp", no_argument, 0, 0 },
#endif
#ifdef HAVE_DPDK
	{ "dpdk", no_argument, 0, 0 },
#endif
	{ "ip-in-cksum", required_argument, 0, 0 },
	{ "ip-out-cksum", required_argument, 0, 0 },
	{ "tcp-in-cksum", required_argument, 0, 0 },
	{ "tcp-out-cksum", required_argument, 0, 0 },
	{ "in-cksum", required_argument, 0, 0 },
	{ "out-cksum", required_argument, 0, 0 },
	{ "cksum", required_argument, 0, 0 },
	{ "tcp-wscale", required_argument, 0, 0 },
	{ "tcp-timestamps", required_argument, 0, 0 },
	{ "tcp-fin-timeout", required_argument, 0, 0 },
	{ "tcp-timewait-timeout", required_argument, 0, 0 },
	{ "report-bytes", required_argument, 0, 0 },
	{ "reports", required_argument, 0, 0 },
	{ "print-report", required_argument, 0, 0 },
	{ "print-banner", required_argument, 0, 0 },
	{ "print-statistics", required_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

static const char *short_options = "hvi:q:s:d:S:D:a:n:c:p:NL";

#ifdef HAVE_DPDK
int dpdk_parse_args(int argc, char **argv);

int
io_parse_args(int argc, char **argv)
{
	int i, rc, use_dpdk;
	char *fake_argv[1];

	use_dpdk = 0;
	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i], "--")) {
			rc = dpdk_parse_args(argc, argv);
			if (rc < 0) {
				return 0;
			} else {
				return rc;
			}
		} else if (!strcmp(argv[i], "--dpdk")) {
			use_dpdk = 1;
		}
	}

	if (use_dpdk) {
		fake_argv[0] = "con-gen";
		dpdk_parse_args(ARRAY_SIZE(fake_argv), fake_argv);
	}
	return 0;
}
#else // HAVE_DPDK
int
io_parse_args(int argc, char **argv)
{
	return 0;
}
#endif // HAVE_DPDK

static int
thread_init(struct thread *t, struct thread *pt, int thread_idx, int argc, char **argv)
{
	int rc, opt, option_index;
	char *endptr;
	const char *optname;
	long long optval;

	spinlock_init(&t->t_lock);
	t->t_id = t - threads;
	t->t_tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;
	t->t_ifname[0] = '\0';
	dlist_init(&t->t_available_head);
	dlist_init(&t->t_pending_head);
	dlist_init(&t->t_so_txq);
	dlist_init(&t->t_so_pool);
	dlist_init(&t->t_sob_pool);
	t->t_rss_queue_id = RSS_QUEUE_ID_MAX;
	if (pt == NULL) {
		t->t_dst_cache_size = 100000;
		t->t_ip_do_incksum = 2;
		t->t_ip_do_outcksum = 2;
		t->t_tcp_do_incksum = 2;
		t->t_tcp_do_outcksum = 2;
		t->t_tcp_do_wscale = 1;
		t->t_tcp_do_timestamps = 1;
		t->t_tcp_fintimo = 60 * NANOSECONDS_SECOND;
		t->t_port = htons(80);
		t->t_mtu = 522;
		t->t_concurrency = 1;
		ether_scanf(t->t_eth_laddr, "00:00:00:00:00:00");
		ether_scanf(t->t_eth_faddr, "ff:ff:ff:ff:ff:ff");
		scan_ip_range(&t->t_ip_laddr_min, &t->t_ip_laddr_max, "10.0.0.1");
		scan_ip_range(&t->t_ip_faddr_min, &t->t_ip_faddr_max, "10.1.0.1");
		t->t_affinity = -1;
	} else {
		strzcpy(t->t_ifname, pt->t_ifname, sizeof(t->t_ifname));
		t->t_dst_cache_size = pt->t_dst_cache_size;
		t->t_so_debug = pt->t_so_debug;
		t->t_ip_do_incksum = pt->t_ip_do_incksum;
		t->t_ip_do_outcksum = pt->t_ip_do_outcksum;
		t->t_tcp_do_incksum = pt->t_tcp_do_incksum;
		t->t_tcp_do_outcksum = pt->t_tcp_do_outcksum;
		t->t_tcp_do_wscale = pt->t_tcp_do_wscale;
		t->t_tcp_do_timestamps = pt->t_tcp_do_wscale;
		t->t_tcp_twtimo = pt->t_tcp_twtimo;
		t->t_tcp_fintimo = pt->t_tcp_fintimo;
		t->t_nflag = pt->t_nflag;
		t->t_port = pt->t_port;
		t->t_mtu = pt->t_mtu;
		t->t_concurrency = pt->t_concurrency;
		memcpy(t->t_eth_laddr, pt->t_eth_laddr, 6);
		memcpy(t->t_eth_faddr, pt->t_eth_faddr, 6);
		t->t_ip_laddr_min = pt->t_ip_laddr_min;
		t->t_ip_laddr_max = pt->t_ip_laddr_max;
		t->t_ip_faddr_min = pt->t_ip_faddr_min;
		t->t_ip_faddr_max = pt->t_ip_faddr_max;
		t->t_affinity = pt->t_affinity;
		t->t_Lflag = pt->t_Lflag;
	}

	while ((opt = getopt_long(argc, argv, short_options,
			long_options, &option_index)) != -1) {
		optval = -1;
		if (optarg != NULL) {
			optval = strtoll(optarg, &endptr, 10);
			if (*endptr != '\0') {
				optval = -1;
			}
		}
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "udp")) {
				g_udp = 1;
			} else if (!strcmp(optname, "toy")) {
				g_toy = 1;
			} else if (!strcmp(optname, "dst-cache")) {
				if (optval < 0) {
					goto err;
				}
				t->t_dst_cache_size = optval;
			} else if (!strcmp(optname, "so-debug")) {
				t->t_so_debug = 1;
#ifdef HAVE_NETMAP
			} else if (!strcmp(optname, "netmap")) {
				g_transport = TRANSPORT_NETMAP;
#endif // HAVE_NETMAP
#ifdef HAVE_PCAP
			} else if (!strcmp(optname, "pcap")) {
				g_transport = TRANSPORT_PCAP;
#endif // HAVE_PCAP
#ifdef HAVE_XDP
			} else if (!strcmp(optname, "xdp")) {
				g_transport = TRANSPORT_XDP;
#endif // HAVE_XDP
#ifdef HAVE_DPDK
			} else if (!strcmp(optname, "dpdk")) {
				g_transport = TRANSPORT_DPDK;
#endif // HAVE_DPDK
			} else if (!strcmp(optname, "ip-in-cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_ip_do_incksum = optval;
			} else if (!strcmp(optname, "ip-out-cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_ip_do_outcksum = optval;
			} else if (!strcmp(optname, "tcp-in-cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_tcp_do_incksum = optval;
			} else if (!strcmp(optname, "tcp-out-cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_tcp_do_outcksum = optval;
			} else if (!strcmp(optname, "in-cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_ip_do_incksum = optval;
				t->t_tcp_do_incksum = optval;
			} else if (!strcmp(optname, "out-cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_ip_do_outcksum = optval;
				t->t_tcp_do_outcksum = optval;
			} else if (!strcmp(optname, "cksum")) {
				if (optval < 0) {
					goto err;
				}
				t->t_ip_do_incksum = optval;
				t->t_tcp_do_incksum = optval;
				t->t_ip_do_outcksum = optval;
				t->t_tcp_do_outcksum = optval;
			} else if (!strcmp(optname, "tcp-wscale")) {
				if (optval < 0) {
					goto err;
				}
				t->t_tcp_do_wscale = optval;
			} else if (!strcmp(optname, "tcp-timestamps")) {
				if (optval < 0) {
					goto err;
				}
				t->t_tcp_do_timestamps = optval;
			} else if (!strcmp(optname, "tcp-fin-timeout")) {
				if (optval < 30) {
					goto err;
				}
				t->t_tcp_fintimo = optval * NANOSECONDS_SECOND;
			} else if (!strcmp(optname, "tcp-timewait-timeout")) {
				if (optval < 0) {
					goto err;
				}
				t->t_tcp_twtimo = optval * NANOSECONDS_SECOND;
			} else if (!strcmp(optname, "report-bytes")) {
				report_bytes_flag = 1;
			} else if (!strcmp(optname, "reports")) {
				if (optval < 1) {
					goto err;
				}
				n_reports_max = optval;
			} else if (!strcmp(optname, "print-report")) {
				if (optval < 0) {
					goto err;
				}
				g_fprint_report = optval;
			} else if (!strcmp(optname, "print-banner")) {
				if (optval < 0) {
					goto err;
				}
				print_banner = optval;
			} else if (!strcmp(optname, "print-statistics")) {
				if (optval < 0) {
					goto err;
				}
				print_statistics = optval;
			}
			break;
		case 'h':
			usage();
			exit(0);
		case 'v':
			verbose++;
			break;
		case 'i':
			strzcpy(t->t_ifname, optarg, sizeof(t->t_ifname));
			break;
		case 'q':
			if (optval < 0 || optval >= RSS_QUEUE_ID_MAX) {
				goto err;
			}
			t->t_rss_queue_id = optval;
			break;
		case 's':
			rc = scan_ip_range(&t->t_ip_laddr_min, &t->t_ip_laddr_max, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'd':
			rc = scan_ip_range(&t->t_ip_faddr_min, &t->t_ip_faddr_max, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'S':
			rc = ether_scanf(t->t_eth_laddr, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'D':
			rc = ether_scanf(t->t_eth_faddr, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'a':
			if (optval < 0) {
				goto err;
			}
			t->t_affinity = optval;
			break;
		case 'n':
			if (optval < 0) {
				goto err;
			}
			t->t_nflag = optval;
			break;
		case 'c':
			t->t_concurrency = strtoul(optarg, NULL, 10);
			if (!t->t_concurrency) {
				goto err;
			}
			break;
		case 'p':
			t->t_port = htons(strtoul(optarg, NULL, 10));
			break;
		case 'N':
			Nflag = 0;
			break;
		case 'L':
			t->t_Lflag = 1;
			break;
		default:
err:
			if (opt != 0) {
				fprintf(stderr, "Invalid argument '-%c': %s\n", opt, optarg);
			} else {
				fprintf(stderr, "Invalid argument '--%s': %s\n", optname, optarg);
			}
			return -EINVAL;
		}
	}
	if (t->t_ifname[0] == '\0') {
		fprintf(stderr, "Interface (-i) not specified for thread %d\n", thread_idx);
		usage();
		return -EINVAL;
	}
	current = t;
	htable_init(&t->t_in_htable, 4096, ip_socket_hash);
	if (t->t_Lflag) {
		t->t_http = http_reply;
		t->t_http_len = http_reply_len;
	} else {
		t->t_http = http_request;
		t->t_http_len = http_request_len;
	}
	t->t_counters = xmalloc(n_counters * sizeof(uint64_t));
	memset(t->t_counters, 0, n_counters * sizeof(uint64_t));
	return 0;
}

static void
sleep_compute_hz(void)
{
	uint64_t t, t2, tsc_hz;

	t = rdtsc();
	usleep(10000);
	t2 = rdtsc();
	tsc_hz = (t2 - t) * 100;
	tsc_mhz = tsc_hz / 1000000;
	assert(tsc_hz);
}

static void
init_counters(counter64_t *a, int n)
{
	int i;

	for (i = 0; i < n; ++i) {
		counter64_init(a + i);
	}
}

#define INIT_STAT(s) \
	init_counters((counter64_t *)&s, sizeof(s)/sizeof(counter64_t))

int
main(int argc, char **argv)
{
	int i, rc, opt_off;
	char hostname[64];
	struct thread *t, *pt;

	srand48(getpid() ^ time(NULL));
	counter64_init(&if_ibytes);
	counter64_init(&if_ipackets);
	counter64_init(&if_obytes);
	counter64_init(&if_opackets);
	counter64_init(&if_imcasts);
	INIT_STAT(udpstat);
	INIT_STAT(tcpstat);
	INIT_STAT(ipstat);
	INIT_STAT(icmpstat);
	sleep_compute_hz();
	rc = gethostname(hostname, sizeof(hostname));
	if (rc == -1) {
		fprintf(stderr, "gethostname() failed (%s)\n", strerror(errno));
		strcpy(hostname, "127.0.0.1");
	} else {
		hostname[sizeof(hostname) - 1] = '\0';
	}
	http_request_len = snprintf(http_request, sizeof(http_request),
		"GET / HTTP/1.0\r\n"
		"Host: %s\r\n"
		"User-Agent: con-gen\r\n"
		"\r\n",
		hostname);	
	http_reply_len = snprintf(http_reply, sizeof(http_reply), 
		"HTTP/1.0 200 OK\r\n"
		"Server: con-gen\r\n"
		"Content-Type: text/html\r\n"
		"Connection: close\r\n"
		"Hi\r\n\r\n");

	rc = io_parse_args(argc, argv);
	argc -= rc;
	argv += rc;

	pt = NULL;
	opt_off = 0;
	while (opt_off < argc - 1 && n_threads < N_THREADS_MAX) {
		t = threads + n_threads;
		rc = thread_init(t, pt, n_threads, argc - opt_off, argv + opt_off);
		if (rc) {
			return EXIT_FAILURE;
		}
		opt_off += (optind - 1);
		optind = 1;
		pt = t;
		n_threads++;
	}
	if (n_threads == 0) {
		usage();
		return EXIT_FAILURE;
	}

	set_transport(g_transport, g_udp, g_toy);
	io_init(threads, n_threads);

	for (i = 0; i < n_threads; ++i) {
		t = threads + i;

		if (!t->t_Lflag) {
			if (t->t_dst_cache_size < 2 * t->t_concurrency) {
				t->t_dst_cache_size = 2 * t->t_concurrency;
			}
			thread_init_dst_cache(t);
		}
	}

	for (i = 0; i < n_threads; ++i) {
		t = threads + i;

		rc = pthread_create(&t->t_pthread, NULL, thread_routine, t);
		if (rc) {
			fprintf(stderr, "pthread_create() failed (%s)\n", strerror(rc));
			return EXIT_FAILURE;
		}
	}

	main_routine();	

	for (i = 0; i < n_threads; ++i) {
		t = threads + i;
		pthread_join(t->t_pthread, NULL);
	}

	if (print_statistics) {
		print_stats(stdout, verbose);
	}

	return 0;
}
