// SPDX-License-Identifier: GPL-2.0-only

#include "global.h"

#include "timer.h"
//#include "netstat.h"
#include <getopt.h>

struct report_data {
	uint64_t rd_ipackets;
	uint64_t rd_ibytes;
	uint64_t rd_opackets;
	uint64_t rd_obytes;
	struct timeval rd_tv;
};

struct cg_core {
	struct cg_dlist cor_list;
	struct cg_dlist cor_tasks_head;
	int cor_affinity;
	pthread_t cor_pthread;
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
static void *g_cg_plugin;

counter64_t if_ibytes;
counter64_t if_ipackets;
counter64_t if_obytes;
counter64_t if_opackets;
counter64_t if_imcasts;

uint64_t cg_tsc_mhz;

int n_counters = 1;

static struct cg_core cg_cores[CG_CORE_MAX];
static int cg_n_cores;

struct cg_dlist cg_threads_head;
__thread struct cg_thread *current;

static int g_transport = TRANSPORT_DEFAULT;


void (*congen_plugin_init)(void);
void (*congen_plugin_current_init)(void);
void (*congen_plugin_update)(uint64_t tsc);
void (*congen_plugin_flush)(void);
void (*congen_plugin_command)(int command, FILE *out, int verbose);
void (*congen_plugin_rx)(void *data, int len);


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

#define CG_DLSYM(handle, symbol) \
	if ((congen_plugin_##symbol = dlsym(handle, "congen_plugin_" #symbol)) == NULL) { \
		panic(0, "dlsym('%s', 'conngen_plugin_"#symbol"') failed (%s)\n", \
				filename, dlerror()); \
	}

static void
cg_load_plugin(const char *plugin_name)
{
	char filename[PATH_MAX];

	snprintf(filename, sizeof(filename), "./libcongen-%s-plugin.so", plugin_name);
	g_cg_plugin = dlopen(filename, RTLD_NOW|RTLD_LOCAL);
	if (g_cg_plugin != NULL) {
		goto loaded;
	}

	snprintf(filename, sizeof(filename), "libcongen-%s-plugin.so", plugin_name);
	g_cg_plugin = dlopen(filename, RTLD_NOW|RTLD_LOCAL);
	if (g_cg_plugin != NULL) {
		goto loaded;
	}

	panic(0, "dlopen('%s') failed (%s)", filename, dlerror());
	

loaded:
	CG_DLSYM(g_cg_plugin, init);
	CG_DLSYM(g_cg_plugin, current_init);
	CG_DLSYM(g_cg_plugin, update);
	CG_DLSYM(g_cg_plugin, flush);
	CG_DLSYM(g_cg_plugin, command);
	CG_DLSYM(g_cg_plugin, rx);
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
ip_socket_hash(struct cg_dlist *p)
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
	double dt, ipps, ibps, opps, obps, pps, bps;
	char ipps_b[40], ibps_b[40];
	char opps_b[40], obps_b[40];
	char pps_b[40], bps_b[40];

	dt = (new->rd_tv.tv_sec - old->rd_tv.tv_sec) +
			(new->rd_tv.tv_usec - old->rd_tv.tv_usec) / 1000000.0f;
	ipps = (new->rd_ipackets - old->rd_ipackets) / dt;
	opps = (new->rd_opackets - old->rd_opackets) / dt;
	ibps = (new->rd_ibytes - old->rd_ibytes) / dt;
	obps = (new->rd_obytes - old->rd_obytes) / dt;
	pps = ipps + opps;
	bps = ibps + obps;
	norm(ipps_b, ipps, Nflag);
	norm(ibps_b, ibps, Nflag);
	norm(opps_b, opps, Nflag);
	norm(obps_b, obps, Nflag);
	norm(pps_b, pps, Nflag);
	norm(bps_b, bps, Nflag);
	printf("%-12s", ipps_b);
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
}

static void
print_report(void)
{
	static int n;

	int conns;
	struct report_data new;
	struct cg_thread *t;

	if (!g_fprint_report) {
		return;
	}
	if (n == 0 && print_banner) {
		printf("%-12s", "ipps");
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
		printf("%s\n", "conns");
	}
	conns = 0;
	CG_DLIST_FOREACH(t, &cg_threads_head, t_list) {
		conns += t->t_n_conns;
	}
	gettimeofday(&new.rd_tv, NULL);
	new.rd_ipackets = counter64_get(&if_ipackets);
	new.rd_opackets = counter64_get(&if_opackets);
	new.rd_ibytes = counter64_get(&if_ibytes);
	new.rd_obytes = counter64_get(&if_obytes);
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
	struct cg_thread *t;

	m_done = 1;
	CG_DLIST_FOREACH(t, &cg_threads_head, t_list) {
		t->t_done = 1;
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
thread_init_dst_cache(struct cg_thread *t)
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
	int rc, command;
	char buf[32];

	rc = read(fd, buf, sizeof(buf));
	if (rc > 1) {
		command = buf[0];
		switch (command) {
		case 'i':
			print_ifstat(out);
			break;

		default:
			congen_plugin_command(command, out, verbose);
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
multiplexer_add(struct cg_thread *t, int fd)
{
	int index;

	index = current->t_pfd_num;
	if (index == CG_ARRAY_SIZE(current->t_pfds)) {
		panic(0, "Queues limit exceeded (%zu)", CG_ARRAY_SIZE(current->t_pfds));
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

void
io_process(void *pkt, int pkt_len)
{
	congen_plugin_rx(pkt, pkt_len);
}

static void
thread_process(void)
{
	int i;
	uint64_t tsc;
	struct packet *pkt;
	struct timespec to;
	struct pollfd pfds[CG_ARRAY_SIZE(current->t_pfds)];

	io_tx();

	if (!current->t_busyloop) {
		memcpy(pfds, current->t_pfds, current->t_pfd_num * sizeof(struct pollfd));
		to.tv_sec = 0;
		to.tv_nsec = 20;
		ppoll(pfds, current->t_pfd_num, &to, NULL);
	}

	tsc = rdtsc();
	if (tsc > current->t_tsc) {
		current->t_time += 1000llu * (tsc - current->t_tsc) / cg_tsc_mhz;
		congen_plugin_update(tsc);

	}
	current->t_tsc = tsc;

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

	while (!io_is_tx_throttled() && !cg_dlist_is_empty(&current->t_pending_head)) {
		pkt = CG_DLIST_FIRST(&current->t_pending_head, struct packet, pkt.list);
		CG_DLIST_REMOVE(pkt, pkt.list);
		current->t_n_pending--;
		if (!io_tx_packet(pkt)) {
			CG_DLIST_INSERT_HEAD(&current->t_available_head, pkt, pkt.list);
		}
	}

	congen_plugin_flush();
}

static void *
thread_routine(void *udata)
{
	struct cg_core *core;

	core = udata;

	set_affinity(core->cor_affinity);


	current = udata;


	current->t_tsc = rdtsc();

	init_timers();

	congen_plugin_current_init();

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
	"\t--dst-cache:  Number of precomputed connect tuples (default: 100000)\n"
	"\t--tcp-wscale {0|1}:  On/Off wscale TCP option\n"
	"\t--tcp-timestamps {0|1}:  On/Off timestamp TCP option\n"
	"\t--tcp-fin-timeout {seconds}:  Specify FIN timeout\n"
	"\t--tcp-timewait-timeout {seconds}:  Specify TIME_WAIT timeout\n"
	"\t--report-bytes {0|1}:  On/Off byte statistic in report\n"
	"\t--reports {num}:  Number of reports of con-gen (0 meaning infinite)\n"
	"\t--print-report {0|1}:  On/Off printing report\n"
	"\t--print-banner {0|1}:  On/Off printing report banner every 20 seconds\n"
	"\t--plugin {name}: Specify plugin\n"
	);
}

static struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "verbose", no_argument, 0, 'v' },
	{ "plugin", required_argument, 0, 0 },
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
	{ "tcp-wscale", required_argument, 0, 0 },
	{ "tcp-timestamps", required_argument, 0, 0 },
	{ "tcp-fin-timeout", required_argument, 0, 0 },
	{ "tcp-timewait-timeout", required_argument, 0, 0 },
	{ "report-bytes", required_argument, 0, 0 },
	{ "reports", required_argument, 0, 0 },
	{ "print-report", required_argument, 0, 0 },
	{ "print-banner", required_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

static const char *short_options = "hvi:q:s:d:S:D:a:n:c:p:NL";

#ifdef HAVE_DPDK
int dpdk_parse_args(int argc, char **argv);

static bool
cg_validate_args(int argc, char **argv)
{
	int save_opterr, opt, option_index;

	save_opterr = opterr;
	opterr = 0;
	while ((opt = getopt_long(argc, argv, short_options,
			long_options, &option_index)) != -1) {
		if (opt != 0 && strchr(short_options, opt) == NULL) {
			optind = 1;
			opterr = save_opterr;
			return false;
		}
	}

	optind = 1;
	opterr = save_opterr;
	return true;
}

int
io_parse_args(int argc, char **argv)
{
	int rc;
	char *fake_argv[1];

	if (cg_validate_args(argc, argv)) {
		fake_argv[0] = "con-gen";
		dpdk_parse_args(CG_ARRAY_SIZE(fake_argv), fake_argv);
		return 0;
	} else {
		rc = dpdk_parse_args(argc, argv);
		if (rc < 0) {
			return 0;
		} else {
			return rc;
		}
	}
}
#else // HAVE_DPDK
int
io_parse_args(int argc, char **argv)
{
	return 0;
}
#endif // HAVE_DPDK

static void
cg_task_set(struct cg_thread *t)
{
	int i;
	struct cg_core *core;

	core = NULL;
	for (i = 0; i < cg_n_cores; ++i) {
		core = cg_cores + i;
		if (core->cor_affinity == t->t_affinity) {
			break;
		}
	}

	if (i == cg_n_cores) {
		if (cg_n_cores == CG_ARRAY_SIZE(cg_cores)) {
			panic(0, "Cores limit exceeded, see CG_CORE_MAX");
		}
		core = cg_cores + cg_n_cores;
		cg_n_cores++;
		cg_dlist_init(&core->cor_tasks_head);
		core->cor_affinity = t->t_affinity;
	}

	CG_DLIST_INSERT_TAIL(&core->cor_tasks_head, t, t_core_list);
}

static struct cg_thread *
cg_task_init(struct cg_thread *tmpl, int argc, char **argv)
{
	int rc, opt, option_index;
	char *endptr;
	const char *optname, *plugin_name;
	long long optval;
	struct cg_thread *t;

	plugin_name = NULL;

	t = xmalloc(sizeof(struct cg_thread));

	spinlock_init(&t->t_lock);
	t->t_ifname[0] = '\0';
	cg_dlist_init(&t->t_available_head);
	cg_dlist_init(&t->t_pending_head);
	cg_dlist_init(&t->t_so_txq);
	cg_dlist_init(&t->t_so_pool);
	cg_dlist_init(&t->t_sob_pool);
	t->t_rss_queue_id = RSS_QUEUE_ID_MAX;

	if (tmpl == NULL) {
		t->t_dst_cache_size = 100000;
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
		t->t_affinity = 0;
	} else {
		strzcpy(t->t_ifname, tmpl->t_ifname, sizeof(t->t_ifname));
		t->t_dst_cache_size = tmpl->t_dst_cache_size;
		t->t_so_debug = tmpl->t_so_debug;
		t->t_tcp_do_wscale = tmpl->t_tcp_do_wscale;
		t->t_tcp_do_timestamps = tmpl->t_tcp_do_wscale;
		t->t_tcp_twtimo = tmpl->t_tcp_twtimo;
		t->t_tcp_fintimo = tmpl->t_tcp_fintimo;
		t->t_nflag = tmpl->t_nflag;
		t->t_port = tmpl->t_port;
		t->t_mtu = tmpl->t_mtu;
		t->t_concurrency = tmpl->t_concurrency;
		memcpy(t->t_eth_laddr, tmpl->t_eth_laddr, 6);
		memcpy(t->t_eth_faddr, tmpl->t_eth_faddr, 6);
		t->t_ip_laddr_min = tmpl->t_ip_laddr_min;
		t->t_ip_laddr_max = tmpl->t_ip_laddr_max;
		t->t_ip_faddr_min = tmpl->t_ip_faddr_min;
		t->t_ip_faddr_max = tmpl->t_ip_faddr_max;
		t->t_affinity = tmpl->t_affinity;
		t->t_Lflag = tmpl->t_Lflag;
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
			if (!strcmp(optname, "plugin")) {
				plugin_name = optarg;
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
				panic(0, "Invalid argument '-%c': %s", opt, optarg);
			} else {
				panic(0, "Invalid argument '--%s': %s", optname, optarg);
			}
		}
	}

	if (t->t_ifname[0] == '\0') {
		panic(0, "Interface (-i) not specified");
	}

	if (g_cg_plugin == NULL) {
		if (plugin_name == NULL) {
			panic(0, "Plugin (--plugin) not specified");
		}
		cg_load_plugin(plugin_name);
	}

	cg_task_set(t);

	current = t;
	htable_init(&t->t_in_htable, 4096, ip_socket_hash);

	// FIXME: to bsd44
	if (t->t_Lflag) {
		t->t_http = http_reply;
		t->t_http_len = http_reply_len;
	} else {
		t->t_http = http_request;
		t->t_http_len = http_request_len;
	}

	if (!t->t_Lflag) {
		if (t->t_dst_cache_size < 2 * t->t_concurrency) {
			t->t_dst_cache_size = 2 * t->t_concurrency;
		}
		thread_init_dst_cache(t);
	}

	t->t_counters = xmalloc(n_counters * sizeof(uint64_t));
	memset(t->t_counters, 0, n_counters * sizeof(uint64_t));
	CG_DLIST_INSERT_TAIL(&cg_threads_head, t, t_list);

	return t;
}

static void
sleep_compute_hz(void)
{
	uint64_t t, t2, tsc_hz;

	t = rdtsc();
	usleep(10000);
	t2 = rdtsc();
	tsc_hz = (t2 - t) * 100;
	cg_tsc_mhz = tsc_hz / 1000000;
	assert(tsc_hz);
}

int
main(int argc, char **argv)
{
	int i, rc, opt_off;
	char hostname[64];
	struct cg_core *core;
	struct cg_thread *t, *tmpl;

	srand48(getpid() ^ time(NULL));
	counter64_init(&if_ibytes);
	counter64_init(&if_ipackets);
	counter64_init(&if_obytes);
	counter64_init(&if_opackets);
	counter64_init(&if_imcasts);
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

	cg_dlist_init(&cg_threads_head);
	tmpl = NULL;
	opt_off = 0;

	while (opt_off < argc - 1) {
		t = cg_task_init(tmpl, argc - opt_off, argv + opt_off);
		opt_off += (optind - 1);
		optind = 1;
		tmpl = t;
	}
	if (cg_dlist_is_empty(&cg_threads_head)) {
		usage();
		return EXIT_FAILURE;
	}

	congen_plugin_init();

	set_transport(g_transport);
	io_init();

	for (i = 0; i < cg_n_cores; ++i) {
		core = cg_cores + i;
		rc = pthread_create(&core->cor_pthread, NULL, thread_routine, core);
		if (rc) {
			panic(rc, "pthread_create() failed");
		}
	}

	main_routine();	

	for (i = 0; i < cg_n_cores; ++i) {
		core = cg_cores + i;
		pthread_join(core->cor_pthread, NULL);
	}

	return 0;
}
