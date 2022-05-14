#include "./bsd44/socket.h"
#include "./bsd44/if_ether.h"
#include "./bsd44/ip.h"
#include "./gbtcp/timer.h"
#include "global.h"
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

void bsd_eth_in(void *, int);
void bsd_flush();
void bsd_server_listen(int);
void bsd_client_connect();

void toy_eth_in(void *, int);
void toy_flush();
void toy_server_listen(int);
void toy_client_connect();

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
		dbg("pthread_setaffinity_np(%d) failed", cpu_id);
		return -rc;
	}
	return 0;
}

#ifdef __linux__
int
read_rss_key(const char *ifname, u_char *rss_key)
{
	int fd, rc, size, off;
	struct ifreq ifr;
	struct ethtool_rxfh rss, *rss2;

	rc = socket(AF_INET, SOCK_DGRAM, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	memset(&rss, 0, sizeof(rss));
	memset(&ifr, 0, sizeof(ifr));
	strzcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	rss.cmd = ETHTOOL_GRSSH;
	ifr.ifr_data = (void *)&rss;
	rc = ioctl(fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc < 0) {
		dbg("%s: ioctl(SIOCETHTOOL) failed", ifname);
		goto out;
	}
	if (rss.key_size != RSS_KEY_SIZE) {
		dbg("%s: Invalid rss key_size (%d)", ifname, rss.key_size);
		goto out;
	}
	size = (sizeof(rss) + rss.key_size +
	       rss.indir_size * sizeof(rss.rss_config[0]));
	rss2 = malloc(size);
	if (rc) {
		goto out;
	}
	memset(rss2, 0, size);
	rss2->cmd = ETHTOOL_GRSSH;
	rss2->indir_size = rss.indir_size;
	rss2->key_size = rss.key_size;
	ifr.ifr_data = (void *)rss2;
	rc = ioctl(fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc) {
		dbg("%s: ioctl(SIOCETHTOOL) failed", ifname);
		goto out2;
	}
	off = rss2->indir_size * sizeof(rss2->rss_config[0]);
	memcpy(rss_key, (u_char *)rss2->rss_config + off, RSS_KEY_SIZE);
out2:
	free(rss2);
out:
	close(fd);
	return rc;
}
#else // __linux__
int
read_rss_key(const char *ifname, u_char *rss_key)
{
	return 0;
}
#endif // __linux__

uint32_t
ip_socket_hash(struct dlist *p)
{
	uint32_t h;
	struct ip_socket *so;

	so = container_of(p, struct ip_socket, ipso_list);
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
	printf("%-10s%-10s", cps_b, ipps_b);
	if (report_bytes_flag) {
		printf("%-10s", ibps_b);
	}
	printf("%-10s", opps_b);
	if (report_bytes_flag) {
		printf("%-10s", obps_b);
	}
	printf("%-10s", pps_b);
	if (report_bytes_flag) {
		printf("%-10s", bps_b);
	}
	printf("%-10s", rxmtps_b);
	*old = *new;
}

static void
print_report()
{
	int i;
	static int n;
	struct report_data new;
	int conns;

	if (n == 0 && print_banner) {
		printf("%-10s%-10s", "cps", "ipps");
		if (report_bytes_flag) {
			printf("%-10s", "ibps");
		}
		printf("%-10s", "opps");
		if (report_bytes_flag) {
			printf("%-10s", "obps");
		}
		printf("%-10s", "pps");
		if (report_bytes_flag) {
			printf("%-10s", "bps");
		}
		printf("%-10s", "rxmtps");
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
	printf("%d\n", conns);
	n++;
	if (n == 20) {
		n = 0;
	}
}

static void
quit()
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

static int
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
		dbg("Not enough memory for dst cache");
		return -ENOMEM;
	}
	ip_laddr_connect = t->t_ip_laddr_min;
	ip_lport_connect = EPHEMERAL_MIN;
	ip_faddr_connect = t->t_ip_faddr_min;
	dst_cache_size = 0;
	n = (t->t_ip_laddr_max - t->t_ip_laddr_min + 1) * 
	    (t->t_ip_faddr_max - t->t_ip_faddr_min + 1) *
	    NEPHEMERAL;
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
		if (t->t_rss_qid != RSS_QID_NONE) {
			h = rss_hash4(laddr, faddr, lport, fport, t->t_rss_key);
			if ((h % t->t_n_rss_q) != t->t_rss_qid) {
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
	return 0;
}

static void
thread_process_rx()
{
	int i, j, n;
	void *buf;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;

	for (i = current->t_nmd->first_rx_ring;
	     i <= current->t_nmd->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(current->t_nmd->nifp, i);
		n = nm_ring_space(rxr);
		if (n > current->t_burst_size) {
			n = current->t_burst_size;
		}
		for (j = 0; j < n; ++j) {
			DEV_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			buf = NETMAP_BUF(rxr, slot->buf_idx);
			if (slot->len >= 14) {
				if (current->t_toy) {
					toy_eth_in(buf, slot->len);
				} else {
					bsd_eth_in(buf, slot->len);
				}
			}
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
	}
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
		}
	}
}

static void
main_routine()
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
				} else {
					close(fd2);
				}
			}
		}
	}
	unlink(a.sun_path);	
}

void
thread_process()
{
	uint64_t t, age;
	struct pollfd pfd;

	pfd.fd = current->t_nmd->fd;
	pfd.events = POLLIN;
	if (current->t_tx_throttled) {
		pfd.events |= POLLOUT;
	}
	poll(&pfd, 1, 10);
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
	if (pfd.revents & POLLIN) {
		spinlock_lock(&current->t_lock);
		thread_process_rx();
		spinlock_unlock(&current->t_lock);
	}
	check_timers();
	if (pfd.revents & POLLOUT) {
		current->t_tx_throttled = 0;
	}
	if (current->t_toy) {
		toy_flush();
	} else {
		bsd_flush();
	}
}

static void *
thread_routine(void *udata)
{
	int rc, ipproto;

	current = udata;
	if (current->t_affinity >= 0) {
		set_affinity(current->t_affinity);
	}
	if (!current->t_Lflag) {
		if (current->t_dst_cache_size < 2 * current->t_concurrency) {
			current->t_dst_cache_size = 2 * current->t_concurrency;
		}
		rc = thread_init_dst_cache(current);
		if (rc) {
			return NULL;
		}
	}
	current->t_tsc = rdtsc();
	current->t_time = 1000 * current->t_tsc / tsc_mhz;
	current->t_tcp_now = 1;
	current->t_tcp_nowage = current->t_time;
	init_timers();
	if (current->t_Lflag || current->t_udp) {
		ipproto = current->t_udp ? IPPROTO_UDP: IPPROTO_TCP;
		if (current->t_toy) {
			toy_server_listen(ipproto);
		} else {
			bsd_server_listen(ipproto);
		}
	} else {
		if (current->t_toy) {
			toy_client_connect();
		} else {
			bsd_client_connect();
		}
	}
	while (!current->t_done) {
		thread_process();
	}
	return 0;
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
	"\t-a {cpu-id}: Set CPU affinity\n"
	"\t-n {num}: Number of connections of con-gen (0 meaning infinite)\n"
	"\t-b {num}: Burst size\n"
	"\t-N: Do not normalize units (i.e., use bps, pps instead of Mbps, Kpps, etc.).\n"
	"\t-L: Operate in server mode\n"
	"\t--so-debug: Enable SO_DEBUG option\n"
	"\t--udp: Use UDP instead of TCP\n"
	"\t--toy: Use toy tcp/ip stack instead of bsd4.4 (it is a bit faster)\n"
	"\t--dst-cache: Number of precomputed connect tuples (default: 100000)\n"
	"\t--ip-in-cksum {0|1}: On/Off IP input checksum calculation\n"
	"\t--ip-out-cksum {0|1}: On/Off IP output checksum calculation\n"
	"\t--tcp-in-cksum {0|1}: On/Off TCP input checksum calculation\n"
	"\t--tcp-out-cksum {0|1}: On/Off TCP output checksum calculation\n"
	"\t--in-cksum {0|1}: On/Off input checksum calculation\n"
	"\t--out-cksum {0|1}: On/Off output checksum calculation\n"
	"\t--cksum {0|1}: On/Off checksum calculation\n"
	"\t--tcp-wscale {0|1}: On/Off wscale TCP option\n"
	"\t--tcp-timestamps {0|1}: On/Off timestamp TCP option\n"
	"\t--tcp-fin-timeout {seconds}: Specify FIN timeout\n"
	"\t--tcp-timewait-timeout {seconds}: Specify TIME_WAIT timeout\n"
	"\t--report-bytes {0|1}: On/Off byte statistic in report\n"
	"\t--reports {num}: Number of reports of con-gen (0 meaning infinite)\n"
	"\t--print-banner {0|1}: On/Off printing report banner every 20 seconds\n"
	"\t--print-statistics {0|1}: On/Off printing statistics at the end of execution\n"
	);
}

static struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "verbose", no_argument, 0, 'v' },
	{ "udp", no_argument, 0, 0 },
	{ "toy", no_argument, 0, 0 },
	{ "dst-cache", required_argument, 0, 0 },
	{ "so-debug", no_argument, 0, 0 },
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
	{ "print-banner", required_argument, 0, 0 },
	{ "print-statistics", required_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

static int
thread_init_if(struct thread *t, const char *ifname)
{
	int rc;
	char buf[IFNAMSIZ + 7];

	snprintf(buf, sizeof(buf), "netmap:%s", ifname);
	t->t_nmd = nm_open(buf, NULL, 0, NULL);
	if (t->t_nmd == NULL) {
		rc = -errno;
		dbg("nm_open('%s') failed (%s)", buf, strerror(-rc));
		return rc;
	}
	if (t->t_nmd->req.nr_rx_rings != t->t_nmd->req.nr_tx_rings) {
		rc = -EINVAL;
		dbg("%s: nr_rx_rings != nr_tx_rings", buf);
		goto err;
	}
	t->t_n_rss_q = t->t_nmd->req.nr_rx_rings;
	t->t_rss_qid = RSS_QID_NONE;	
	if ((t->t_nmd->req.nr_flags & NR_REG_MASK) == NR_REG_ONE_NIC) {
		t->t_rss_qid = t->t_nmd->first_rx_ring;
		rc = read_rss_key(t->t_nmd->req.nr_name, t->t_rss_key);
		if (rc) {
			dbg("%s: Can't read rss key", t->t_nmd->req.nr_name);
			goto err;
		}
	}
	return 0;
err:
	nm_close(t->t_nmd);
	t->t_nmd = NULL;
	return rc;
}

static int
thread_init(struct thread *t, struct thread *pt, int thread_idx, int argc, char **argv)
{
	int rc, opt, option_index;
	const char *optname;
	const char *ifname;
	long long optval;

	spinlock_init(&t->t_lock);
	t->t_id = t - threads;
	t->t_tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;
	dlist_init(&t->t_so_txq);
	dlist_init(&t->t_so_pool);
	dlist_init(&t->t_sob_pool);
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
		t->t_burst_size = 256;
		t->t_concurrency = 1;
		ether_scanf(t->t_eth_laddr, "00:00:00:00:00:00");
		ether_scanf(t->t_eth_faddr, "ff:ff:ff:ff:ff:ff");
		scan_ip_range(&t->t_ip_laddr_min,
			&t->t_ip_laddr_max, "10.0.0.1");
		scan_ip_range(&t->t_ip_faddr_min,
			&t->t_ip_faddr_max, "10.1.0.1");
		t->t_affinity = -1;
	} else {
		t->t_toy = pt->t_toy;
		t->t_dst_cache_size = pt->t_dst_cache_size;
		t->t_Lflag = pt->t_Lflag;
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
		t->t_burst_size = pt->t_burst_size;
		t->t_concurrency = pt->t_concurrency;
		memcpy(t->t_eth_laddr, pt->t_eth_laddr, 6);
		memcpy(t->t_eth_faddr, pt->t_eth_faddr, 6);
		t->t_ip_laddr_min = pt->t_ip_laddr_min;
		t->t_ip_laddr_max = pt->t_ip_laddr_max;
		t->t_ip_faddr_min = pt->t_ip_faddr_min;
		t->t_ip_faddr_max = pt->t_ip_faddr_max;
		t->t_udp = pt->t_udp;
		t->t_affinity = pt->t_affinity;
	}
	ifname = NULL;
	while ((opt = getopt_long(argc, argv,
			"hvi:s:d:S:D:a:n:b:c:p:NL",
			long_options, &option_index)) != -1) {
		optval = optarg ? strtoll(optarg, NULL, 10) : 0;
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "udp")) {
				t->t_udp = 1;
			} else if (!strcmp(optname, "toy")) {
				t->t_toy = 1;
			} else if (!strcmp(optname, "dst-cache")) {
				t->t_dst_cache_size = optval;
			} else if (!strcmp(optname, "so-debug")) {
				t->t_so_debug = 1;
			} else if (!strcmp(optname, "ip-in-cksum")) {
				t->t_ip_do_incksum = optval;
			} else if (!strcmp(optname, "ip-out-cksum")) {
				t->t_ip_do_outcksum = optval;
			} else if (!strcmp(optname, "tcp-in-cksum")) {
				t->t_tcp_do_incksum = optval;
			} else if (!strcmp(optname, "tcp-out-cksum")) {
				t->t_tcp_do_outcksum = optval;
			} else if (!strcmp(optname, "in-cksum")) {
				t->t_ip_do_incksum = optval;
				t->t_tcp_do_incksum = optval;
			} else if (!strcmp(optname, "out-cksum")) {
				t->t_ip_do_outcksum = optval;
				t->t_tcp_do_outcksum = optval;
			} else if (!strcmp(optname, "cksum")) {
				t->t_ip_do_incksum = optval;
				t->t_tcp_do_incksum = optval;
				t->t_ip_do_outcksum = optval;
				t->t_tcp_do_outcksum = optval;
			} else if (!strcmp(optname, "tcp-wscale")) {
				t->t_tcp_do_wscale = optval;
			} else if (!strcmp(optname, "tcp-timestamps")) {
				t->t_tcp_do_timestamps = optval;
			} else if (!strcmp(optname, "tcp-fin-timeout")) {
				if (optval < 30) {
					goto err;
				}
				t->t_tcp_fintimo = optval * NANOSECONDS_SECOND;
			} else if (!strcmp(optname, "tcp-timewait-timeout")) {
				t->t_tcp_twtimo = optval * NANOSECONDS_SECOND;
			} else if (!strcmp(optname, "report-bytes")) {
				report_bytes_flag = 1;
			} else if (!strcmp(optname, "reports")) {
				n_reports_max = optval;
			} else if (!strcmp(optname, "print-banner")) {
				print_banner = optval;
			} else if (!strcmp(optname, "print-statistics")) {
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
			ifname = optarg;
			break;
		case 's':
			rc = scan_ip_range(&t->t_ip_laddr_min,
				&t->t_ip_laddr_max, optarg);
			if (rc) {
				goto err;
			}
			break;
		case 'd':
			rc = scan_ip_range(&t->t_ip_faddr_min,
				&t->t_ip_faddr_max, optarg);
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
			t->t_affinity = optval;
			break;
		case 'n':
			t->t_nflag = optval;
			break;
		case 'b':
			t->t_burst_size = strtoul(optarg, NULL, 10);
			if (!t->t_burst_size) {
				goto err;
			}
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
			dbg("Invalid argument '-%c': %s", opt, optarg);
			return -EINVAL;
		}
	}
	if (ifname == NULL) {
		dbg("Interface (-i) not specified for thread %d", thread_idx);
		usage();
		return -EINVAL;
	}
	rc = thread_init_if(t, ifname);
	if (rc) {
		return rc;
	}
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
sleep_compute_hz()
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
		dbg("gethostname() failed (%s)\n", strerror(errno));
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
	for (i = 0; i < n_threads; ++i) {
		t = threads + i;
		rc = pthread_create(&t->t_pthread, NULL, thread_routine, t);
		if (rc) {
			dbg("pthread_create() failed (%s)", strerror(rc));
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
