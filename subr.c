#include "global.h"
#include "subr.h"

#include <sys/resource.h>

static struct spinlock panic_lock;

int verbose;
struct udpstat udpstat;
struct tcpstat tcpstat;
struct ipstat ipstat;
struct icmpstat icmpstat;

const char *tcpstates[TCP_NSTATES] = {
	[TCPS_CLOSED] = "CLOSED",
	[TCPS_LISTEN] = "LISTEN",
	[TCPS_SYN_SENT] = "SYN_SENT",
	[TCPS_SYN_RECEIVED] = "SYN_RCVD",
	[TCPS_ESTABLISHED] = "ESTABLISHED",
	[TCPS_CLOSE_WAIT] = "CLOSE_WAIT",
	[TCPS_FIN_WAIT_1] = "FIN_WAIT_1",
	[TCPS_CLOSING] = "CLOSING",
	[TCPS_LAST_ACK] = "LAST_ACK",
	[TCPS_FIN_WAIT_2] = "FIN_WAIT_2",
	[TCPS_TIME_WAIT] = "TIME_WAIT",
};

static void read_rss_key(const char *, u_char *) __attribute__((unused));

void
dbg5(const char *file, u_int line, const char *func, int suppressed,
     const char *fmt, ...)
{
	int len;
	char buf[BUFSIZ];
	va_list ap;

	len = snprintf(buf, sizeof(buf), "%-6d: %-20s: %-4d: %-20s: ",
		getpid(), file, line, func);
	va_start(ap, fmt);
	len += vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
	va_end(ap);
	if (len < sizeof(buf) && suppressed) {
		snprintf(buf + len, sizeof(buf) - len, " (suppressed %d)",
			suppressed);
	}
	printf("%s\n", buf);
}

struct pseudo {
	be32_t ph_src;
	be32_t ph_dst;
	uint8_t ph_pad;
	uint8_t ph_proto;
	be16_t ph_len;
} __attribute__((packed));


static inline uint64_t
cksum_add(uint64_t sum, uint64_t x)
{
	sum += x;
	if (sum < x) {
		++sum;
	}
	return sum;
}

static uint16_t
reduce(uint64_t sum)
{
	uint64_t mask;
	uint16_t reduced;

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	reduced = ~((uint16_t)sum);
	if (reduced == 0) {
		reduced = 0xffff;
	}
	return reduced;
}

static uint64_t
cksum_raw(const u_char *b, int size)
{
	uint64_t sum;

	sum = 0;
	while (size >= sizeof(uint64_t)) {
		sum = cksum_add(sum, *((uint64_t *)b));
		size -= sizeof(uint64_t);
		b += sizeof(uint64_t);
	}
	if (size >= 4) {
		sum = cksum_add(sum, *((uint32_t *)b));
		size -= sizeof(uint32_t);
		b += sizeof(uint32_t);
	}
	if (size >= 2) {
		sum = cksum_add(sum, *((uint16_t *)b));
		size -= sizeof(uint16_t);
		b += sizeof(uint16_t);
	}
	if (size) {
		assert(size == 1);
		sum = cksum_add(sum, *b);
	}
	return sum;
}

uint16_t
in_cksum(void *data, int len)
{
	uint64_t sum;
	uint16_t reduced;

	sum = cksum_raw(data, len);
	reduced = reduce(sum);
	return reduced;
}

static uint64_t
pseudo_cksum(struct ip *ip, int len)
{	
	uint64_t sum;
	struct pseudo ph;

	ph.ph_src = ip->ip_src.s_addr;
	ph.ph_dst = ip->ip_dst.s_addr;
	ph.ph_pad = 0;
	ph.ph_proto = ip->ip_p;
	ph.ph_len = htons(len);
	sum = cksum_raw((u_char *)&ph, sizeof(ph));
	return sum;
}

uint16_t
udp_cksum(struct ip *ip, int len)
{
	uint16_t reduced;
	uint64_t sum, ph_cksum;

	sum = cksum_raw((u_char *)ip + (ip->ip_hl << 2), len);
	ph_cksum = pseudo_cksum(ip, len);
	sum = cksum_add(sum, ph_cksum);
	reduced = reduce(sum);
	return reduced;
}

void *
xmalloc(size_t size)
{
	void *ptr;

	//printf("malloc(%zu)\n", size);
	ptr = malloc(size);
	if (ptr == NULL) {
		panic(0, "malloc(%zu) failed", size);
	}
	return ptr;
}

void
panic3(const char *file, int line, int errnum, const char *format, ...)
{
	va_list ap;

	spinlock_lock(&panic_lock);
#ifndef NDEBUG
	fprintf(stderr, "%s:%d: ", file, line);
#endif // NDEBUG
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum) {
		fprintf(stderr, " (%d:%s)", errnum, strerror(errnum));
	}
	fprintf(stderr, "\n");
	print_stats(stderr, 0);
#ifndef NDEBUG
	abort();
#else
	exit(1);
#endif
	spinlock_unlock(&panic_lock);
}

void
add_pending_packet(struct packet *pkt)
{
	struct packet *cp;

	if (dlist_is_empty(&current->t_available_head)) {
		if (current->t_n_pending < 2048) {
			cp = xmalloc(sizeof(*pkt));
		} else {
			cp = DLIST_FIRST(&current->t_pending_head, struct packet, pkt.list);
			current->t_n_pending--;
		}
	} else {
		cp = DLIST_FIRST(&current->t_available_head, struct packet, pkt.list);
		DLIST_REMOVE(cp, pkt.list);
	}

	memcpy(cp->pkt_body, pkt->pkt.buf, pkt->pkt.len);
	cp->pkt.len = pkt->pkt.len;
	cp->pkt.buf = cp->pkt_body;
	DLIST_INSERT_TAIL(&current->t_pending_head, cp, pkt.list);
	current->t_n_pending++;

}

void
set_transport(struct thread *t, int transport)
{
	switch (transport) {
#ifdef HAVE_NETMAP
	case TRANSPORT_NETMAP:
		set_netmap_ops(t);
		break;
#endif
#ifdef HAVE_PCAP
	case TRANSPORT_PCAP:
		set_pcap_ops(t);
		break;
#endif
#ifdef HAVE_XDP
	case TRANSPORT_XDP:
		set_xdp_ops(t);
		break;
#endif
	default:
		panic(0, "Transport %d not supported", transport);
		break;
	}
}

void
io_init(const char *ifname)
{
	(*current->t_io_init_op)(ifname);
	if (current->t_rss_queue_num > 1 && current->t_rss_queue_id != RSS_QUEUE_ID_NONE) {
		read_rss_key(current->t_ifname, current->t_rss_key);
	}
}

void
io_init_tx_packet(struct packet *pkt)
{
	return (*current->t_io_init_tx_packet_op)(pkt);
}

void
io_deinit_tx_packet(struct packet *pkt)
{
	if (current->t_io_deinit_tx_packet_op != NULL) {
		(*current->t_io_deinit_tx_packet_op)(pkt);
	}
}

bool
io_is_tx_throttled()
{
	return (*current->t_io_is_tx_throttled_op)();
}

int
io_tx_packet(struct packet *pkt)
{
	int len;
	bool sent;

	len = pkt->pkt.len;
	sent = (*current->t_io_tx_packet_op)(pkt);
	if (sent) {
		counter64_add(&if_obytes, len);
		counter64_inc(&if_opackets);
		return 0;
	} else {
		return -ENOBUFS;
	}
}

int
io_rx(int queue_id)
{
	return (*current->t_io_rx_op)(queue_id);
}

void
io_tx()
{
	if (current->t_io_tx_op != NULL) {
		(*current->t_io_tx_op)();
	}
}

int
parse_http(const char *s, int len, u_char *ctx)
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

char *
strzcpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}
	dest[i] = '\0';
	return dest;
}

#ifdef __linux__
static void
read_rss_key(const char *ifname, u_char *rss_key)
{
	int fd, rc, size, off;
	struct ifreq ifr;
	struct ethtool_rxfh rss, *rss2;

	rc = socket(AF_INET, SOCK_DGRAM, 0);
	if (rc < 0) {
		panic(errno, "Reading %s RSS key error: socket() failed", ifname);
	}
	fd = rc;
	memset(&rss, 0, sizeof(rss));
	memset(&ifr, 0, sizeof(ifr));
	strzcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	rss.cmd = ETHTOOL_GRSSH;
	ifr.ifr_data = (void *)&rss;
	rc = ioctl(fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc < 0) {
		panic(errno, "Reading %s RSS key error: ioctl(SIOCETHTOOL) failed", ifname);
	}
	if (rss.key_size != RSS_KEY_SIZE) {
		panic(errno, "%s: Invalid RSS key_size (%d)\n", ifname, rss.key_size);
	}
	size = (sizeof(rss) + rss.key_size +
	       rss.indir_size * sizeof(rss.rss_config[0]));
	rss2 = xmalloc(size);
	memset(rss2, 0, size);
	rss2->cmd = ETHTOOL_GRSSH;
	rss2->indir_size = rss.indir_size;
	rss2->key_size = rss.key_size;
	ifr.ifr_data = (void *)rss2;
	rc = ioctl(fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc) {
		panic(errno, "Reading %s RSS key error: ioctl(SIOCETHTOOL) failed", ifname);
	}
	off = rss2->indir_size * sizeof(rss2->rss_config[0]);
	memcpy(rss_key, (u_char *)rss2->rss_config + off, RSS_KEY_SIZE);
	free(rss2);
	close(fd);
}
#else // __linux__
void
read_rss_key(const char *ifname, u_char *rss_key)
{
	static uint8_t freebsd_rss_key[RSS_KEY_SIZE] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
		0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
		0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
		0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
		0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	};
	memcpy(rss_key, freebsd_rss_key, RSS_KEY_SIZE);
}
#endif // __linux__

uint32_t
toeplitz_hash(const u_char *data, int cnt, const u_char *key)
{   
	uint32_t h, v;
	int i, b;

	h = 0; 
	v = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
	for (i = 0; i < cnt; i++) {
		for (b = 0; b < 8; ++b) {
			if (data[i] & (1 << (7 - b))) {
				h ^= v;
			}
			v <<= 1;
			if ((i + 4) < RSS_KEY_SIZE &&
			    (key[i + 4] & (1 << (7 - b)))) {
				v |= 1;
			}
		}
	}
	return h;
}

uint32_t
rss_hash4(be32_t laddr, be32_t faddr, be16_t lport, be16_t fport, u_char *key)
{
	int off;
	uint32_t h;
	u_char data[12];

	off = 0;
	*(be32_t *)(data + off) = faddr;
	off += 4;
	*(be32_t *)(data + off) = laddr;
	off += 4;
	*(be16_t *)(data + off) = fport;
	off += 2;
	*(be16_t *)(data + off) = lport;
	off += 2;
	h = toeplitz_hash(data, off, key);
	h &= 0x0000007F;
	return h;
}

void
counter64_init(counter64_t *c)
{
	*c = n_counters++;
}

uint64_t
counter64_get(counter64_t *c)
{
	int i;
	uint64_t accum;

	accum = 0;
	for (i = 0; i < n_threads; ++i) {
		assert(*c != 0);
		accum += threads[i].t_counters[*c];
	}
	return accum;
}

void
spinlock_init(struct spinlock *sl)
{
	sl->spinlock_locked = 0;
}

void
spinlock_lock(struct spinlock *sl)
{
	while (__sync_lock_test_and_set(&sl->spinlock_locked, 1)) {
		while (sl->spinlock_locked) {
			_mm_pause();
		}
	}
}

int
spinlock_trylock(struct spinlock *sl)
{
	return __sync_lock_test_and_set(&sl->spinlock_locked, 1) == 0;
}

void
spinlock_unlock(struct spinlock *sl)
{
	__sync_lock_release(&sl->spinlock_locked);
}

static struct ip_socket *
ip_socket_get(struct ip_socket *x, uint32_t h)
{
	struct dlist *b;
	struct ip_socket *so;

	b = htable_bucket_get(&current->t_in_htable, h);
	DLIST_FOREACH(so, b, ipso_list) {
		if (so->ipso_laddr == x->ipso_laddr && so->ipso_faddr == x->ipso_faddr &&
				so->ipso_lport == x->ipso_lport &&
				so->ipso_fport == x->ipso_fport) {
			return so;
		}
	}
	return NULL;
}

int
ip_connect(struct ip_socket *new, uint32_t *ph)
{
	int i;
	uint32_t h;
	struct ip_socket *cache;

	new->ipso_cache = NULL;
	if (current->t_Lflag) {
		h = SO_HASH(new->ipso_faddr, new->ipso_lport, new->ipso_fport);
		if (ip_socket_get(new, h) != NULL) {
			return -EADDRINUSE;
		}
	} else {
		for (i = 0; i < current->t_dst_cache_size; ++i) {
			cache = current->t_dst_cache + current->t_dst_cache_i;
			current->t_dst_cache_i++;
			if (current->t_dst_cache_i == current->t_dst_cache_size) {
				current->t_dst_cache_i = 0;
			}
			h = cache->ipso_hash;
			if (ip_socket_get(cache, h) == NULL) {
				new->ipso_laddr = cache->ipso_laddr;
				new->ipso_faddr = cache->ipso_faddr;
				new->ipso_lport = cache->ipso_lport;
				new->ipso_fport = cache->ipso_fport;
				new->ipso_cache = cache;
				goto out;
			}
		}
		return -EADDRNOTAVAIL;
	}
out:
	htable_add(&current->t_in_htable, &new->ipso_list, h);
	current->t_n_conns++;
	if (ph != NULL) {
		*ph = h;
	}
	return 0;
}

void
ip_disconnect(struct ip_socket *so)
{
//	if (so->ipso_cache != NULL) {
//		DLIST_INSERT_TAIL(&current->t_dst_cache, so->ipso_cache, ipso_list);
//		so->ipso_cache = NULL;
//	}
	assert(current->t_n_conns);
	current->t_n_conns--;
	htable_del(&current->t_in_htable, &so->ipso_list);
}
