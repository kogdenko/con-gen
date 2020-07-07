#include "global.h"
#include "subr.h"

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

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	return ~((uint16_t)sum);
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

	fprintf(stderr, "%s:%d: ", file, line);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum) {
		fprintf(stderr, " (%d:%s)", errnum, strerror(errnum));
	}
	fprintf(stderr, "\n");
	abort();
}

struct netmap_ring *
not_empty_txr(struct netmap_slot **pslot)
{
	int i;
	struct netmap_ring *txr;

	if (current->t_tx_throttled) {
		return NULL;
	}
	for (i = current->t_nmd->first_tx_ring;
	     i <= current->t_nmd->last_tx_ring; ++i) {
		txr = NETMAP_TXRING(current->t_nmd->nifp, i);
		if (!nm_ring_empty(txr)) {
			if (pslot != NULL) {
				*pslot = txr->slot + txr->cur;
				(*pslot)->len = 0;
			}
			return txr;	
		}
	}
	current->t_tx_throttled = 1;
	return NULL;
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
		if (so->ipso_laddr == x->ipso_laddr &&
		    so->ipso_faddr == x->ipso_faddr &&
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
