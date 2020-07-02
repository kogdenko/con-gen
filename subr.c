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
ifaddr_init(struct if_addr *ifa)
{
	int i;

	ifa->ifa_ports = xmalloc(NEPHEMERAL * sizeof(struct dlist));
	dlist_init(&ifa->ifa_port_head);
	for (i = 0; i < NEPHEMERAL; ++i) {
		dlist_insert_tail(&ifa->ifa_port_head, ifa->ifa_ports + i);
	}
}

uint16_t
ifaddr_alloc_ephemeral_port(struct if_addr *ifa)
{
	struct dlist *p;

	if (dlist_is_empty(&ifa->ifa_port_head)) {
		return 0;
	}
	p = dlist_first(&ifa->ifa_port_head);
	dlist_remove(p);
	p->dls_next = NULL;
	return EPHEMERAL_MIN + (p - ifa->ifa_ports);
}

void
ifaddr_free_ephemeral_port(struct if_addr *ifa, uint16_t port)
{
	struct dlist *p;

	assert(port >= EPHEMERAL_MIN);
	assert(port <= EPHEMERAL_MAX);
	p = ifa->ifa_ports + (port - EPHEMERAL_MIN);
	assert(p->dls_next == NULL);
	dlist_insert_tail(&ifa->ifa_port_head, p);
}

int
alloc_ephemeral_port(uint32_t *laddr, uint16_t *lport)
{
	int i;
	static int ifai, ifan;
	struct if_addr *ifa;

	for (i = 0; i < current->t_n_addrs; ++i) {
		if (ifan >= NEPHEMERAL) {
			ifan = 0;
			ifai++;
			if (ifai == current->t_n_addrs) {
				ifai = 0;
			}
		}
		ifa = current->t_addrs + ifai;
		ifan++;
		*lport = ifaddr_alloc_ephemeral_port(ifa);
		if (*lport) {
			*laddr = current->t_ip_laddr_min + ifai;
			return 0;
		}
	}
	return -EADDRNOTAVAIL;
}

void
free_ephemeral_port(uint32_t laddr, uint16_t lport)
{
	int ifai;
	struct if_addr *ifa;

	assert(laddr >= current->t_ip_laddr_min);
	ifai = laddr - current->t_ip_laddr_min;
	assert(ifai < current->t_n_addrs);
	ifa = current->t_addrs + ifai;
	ifaddr_free_ephemeral_port(ifa, lport);
}

uint32_t
select_faddr()
{
	static int fi;

	if (fi + current->t_ip_faddr_min > current->t_ip_faddr_max) {
		fi = 0;
	}
	return current->t_ip_faddr_min + fi++;
}

