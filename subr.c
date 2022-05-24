#include "global.h"
#include "subr.h"

#include <sys/resource.h>

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
	print_stats(stdout, 0);
	exit(1);
}

static struct packet *
alloc_tx_packet()
{
	struct packet *pkt;

	if (dlist_is_empty(&current->t_pkt_head)) {
		pkt = malloc(sizeof(*pkt));
		if (pkt == NULL) {
			return NULL;
		}
	} else {
		pkt = DLIST_FIRST(&current->t_pkt_head, struct packet, pkt.list);
		DLIST_REMOVE(pkt, pkt.list);
	}
	return pkt;
}

static void
add_pending_packet(struct packet *pkt)
{
	struct packet *cp;

	cp = alloc_tx_packet();
	if (cp == NULL) {
		return;
	}
	memcpy(cp->pkt_body, pkt->pkt.buf, pkt->pkt.len);
	cp->pkt.len = pkt->pkt.len;
	cp->pkt.buf = cp->pkt_body;
	DLIST_INSERT_TAIL(&current->t_pkt_pending_head, cp, pkt.list);
}

#ifdef HAVE_NETMAP
static struct netmap_ring *
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

static int
netmap_init(struct thread *t, const char *ifname)
{
	int rc;
	char buf[IFNAMSIZ + 7];

	snprintf(buf, sizeof(buf), "netmap:%s", ifname);
	t->t_nmd = nm_open(buf, NULL, 0, NULL);
	if (t->t_nmd == NULL) {
		rc = -errno;
		fprintf(stderr, "nm_open('%s') failed (%s)", buf, strerror(-rc));
		return rc;
	}
	if (t->t_nmd->req.nr_rx_rings != t->t_nmd->req.nr_tx_rings) {
		rc = -EINVAL;
		fprintf(stderr, "%s: nr_rx_rings != nr_tx_rings", buf);
		goto err;
	}
	t->t_n_rss_q = t->t_nmd->req.nr_rx_rings;
	if ((t->t_nmd->req.nr_flags & NR_REG_MASK) == NR_REG_ONE_NIC &&
			t->t_n_rss_q > 1) {
		t->t_rss_qid = t->t_nmd->first_rx_ring;
		rc = read_rss_key(t->t_nmd->req.nr_name, t->t_rss_key);
		if (rc) {
			fprintf(stderr, "%s: Can't read rss key\n", t->t_nmd->req.nr_name);
			goto err;
		}
	}
	t->t_fd = t->t_nmd->fd;
	return 0;
err:
	nm_close(t->t_nmd);
	t->t_nmd = NULL;
	return rc;
}

bool
netmap_is_tx_buffer_full()
{
	return not_empty_txr(NULL) == NULL;
}

void
netmap_init_tx_packet(struct packet *pkt)
{
	pkt->pkt.txr = not_empty_txr(&pkt->pkt.slot);
	if (pkt->pkt.txr == NULL) {
		pkt->pkt.buf = pkt->pkt_body;
	} else {
		pkt->pkt.buf = (u_char *)NETMAP_BUF(pkt->pkt.txr, pkt->pkt.slot->buf_idx);
	}
	pkt->pkt.len = 0;
}

bool
netmap_tx_packet(struct packet *pkt)
{
	u_char *buf;
	struct netmap_ring *txr;

	if (pkt->pkt.txr == NULL) {
		pkt->pkt.txr = not_empty_txr(&pkt->pkt.slot);
		if (pkt->pkt.txr == NULL) {
			add_pending_packet(pkt);
			return false;
		}
		buf = (u_char *)NETMAP_BUF(pkt->pkt.txr, pkt->pkt.slot->buf_idx);
		memcpy(buf, pkt->pkt.buf, pkt->pkt.len);
		pkt->pkt.buf = buf;
	}
	assert(pkt->pkt.len);
	pkt->pkt.slot->len = pkt->pkt.len;
	txr = pkt->pkt.txr;
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
	return true;
}

void
netmap_rx()
{
	int i, j, n;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;

	for (i = current->t_nmd->first_rx_ring; i <= current->t_nmd->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(current->t_nmd->nifp, i);
		n = nm_ring_space(rxr);
		if (n > current->t_burst_size) {
			n = current->t_burst_size;
		}
		for (j = 0; j < n; ++j) {
			DEV_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			(*current->t_rx_op)(NETMAP_BUF(rxr, slot->buf_idx) , slot->len);
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
	}
}
#endif // HAVE_NETMAP

#ifdef HAVE_PCAP
int
cg_pcap_init(struct thread *t, const char *ifname)
{
	int i, rc, fd, *dlt_buf, snaplen;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;

	snaplen = 1500;
	pcap = pcap_create(ifname, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_create('%s') failed (%s)\n", ifname, errbuf);
		return -EINVAL;
	}
	rc = pcap_set_immediate_mode(pcap, 1);
	if (rc < 0) {
		fprintf(stderr, "pcap_set_immediate_mode('%s', 1) failed (%s)\n",
			ifname, pcap_geterr(pcap));
		goto err;
	}
	rc = pcap_set_promisc(pcap, 1);
	if (rc < 0) {
		fprintf(stderr, "pcap_set_promisc('%s', 1) failed (%s)\n",
			ifname, pcap_geterr(pcap));
		goto err;
	}
	rc = pcap_set_snaplen(pcap, snaplen);
	if (rc < 0) {
		fprintf(stderr, "pcap_set_snaplen('%s', %d) failed (%s)\n",
			ifname, snaplen, pcap_geterr(pcap));
		goto err;
	}
	rc = pcap_activate(pcap);
	if (rc != 0) {
		fprintf(stderr, "pcap_activate('%s') failed (%s)\n", ifname, pcap_geterr(pcap));
		goto err;
	}
	rc = pcap_list_datalinks(pcap, &dlt_buf);
	if (rc < 0) {
		fprintf(stderr, "pcap_list_datatlinks('%s') failed (%s)\n",
			ifname, pcap_geterr(pcap));
		goto err;
	}
	for (i = 0; i < rc; ++i) {
		if (dlt_buf[i] == DLT_EN10MB) {
			break;
		}
	}
	if (i == rc) {
		fprintf(stderr, "%s doesn't support DLT_EN10MB datalink type\n", ifname);
		goto err;
	}
	pcap_free_datalinks(dlt_buf);
	pcap_setdirection(pcap, PCAP_D_IN);
	rc = pcap_setnonblock(pcap, 1, errbuf);
	if (rc < 0) {
		fprintf(stderr, "pcap_setnonblock('%s') failed (%s)\n", ifname, errbuf);
		goto err;
	}
	fd = pcap_get_selectable_fd(pcap);
	if (fd < 0) {
		fprintf(stderr, "pcap_get_selectable_fd('%s') failed (%s)",
			ifname, pcap_geterr(pcap));
		goto err;
	}
	t->t_pcap = pcap;
	t->t_fd = fd;
	return 0;
err:
	pcap_close(pcap);
	return -EINVAL;
}

bool
pcap_is_tx_buffer_full()
{
	return current->t_tx_throttled;
}

void
pcap_init_tx_packet(struct packet *pkt)
{
	pkt->pkt.buf = pkt->pkt_body;
	pkt->pkt.len = 0;
}

bool
pcap_tx_packet(struct packet *pkt)
{
	assert(pkt->pkt_len);
	if (pcap_inject(current->t_pcap, pkt->pkt_buf, pkt->pkt_len) <= 0) {
		current->t_tx_throttled = 1;
		add_pending_packet(pkt);
		return false;
	} else {
		return true;
	}
}

void
pcap_rx()
{
	int i, rc;
	const u_char *pkt_dat;
	struct pcap_pkthdr *pkt_hdr;

	for (i = 0; i < current->t_burst_size; ++i) {
		rc = pcap_next_ex(current->t_pcap, &pkt_hdr, &pkt_dat);
		if (rc == 1) {
			(*current->t_rx_op)((void *)pkt_dat, pkt_hdr->caplen);
		} else {
			break;
		}
	}
}
#endif // HAVE_PCAP

#ifdef HAVE_XDP

#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_INVALID UINT64_MAX

static uint64_t
alloc_frame(struct thread *t)
{
	uint64_t frame;

	if (t->t_xdp_frame_free == 0) {
		return FRAME_INVALID;
	}
	frame = t->t_xdp_frame[--t->t_xdp_frame_free];
	t->t_xdp_frame[t->t_xdp_frame_free] = FRAME_INVALID;
	//printf("alloc %"PRIu64", rem=%u\n", frame, t->t_xdp_frame_free);
	return frame;
}

static void
free_frame(struct thread *t, uint64_t frame)
{
	/*int i;
	printf("free %"PRIu64", rem=%u\n", frame, t->t_xdp_frame_free + 1);
	for (i = 0; i < t->t_xdp_frame_free; ++i) {
		if (t->t_xdp_frame[i] == frame) {
			printf("Duplicate %"PRIu64"\n", frame);
			assert(0);
		}
	}*/
	assert(t->t_xdp_frame_free < XDP_FRAME_NUM);
	t->t_xdp_frame[t->t_xdp_frame_free++] = frame;
}

static void
xdp_configure_socket(struct thread *t, const char *ifname)
{
	int rc, i, ifindex;
	uint32_t idx;
	struct xsk_socket_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	rc = xsk_socket__create(&t->t_xdp_xsk, ifname, 0/*qid*/, t->t_xdp_umem,
		&t->t_xdp_rxq, &t->t_xdp_txq, &cfg);
	if (rc < 0) {
		panic(-rc, "xsk_socket__create() failed");
	}
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		panic(errno, "if_nametoindex('%s') failed", ifname);
	}
	rc = bpf_get_link_xdp_id(ifindex, &t->t_xdp_prog_id, 0);
	if (rc < 0) {
		panic(-rc, "bpf_get_link_xdp_id() failed");
	}
	idx = UINT32_MAX;
	rc = xsk_ring_prod__reserve(&t->t_xdp_fillq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (rc != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		panic(0, "xsk_ring_prod__reserve() failed");
	}
	assert(idx != UINT32_MAX);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++, idx++) {
		*xsk_ring_prod__fill_addr(&t->t_xdp_fillq, idx) = alloc_frame(t);
	}
	xsk_ring_prod__submit(&t->t_xdp_fillq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
}

static int
xdp_init(struct thread *t, const char *ifname)
{
	int i, rc, size;

	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &rlim );

	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	if (posix_memalign(&t->t_xdp_buf, getpagesize(), size)) {
		panic(errno, "posix_memalign(%d) failed", size);
	}
	for (i = 0; i < XDP_FRAME_NUM; ++i) {
		t->t_xdp_frame[i] = i * XDP_FRAME_SIZE;
	}
	t->t_xdp_frame_free = XDP_FRAME_NUM;
	rc = xsk_umem__create(&t->t_xdp_umem, t->t_xdp_buf, size,
		&t->t_xdp_fillq, &t->t_xdp_compq, NULL);
	if (rc < 0) {
		panic(-rc, "xsk_umem__create() failed");
	}
	xdp_configure_socket(t, ifname);
	t->t_fd = xsk_socket__fd(t->t_xdp_xsk);
	return 0;
}

static void *
xdp_get_tx_buf(uint32_t *idx)
{
	int rc;
	void *buf;
	uint64_t addr;

	if (current->t_tx_throttled == 1) {
		return NULL;
	}
	if (current->t_xdp_frame_free == 0) {
		goto throttled;
	}
	if (current->t_xdp_tx_buf != NULL) {
		buf = current->t_xdp_tx_buf;
		*idx = current->t_xdp_tx_idx;
		current->t_xdp_tx_buf = NULL;
		//dbg("Her!");
		return buf;
	}
	rc = xsk_ring_prod__reserve(&current->t_xdp_txq, 1, idx);
	assert(rc <= 1);
	if (rc == 0) {
		goto throttled;
	}
	addr = alloc_frame(current);
	xsk_ring_prod__tx_desc(&current->t_xdp_txq, *idx)->addr = addr;
	addr = xsk_umem__add_offset_to_addr(addr);
	buf = xsk_umem__get_data(current->t_xdp_buf, addr);
	return buf;
throttled:
	current->t_tx_throttled = 1;
	return NULL;
}

bool
xdp_is_tx_buffer_full()
{
	if (current->t_tx_throttled == 1) {
		return true;
	}
	if (xsk_prod_nb_free(&current->t_xdp_txq, 1) == 0) {
		current->t_tx_throttled = 1;
		return true;
	} else {
		return false;
	}
}

void
xdp_init_tx_packet(struct packet *pkt)
{
	void *buf;

	pkt->pkt.len = 0;
	buf = xdp_get_tx_buf(&pkt->pkt.idx);
	if (buf == NULL) {
		pkt->pkt.buf = pkt->pkt_body;
	} else {
		pkt->pkt.buf = buf;
	}
}

void
xdp_deinit_tx_packet(struct packet *pkt)
{
	if (pkt->pkt.buf != pkt->pkt_body && pkt->pkt.buf != NULL) {
//		dbg("Not used TX buf");
		assert(current->t_xdp_tx_buf == NULL);
		current->t_xdp_tx_buf = pkt->pkt.buf;
		current->t_xdp_tx_idx = pkt->pkt.idx;
		pkt->pkt.buf = NULL;
	}
}

bool
xdp_tx_packet(struct packet *pkt)
{
	void *buf;

	assert(pkt->pkt.len);
	if (pkt->pkt.buf == pkt->pkt_body) {
		buf = xdp_get_tx_buf(&pkt->pkt.idx);
		if (buf == NULL) {
			add_pending_packet(pkt);
			return false;
		}
		memcpy(buf, pkt->pkt.buf, pkt->pkt.len);
		pkt->pkt.buf = buf;
	}
	xsk_ring_prod__tx_desc(&current->t_xdp_txq, pkt->pkt.idx)->len = pkt->pkt.len;
	xsk_ring_prod__submit(&current->t_xdp_txq, 1);
	current->t_xdp_tx_outstanding++;
	pkt->pkt.buf = NULL;
	return true;
}

void
xdp_tx()
{
	int i, n;
	uint32_t idx;
	uint64_t addr;

	if (current->t_xdp_tx_outstanding == 0) {
		return;
	}
	sendto(current->t_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	idx = UINT32_MAX;
	n = xsk_ring_cons__peek(&current->t_xdp_compq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx);
	if (n <= 0) {
		return;
	}
	assert(idx != UINT32_MAX);
	for (i = 0; i < n; ++i, ++idx) {
		addr = *xsk_ring_cons__comp_addr(&current->t_xdp_compq, idx);
		free_frame(current, addr);
	}
	xsk_ring_cons__release(&current->t_xdp_compq, n);
	assert(n <= current->t_xdp_tx_outstanding);
	current->t_xdp_tx_outstanding -= n;
}

void
xdp_rx()
{
	int i, n, m, rc, len;
	uint32_t idx_rx, idx_fill;
	uint64_t addr, frame;
	struct xsk_ring_prod *fillq;

	n = xsk_ring_cons__peek(&current->t_xdp_rxq, current->t_burst_size, &idx_rx);
	if (n == 0) {
		return;
	}
	for (i = 0; i < n; ++i, ++idx_rx) {
		addr = xsk_ring_cons__rx_desc(&current->t_xdp_rxq, idx_rx)->addr;
		frame = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		len = xsk_ring_cons__rx_desc(&current->t_xdp_rxq, idx_rx)->len;
		(*current->t_rx_op)(xsk_umem__get_data(current->t_xdp_buf, addr), len);
		free_frame(current, frame);
	}
	xsk_ring_cons__release(&current->t_xdp_rxq, n);

	fillq = &current->t_xdp_fillq;
	m = xsk_prod_nb_free(fillq, current->t_xdp_frame_free);
	if (m > 0) {
		m = MIN(m, current->t_xdp_frame_free);
		idx_fill = UINT32_MAX;
		rc = xsk_ring_prod__reserve(fillq, m, &idx_fill);
		assert(rc == m);
		assert(idx_fill != UINT32_MAX);
		UNUSED(rc);
		for (i = 0; i < m; ++i, ++idx_fill) {
			frame = alloc_frame(current);
			*xsk_ring_prod__fill_addr(fillq, idx_fill) = frame;
		}
		xsk_ring_prod__submit(fillq, m);
	}
}
#endif // HAVE_XDP

void
set_transport(struct thread *t, int transport)
{
	switch (transport) {
#ifdef HAVE_NETMAP
	case TRANSPORT_NETMAP:
		t->t_io_init_op = netmap_init;
		t->t_io_is_tx_buffer_full_op = netmap_is_tx_buffer_full;
		t->t_io_init_tx_packet_op = netmap_init_tx_packet;
		t->t_io_tx_packet_op = netmap_tx_packet;
		t->t_io_rx_op = netmap_rx;
		break;
#endif
#ifdef HAVE_PCAP
	case TRANSPORT_PCAP:
		t->t_io_init_op = cg_pcap_init;
		t->t_io_is_tx_buffer_full_op = pcap_is_tx_buffer_full;
		t->t_io_init_tx_packet_op = pcap_init_tx_packet;
		t->t_io_tx_packet_op = pcap_tx_packet;
		t->t_io_rx_op = pcap_rx;
		break;
#endif
#ifdef HAVE_XDP
	case TRANSPORT_XDP:
		t->t_io_init_op = xdp_init;
		t->t_io_is_tx_buffer_full_op = xdp_is_tx_buffer_full;
		t->t_io_init_tx_packet_op = xdp_init_tx_packet;
		t->t_io_deinit_tx_packet_op = xdp_deinit_tx_packet;
		t->t_io_tx_packet_op = xdp_tx_packet;
		t->t_io_rx_op = xdp_rx;
		t->t_io_tx_op = xdp_tx;
		break;
#endif
	default:
		panic(0, "Transport %d not supported", transport);
		break;
	}
}

int
io_init(struct thread *t, const char *ifname)
{
	return (*t->t_io_init_op)(t, ifname);
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
io_is_tx_buffer_full()
{
	return (*current->t_io_is_tx_buffer_full_op)();
}

bool
io_tx_packet(struct packet *pkt)
{
	int len;
	bool sent;

	len = pkt->pkt.len;
	sent = (*current->t_io_tx_packet_op)(pkt);
	if (sent) {
		counter64_add(&if_obytes, len);
		counter64_inc(&if_opackets);
	}
	return sent;
}

void
io_rx()
{
	(*current->t_io_rx_op)();
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

#ifdef HAVE_NETMAP
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
		fprintf(stderr, "%s: ioctl(SIOCETHTOOL) failed\n", ifname);
		goto out;
	}
	if (rss.key_size != RSS_KEY_SIZE) {
		fprintf(stderr, "%s: Invalid rss key_size (%d)\n", ifname, rss.key_size);
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
		fprintf(stderr, "%s: ioctl(SIOCETHTOOL) failed\n", ifname);
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
	static uint8_t freebsd_rss_key[RSS_KEY_SIZE] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
		0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
		0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
		0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
		0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	};
	memcpy(rss_key, freebsd_rss_key, RSS_KEY_SIZE);
	return 0;
}
#endif // __linux__
#endif // HAVE_NETMAP

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
