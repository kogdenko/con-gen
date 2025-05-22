#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
//#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include "subr.h"
#include "global.h"

#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_INVALID UINT64_MAX

#define XDP_FRAME_NUM \
	(2 * (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS))

struct xdp_queue {
	struct xsk_ring_prod xq_fill;
	struct xsk_ring_cons xq_comp;
	struct xsk_ring_prod xq_tx;
	struct xsk_ring_cons xq_rx;
	int xq_tx_outstanding;
	int xq_fd;
	int xq_frame_free;
	void *xq_buf;
	struct xsk_umem *xq_umem;
	struct xsk_socket *xq_xsk;
	void *xq_tx_buf;
	uint32_t xq_tx_idx;
	uint64_t xq_frame[XDP_FRAME_NUM];
};

static uint64_t
alloc_frame(struct xdp_queue *q)
{
	uint64_t frame;

	if (q->xq_frame_free == 0) {
		return FRAME_INVALID;
	}
	frame = q->xq_frame[--q->xq_frame_free];
	q->xq_frame[q->xq_frame_free] = FRAME_INVALID;
	return frame;
}

static void
free_frame(struct xdp_queue *q, uint64_t frame)
{
	assert(q->xq_frame_free < XDP_FRAME_NUM);
	q->xq_frame[q->xq_frame_free++] = frame;
}

static int
get_interface_queue_num(const char *ifname)
{
	struct ifreq req;
	int fd;
	struct ethtool_channels cmd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1) {
		panic(errno, "Get interface (%s) channels error: socket() failed", ifname);
	}
	strzcpy(req.ifr_name, ifname, sizeof(req.ifr_name));
	req.ifr_data = (void *)&cmd;
	cmd.cmd = ETHTOOL_GCHANNELS;
	if (ioctl(fd, SIOCETHTOOL, &req) == -1) {
		panic(errno, "%s: ioctl(ETHTOOL_GCHANNELS) failed", ifname);
	}
	close(fd);
	return cmd.combined_count + cmd.rx_count;
}

static void
xdp_init_queue(struct xdp_queue *q, const char *ifname, int queue_id)
{
	int i, rc, size;
	uint32_t idx;
	struct xsk_socket_config cfg;

	memset(q, 0, sizeof(*q));
	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	if (posix_memalign(&q->xq_buf, getpagesize(), size)) {
		panic(errno, "posix_memalign(%d) failed", size);
	}
	for (i = 0; i < XDP_FRAME_NUM ; ++i) {
		q->xq_frame[i] = i * XDP_FRAME_SIZE;
	}
	q->xq_frame_free = XDP_FRAME_NUM;
	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	rc = xsk_umem__create(&q->xq_umem, q->xq_buf, size, &q->xq_fill, &q->xq_comp, NULL);
	if (rc < 0) {
		panic(-rc, "xsk_umem__create() failed");
	}
	memset(&cfg, 0, sizeof(cfg));
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	rc = xsk_socket__create(&q->xq_xsk, ifname, queue_id, q->xq_umem,
		&q->xq_rx, &q->xq_tx, &cfg);
	if (rc < 0) {
		panic(-rc, "xsk_socket__create() failed");
	}
	idx = UINT32_MAX;
	rc = xsk_ring_prod__reserve(&q->xq_fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (rc != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		panic(0, "xsk_ring_prod__reserve() failed");
	}
	assert(idx != UINT32_MAX);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++, idx++) {
		*xsk_ring_prod__fill_addr(&q->xq_fill, idx) = alloc_frame(q);
	}
	xsk_ring_prod__submit(&q->xq_fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	q->xq_fd = xsk_socket__fd(q->xq_xsk);
}

static void
xdp_init_if(struct thread *t)
{
	int i, ifindex;

	ifindex = if_nametoindex(t->t_ifname);
	if (ifindex == 0) {
		panic(errno, "if_nametoindex('%s') failed", t->t_ifname);
	}
	t->t_rss_queue_num = get_interface_queue_num(t->t_ifname);
	if (t->t_rss_queue_id < RSS_QUEUE_ID_MAX) {
		t->t_xdp_queue_num = 1;
		if (t->t_rss_queue_num > 1) {
			t->t_rss_key_size = read_rss_key(t->t_ifname, &t->t_rss_key);
		}
	} else {
		t->t_xdp_queue_num = t->t_rss_queue_num;
	}
//	rc = bpf_xdp_query_id(ifindex, 0, &t->t_xdp_prog_id);
//	if (rc < 0) {
//		panic(-rc, "bpf_xdp_query_id() failed");
//	}
	t->t_xdp_queues = xmalloc(t->t_xdp_queue_num * sizeof(struct xdp_queue));
	if (t->t_rss_queue_id < RSS_QUEUE_ID_MAX) {
		xdp_init_queue(&t->t_xdp_queues[0], t->t_ifname, t->t_rss_queue_id);
	} else {
		for (i = 0; i < t->t_xdp_queue_num; ++i) {
			xdp_init_queue(&t->t_xdp_queues[i], t->t_ifname, i);
		}
	}
	for (i = 0; i < t->t_xdp_queue_num; ++i) {
		multiplexer_add(t, t->t_xdp_queues[i].xq_fd);
	}
}

static void
xdp_init(struct thread *threads, int n_threads)
{
	int i;

	for (i = 0; i < n_threads; ++i) {
		xdp_init_if(threads + i);
	}
}

static void *
xdp_get_tx_buf(struct packet *pkt)
{
	int i, rc;
	void *buf;
	uint64_t addr;
	struct xdp_queue *q;

	for (i = 0; i < current->t_xdp_queue_num; ++i) {
		q = current->t_xdp_queues + i;
		if (q->xq_tx_buf != NULL) {
			buf = q->xq_tx_buf;
			q->xq_tx_buf = NULL;
			pkt->pkt.idx = q->xq_tx_idx;
			pkt->pkt.queue_idx = i;
			return buf;
		}
		if (q->xq_frame_free == 0) {
			continue;
		}
		rc = xsk_ring_prod__reserve(&q->xq_tx, 1, &pkt->pkt.idx);
		assert(rc <= 1);
		if (rc == 1) {
			addr = alloc_frame(q);
			xsk_ring_prod__tx_desc(&q->xq_tx, pkt->pkt.idx)->addr = addr;
			addr = xsk_umem__add_offset_to_addr(addr);
			buf = xsk_umem__get_data(q->xq_buf, addr);
			pkt->pkt.queue_idx = i;
			return buf;
		} else {
			multiplexer_pollout(i);
		}
	}
	return NULL;
}

bool
xdp_is_tx_throttled(void)
{
	int i;
	struct xdp_queue *q;

	for (i = 0; i < current->t_xdp_queue_num; ++i) {
		if ((multiplexer_get_events(i) & POLLOUT) == 0) {
			q = current->t_xdp_queues + i;
			if (xsk_prod_nb_free(&q->xq_tx, 1) > 0) {
				return false;
			} else {
				multiplexer_pollout(i);
			}
		}
	}
	return true;
}

void
xdp_init_tx_packet(struct packet *pkt)
{
	void *buf;

	pkt->pkt.len = 0;
	buf = xdp_get_tx_buf(pkt);
	if (buf == NULL) {
		pkt->pkt.buf = pkt->pkt_body;
	} else {
		pkt->pkt.buf = buf;
	}
}

void
xdp_deinit_tx_packet(struct packet *pkt)
{
	struct xdp_queue *q;

	if (pkt->pkt.buf != pkt->pkt_body && pkt->pkt.buf != NULL) {
		q = current->t_xdp_queues + pkt->pkt.queue_idx;
		assert(q->xq_tx_buf == NULL);
		q->xq_tx_buf = pkt->pkt.buf;
		q->xq_tx_idx = pkt->pkt.idx;
		pkt->pkt.buf = NULL;
	}
}

bool
xdp_tx_packet(struct packet *pkt)
{
	void *buf;
	struct xdp_queue *q;

	assert(pkt->pkt.len);
	if (pkt->pkt.buf == pkt->pkt_body) {
		buf = xdp_get_tx_buf(pkt);
		if (buf == NULL) {
			add_pending_packet(pkt);
			return false;
		}
		memcpy(buf, pkt->pkt.buf, pkt->pkt.len);
		pkt->pkt.buf = buf;
	}
	q = current->t_xdp_queues + pkt->pkt.queue_idx;
	xsk_ring_prod__tx_desc(&q->xq_tx, pkt->pkt.idx)->len = pkt->pkt.len;
	xsk_ring_prod__submit(&q->xq_tx, 1);
	q->xq_tx_outstanding++;
	pkt->pkt.buf = NULL;
	return true;
}

void
xdp_tx(void)
{
	int i, j, n;
	uint32_t idx;
	uint64_t addr;
	struct xdp_queue *q;

	for (i = 0; i < current->t_xdp_queue_num; ++i) {
		q = current->t_xdp_queues + i;
		if (q->xq_tx_outstanding == 0) {
			continue;
		}
		sendto(q->xq_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
		idx = UINT32_MAX;
		n = xsk_ring_cons__peek(&q->xq_comp, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx);
		if (n <= 0) {
			continue;
		}
		assert(idx != UINT32_MAX);
		for (j = 0; j < n; ++j, ++idx) {
			addr = *xsk_ring_cons__comp_addr(&q->xq_comp, idx);
			free_frame(q, addr);
		}
		xsk_ring_cons__release(&q->xq_comp, n);
		assert(n <= q->xq_tx_outstanding);
		q->xq_tx_outstanding -= n;
	}
}

int
xdp_rx(int queue_id)
{
	int i, n, m, rc, len;
	uint32_t idx_rx, idx_fill;
	uint64_t addr, frame;
	struct xdp_queue *q;

	q = current->t_xdp_queues + queue_id;
	idx_rx = 0;
	n = xsk_ring_cons__peek(&q->xq_rx, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_rx);
	if (n == 0) {
		return 0;
	}
	for (i = 0; i < n; ++i) {
		addr = xsk_ring_cons__rx_desc(&q->xq_rx, idx_rx + i)->addr;
		frame = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		len = xsk_ring_cons__rx_desc(&q->xq_rx, idx_rx + i)->len;
		io_process(xsk_umem__get_data(q->xq_buf, addr), len);
		free_frame(q, frame);
	}
	xsk_ring_cons__release(&q->xq_rx, n);

	m = xsk_prod_nb_free(&q->xq_fill, q->xq_frame_free);
	if (m > 0) {
		m = MIN(m, q->xq_frame_free);
		idx_fill = UINT32_MAX;
		rc = xsk_ring_prod__reserve(&q->xq_fill, m, &idx_fill);
		assert(rc == m);
		assert(idx_fill != UINT32_MAX);
		UNUSED(rc);
		for (i = 0; i < m; ++i, ++idx_fill) {
			frame = alloc_frame(q);
			*xsk_ring_prod__fill_addr(&q->xq_fill, idx_fill) = frame;
		}
		xsk_ring_prod__submit(&q->xq_fill, m);
	}
	return n;
}

struct transport_ops xdp_ops = {
	.tr_io_init_op = xdp_init,
	.tr_io_is_tx_throttled_op = xdp_is_tx_throttled,
	.tr_io_init_tx_packet_op = xdp_init_tx_packet,
	.tr_io_deinit_tx_packet_op = xdp_deinit_tx_packet,
	.tr_io_tx_packet_op = xdp_tx_packet,
	.tr_io_rx_op = xdp_rx,
	.tr_io_tx_op = xdp_tx,
};
