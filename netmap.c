#include "subr.h"
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#if 0
#define CG_PREFETCH(ring)
#else
#define CG_PREFETCH(ring) \
	MEM_PREFETCH(NETMAP_BUF((ring), \
		((ring)->slot + nm_ring_next(ring, (ring)->cur))->buf_idx))
#endif

static struct netmap_ring *
not_empty_txr(struct cg_task *t, struct netmap_slot **pslot)
{
	int i;
	struct netmap_ring *txr;

	if (multiplexer_get_events(t, 0) & POLLOUT) {
		return NULL;
	}
	for (i = t->t_nmd->first_tx_ring; i <= t->t_nmd->last_tx_ring; ++i) {
		txr = NETMAP_TXRING(t->t_nmd->nifp, i);
		if (!nm_ring_empty(txr)) {
			if (pslot != NULL) {
				*pslot = txr->slot + txr->cur;
				(*pslot)->len = 0;
			}
			return txr;	
		}
	}
	multiplexer_pollout(t, 0);
	return NULL;
}

static void
netmap_init_task(struct cg_task *t)
{
	char buf[IFNAMSIZ + 64];

	if (t->t_rss_queue_id < RSS_QUEUE_ID_MAX) {
		snprintf(buf, sizeof(buf), "netmap:%s-%d", t->t_ifname, t->t_rss_queue_id);
	} else {
		snprintf(buf, sizeof(buf), "netmap:%s", t->t_ifname);
	}
	t->t_nmd = nm_open(buf, NULL, 0, NULL);
	if (t->t_nmd == NULL) {
		panic(errno, "nm_open('%s') failed", buf);
	}

	assert(t->t_nmd->req.nr_rx_rings == t->t_nmd->req.nr_tx_rings);

	t->t_rss_queue_num = t->t_nmd->req.nr_rx_rings;
	if (t->t_rss_queue_num > 1) {
		t->t_rss_key_size = read_rss_key(t->t_ifname, &t->t_rss_key);
	}

	multiplexer_add(t, t->t_nmd->fd);
}

static void
netmap_init(void)
{
	struct cg_task *t;

	CG_TASK_FOREACH(t) {
		netmap_init_task(t);
	}
}

static bool
netmap_is_tx_throttled(struct cg_task *t)
{
	return not_empty_txr(t, NULL) == NULL;
}

static void
netmap_init_tx_packet(struct cg_task *t, struct packet *pkt)
{
	pkt->pkt.txr = not_empty_txr(t, &pkt->pkt.slot);
	if (pkt->pkt.txr == NULL) {
		pkt->pkt.buf = pkt->pkt_body;
	} else {
		pkt->pkt.buf = (u_char *)NETMAP_BUF(pkt->pkt.txr, pkt->pkt.slot->buf_idx);
	}
	pkt->pkt.len = 0;
}

static bool
netmap_tx_packet(struct cg_task *t, struct packet *pkt)
{
	u_char *buf;
	struct netmap_ring *txr;

	if (pkt->pkt.txr == NULL) {
		pkt->pkt.txr = not_empty_txr(t, &pkt->pkt.slot);
		if (pkt->pkt.txr == NULL) {
			add_pending_packet(t, pkt);
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

static int
netmap_rx(struct cg_task *t, int queue_id)
{
	int i, j, n, accum;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;

	accum = 0;
	for (i = t->t_nmd->first_rx_ring; i <= t->t_nmd->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(t->t_nmd->nifp, i);
		n = nm_ring_space(rxr);
		for (j = 0; j < n; ++j) {
			CG_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			io_process(t, NETMAP_BUF(rxr, slot->buf_idx) , slot->len);
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
		accum += n;
	}

	return accum;
}

struct transport_ops netmap_ops = {
	.tr_io_init_op = netmap_init,
	.tr_io_is_tx_throttled_op = netmap_is_tx_throttled,
	.tr_io_init_tx_packet_op = netmap_init_tx_packet,
	.tr_io_tx_packet_op = netmap_tx_packet,
	.tr_io_rx_op = netmap_rx,
};
