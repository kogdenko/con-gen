#include "subr.h"
#include "global.h"
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

static struct netmap_ring *
not_empty_txr(struct netmap_slot **pslot)
{
	int i;
	struct netmap_ring *txr;

	if (multiplexer_get_events(0) & POLLOUT) {
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
	multiplexer_pollout(0);
	return NULL;
}

static void
netmap_init(const char *ifname)
{
	char buf[IFNAMSIZ + 7];

	snprintf(buf, sizeof(buf), "netmap:%s", ifname);
	current->t_nmd = nm_open(buf, NULL, 0, NULL);
	if (current->t_nmd == NULL) {
		panic(errno, "nm_open('%s') failed", buf);
	}
	if (current->t_nmd->req.nr_rx_rings != current->t_nmd->req.nr_tx_rings) {
		panic(0, "%s: nr_rx_rings != nr_tx_rings", buf);
	}
	current->t_rss_queue_num = current->t_nmd->req.nr_rx_rings;
	if ((current->t_nmd->req.nr_flags & NR_REG_MASK) == NR_REG_ONE_NIC) {
		current->t_rss_queue_id = current->t_nmd->first_rx_ring;
	}
	strzcpy(current->t_ifname, current->t_nmd->req.nr_name, sizeof(current->t_ifname));
	multiplexer_add(current->t_nmd->fd);
}

bool
netmap_is_tx_throttled()
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

void
set_netmap_ops(struct thread *t)
{
	t->t_io_init_op = netmap_init;
	t->t_io_is_tx_throttled_op = netmap_is_tx_throttled;
	t->t_io_init_tx_packet_op = netmap_init_tx_packet;
	t->t_io_tx_packet_op = netmap_tx_packet;
	t->t_io_rx_op = netmap_rx;
}
