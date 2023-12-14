#include <rte_eal.h>
#include <rte_ethdev.h>

#include "global.h"
#include "subr.h"

#define DPDK_MEMPOOL_CACHE_SIZE 128

struct dpdk_port {
	int n_queues;
	uint16_t n_rxd;
	uint16_t n_txd;
};

static struct dpdk_port g_ports[RTE_MAX_ETHPORTS];
static struct rte_mempool *g_pktmbuf_pool;

static const char *
dpdk_port_name(struct dpdk_port *port, struct rte_eth_dev_info *dev_info)
{
	int port_id;

	port_id = port - g_ports;
	rte_eth_dev_info_get(port_id, dev_info);
	if (dev_info->device == NULL) {
		return "???";
	}

	return dev_info->device->name;
}

int
dpdk_parse_args(int argc, char **argv)
{
	int rc;

	rc = rte_eal_init(argc, argv);

	return rc;
}

static void
dpdk_init(struct thread *threads, int n_threads)
{
	int i, j, rc, n_mbufs;
	const char *port_name;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf port_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rss_conf rss_conf;
	struct thread *t;
	struct dpdk_port *port;

	for (i = 0; i < n_threads; ++i) {
		t = threads + i;

		t->t_busyloop = 1;

		rc = rte_eth_dev_get_port_by_name(t->t_ifname, &t->t_dpdk_port_id);
		if (rc != 0) {
			panic(0, "DPDK doesn't run on port '%s'", t->t_ifname);	
		}

		if (t->t_rss_queue_id == RSS_QUEUE_ID_MAX) {
			t->t_rss_queue_id = 0;
		}

		port = g_ports + t->t_dpdk_port_id;
		port->n_queues = MAX(port->n_queues, t->t_rss_queue_id + 1);
	}

	n_mbufs = CG_TX_PENDING_MAX;

	for (i = 0; i < ARRAY_SIZE(g_ports); ++i) {
		port = g_ports + i;
		if (port->n_queues == 0) {
			continue;
		}

		port_name = dpdk_port_name(port, &dev_info);

		memset(&port_conf, 0, sizeof(port_conf));
		port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
		if (port->n_queues > 1) {
			port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
			port_conf.rx_adv_conf.rss_conf.rss_hf =
				RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
			port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		}
		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}

		rc = rte_eth_dev_configure(i, port->n_queues, port->n_queues, &port_conf);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_configure('%s', %d, %d) failed",
					port_name, port->n_queues, port->n_queues);
		}

		port->n_rxd = 4096;
		port->n_txd = 4096;
		rc = rte_eth_dev_adjust_nb_rx_tx_desc(i, &port->n_rxd, &port->n_txd);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_adjust_nb_rx_tx_desc('%s') failed", port_name);
		}

		n_mbufs += port->n_queues * (port->n_rxd + port->n_txd + DPDK_MAX_PKT_BURST);
	}

	g_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", n_mbufs,
			DPDK_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (g_pktmbuf_pool == NULL) {
		panic(rte_errno, "rte_pktmbuf_pool_create(%d) failed", n_mbufs);
	}

	for (i = 0; i < ARRAY_SIZE(g_ports); ++i) {
		port = g_ports + i;
		if (port->n_queues == 0) {
			continue;
		}

		port_name = dpdk_port_name(port, &dev_info);

		for (j = 0; j < port->n_queues; ++j) {
			rxq_conf = dev_info.default_rxconf;
			rc = rte_eth_rx_queue_setup(i, j, port->n_rxd,
					rte_eth_dev_socket_id(i), &rxq_conf, g_pktmbuf_pool);
			if (rc < 0) {
				panic(-rc, "rte_eth_rx_queue_setup('%s', %d, %d) failed",
						port_name, i, j);
			}

			txq_conf = dev_info.default_txconf;
			rc = rte_eth_tx_queue_setup(i, j, port->n_txd,
					rte_eth_dev_socket_id(i), &txq_conf);
			if (rc < 0) {
				panic(-rc, "rte_eth_tx_queue_setup('%s', %d, %d) failed",
						port_name, i, j);
			}
		}

		rc = rte_eth_dev_start(i);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_start('%s') failed", port_name);
		}

		rc = rte_eth_promiscuous_enable(i);
		if (rc < 0) {
			panic(-rc, "rte_eth_promiscuous_enable('%s') failed", port_name);
		}
	}

	for (i = 0; i < n_threads; ++i) {
		t = threads + i;

		port = g_ports + t->t_dpdk_port_id;

		t->t_rss_queue_num = port->n_queues;
		if (t->t_rss_queue_num < 2) {
			continue;
		}

		port_name = dpdk_port_name(port, &dev_info);

		memset(&rss_conf, 0, sizeof(rss_conf));
		rss_conf.rss_key = t->t_rss_key;
		rc = rte_eth_dev_rss_hash_conf_get(t->t_dpdk_port_id, &rss_conf);
		if (rc == -ENOTSUP) {
			memcpy(t->t_rss_key, freebsd_rss_key, sizeof(t->t_rss_key));
		} else if (rc < 0) {
			panic(-rc, "rte_eth_dev_rss_hash_conf_get('%s') failed", port_name);
		}
	}
}

static bool
dpdk_is_tx_throttled(void)
{
	return current->t_dpdk_tx_bufsiz == DPDK_MAX_PKT_BURST;
}

static void
dpdk_init_tx_packet(struct packet *pkt)
{
	struct rte_mbuf *m;

	m = rte_pktmbuf_alloc(g_pktmbuf_pool);
	if (m == NULL) {
		panic(0, "rte_pktmbuf_alloc() failed");
	}

	pkt->pkt.mbuf = m;
	pkt->pkt.len = 0;
	pkt->pkt.buf = rte_pktmbuf_mtod(m, void *);
}

static void
dpdk_deinit_tx_packet(struct packet *pkt)
{
	struct rte_mbuf *m;

	m = pkt->pkt.mbuf;
	rte_pktmbuf_free(m);

	pkt->pkt.mbuf = NULL;
	pkt->pkt.buf = NULL;
	pkt->pkt.len = 0;
}

static bool
dpdk_tx_packet(struct packet *pkt)
{
	int len;
	struct rte_mbuf *m;

	if (pkt->pkt.buf == pkt->pkt_body) {
		assert(pkt->pkt.mbuf == NULL);
		len = pkt->pkt.len;
		dpdk_init_tx_packet(pkt);
		memcpy(pkt->pkt.buf, pkt->pkt_body, len);
	} else {
		assert(pkt->pkt.mbuf != NULL);
	}

	m = pkt->pkt.mbuf;
	m->data_len = m->pkt_len = pkt->pkt.len;
	m->port = current->t_dpdk_port_id;

	assert(!dpdk_is_tx_throttled());
	pkt->pkt.mbuf = NULL;
	current->t_dpdk_tx_buf[current->t_dpdk_tx_bufsiz++] = m;
	return true;
}

static int
dpdk_rx(int unused)
{
	int i, n;
	struct rte_mbuf *m, *pkts[DPDK_MAX_PKT_BURST];

	n = rte_eth_rx_burst(current->t_dpdk_port_id, current->t_rss_queue_id,
			pkts, ARRAY_SIZE(pkts));
	for (i = 0; i < n; ++i) {
		m = pkts[i];
		io_process(rte_pktmbuf_mtod(m, void *), m->data_len);
		rte_pktmbuf_free(m);
	}

	return n;
}

static void
dpdk_txbuf(void)
{
	int rc;

	rc = rte_eth_tx_burst(current->t_dpdk_port_id, current->t_rss_queue_id,
			current->t_dpdk_tx_buf, current->t_dpdk_tx_bufsiz);

	if (rc == current->t_dpdk_tx_bufsiz) {
		current->t_dpdk_tx_bufsiz = 0;
	} else {
		memmove(current->t_dpdk_tx_buf, current->t_dpdk_tx_buf + rc,
				sizeof(struct rte_mbuf *) * (current->t_dpdk_tx_bufsiz - rc));
		current->t_dpdk_tx_bufsiz -= rc;
	}
}

static void
dpdk_tx(void)
{
	if (current->t_dpdk_tx_bufsiz) {
		dpdk_txbuf();
	}

}

struct transport_ops dpdk_ops = {
	.tr_io_init_op = dpdk_init,
	.tr_io_is_tx_throttled_op = dpdk_is_tx_throttled,
	.tr_io_init_tx_packet_op = dpdk_init_tx_packet,
	.tr_io_deinit_tx_packet_op = dpdk_deinit_tx_packet,
	.tr_io_tx_packet_op = dpdk_tx_packet,
	.tr_io_rx_op = dpdk_rx,
	.tr_io_tx_op = dpdk_tx,
};
