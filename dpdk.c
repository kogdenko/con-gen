#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_version.h>

#include "global.h"
#include "subr.h"

#if RTE_VERSION <= RTE_VERSION_NUM(21, 8, 0, 99)
#define DPDK_ETH_MQ_TX_NONE ETH_MQ_TX_NONE
#define DPDK_ETH_TX_OFFLOAD_MBUF_FAST_FREE DEV_TX_OFFLOAD_MBUF_FAST_FREE
#define DPDK_ETH_MQ_RX_RSS ETH_MQ_RX_RSS
#define DPDK_ETH_RSS_IP ETH_RSS_IP
#define DPDK_ETH_RSS_TCP ETH_RSS_TCP
#define DPDK_ETH_RSS_UDP ETH_RSS_UDP
#else
#define DPDK_ETH_MQ_TX_NONE RTE_ETH_MQ_TX_NONE
#define DPDK_ETH_TX_OFFLOAD_MBUF_FAST_FREE RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
#define DPDK_ETH_MQ_RX_RSS RTE_ETH_MQ_RX_RSS
#define DPDK_ETH_RSS_IP RTE_ETH_RSS_IP
#define DPDK_ETH_RSS_TCP RTE_ETH_RSS_TCP
#define DPDK_ETH_RSS_UDP RTE_ETH_RSS_UDP
#endif

#define DPDK_MEMPOOL_CACHE_SIZE 128

#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 16)
#error "Too old DPDK version (not tested)"
#endif

struct dpdk_port {
	int n_queues;
	uint16_t n_rxd;
	uint16_t n_txd;
};

static struct dpdk_port g_ports[RTE_MAX_ETHPORTS];
static struct rte_mempool *g_pktmbuf_pool;

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
	int i, rc, n_mbufs, port_id, socket_id;
	char port_name[RTE_ETH_NAME_MAX_LEN];
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

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_ports + port_id;
		if (port->n_queues == 0) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);
		rc = rte_eth_dev_info_get(port_id, &dev_info);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_info_get('%s') failed", port_name);
		}

		memset(&port_conf, 0, sizeof(port_conf));
		port_conf.txmode.mq_mode = DPDK_ETH_MQ_TX_NONE;
		if (port->n_queues > 1) {
			port_conf.rxmode.mq_mode = DPDK_ETH_MQ_RX_RSS;
			port_conf.rx_adv_conf.rss_conf.rss_hf =
				DPDK_ETH_RSS_IP | DPDK_ETH_RSS_TCP | DPDK_ETH_RSS_UDP;
			port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		}
		if (dev_info.tx_offload_capa & DPDK_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port_conf.txmode.offloads |= DPDK_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}

		rc = rte_eth_dev_configure(port_id, port->n_queues, port->n_queues, &port_conf);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_configure('%s', %d, %d) failed",
					port_name, port->n_queues, port->n_queues);
		}

		port->n_rxd = 4096;
		port->n_txd = 4096;
		rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &port->n_rxd, &port->n_txd);
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

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_ports + port_id;
		if (port->n_queues == 0) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);
		rc = rte_eth_dev_info_get(port_id, &dev_info);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_info_get('%s') failed", port_name);
		}

		for (i = 0; i < port->n_queues; ++i) {
			rxq_conf = dev_info.default_rxconf;
			socket_id = rte_eth_dev_socket_id(port_id);
			rc = rte_eth_rx_queue_setup(port_id, i, port->n_rxd,
					socket_id, &rxq_conf, g_pktmbuf_pool);
			if (rc < 0) {
				panic(-rc, "rte_eth_rx_queue_setup('%s', %d, %d) failed",
						port_name, port_id, i);
			}

			txq_conf = dev_info.default_txconf;
			rc = rte_eth_tx_queue_setup(port_id, i, port->n_txd, socket_id, &txq_conf);
			if (rc < 0) {
				panic(-rc, "rte_eth_tx_queue_setup('%s', %d, %d) failed",
						port_name, port_id, i);
			}
		}

		rc = rte_eth_dev_start(port_id);
		if (rc < 0) {
			panic(-rc, "rte_eth_dev_start('%s') failed", port_name);
		}

		rte_eth_promiscuous_enable(port_id);
	}

	for (i = 0; i < n_threads; ++i) {
		t = threads + i;

		port = g_ports + t->t_dpdk_port_id;

		t->t_rss_queue_num = port->n_queues;
		if (t->t_rss_queue_num < 2) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);

		memset(&rss_conf, 0, sizeof(rss_conf));
		t->t_rss_key = xmalloc(40);
		t->t_rss_key_size = 40;
		rss_conf.rss_key = t->t_rss_key;
		rc = rte_eth_dev_rss_hash_conf_get(t->t_dpdk_port_id, &rss_conf);
		if (rc == -ENOTSUP) {
			memcpy(t->t_rss_key, freebsd_rss_key, sizeof(freebsd_rss_key));
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
