#ifndef CON_GEN__GLOBAL_H
#define CON_GEN__GLOBAL_H

#include "subr.h"
#include "netstat.h"
#include "gbtcp/htable.h"

#define RSS_QUEUE_ID_NONE 255
#define RSS_KEY_SIZE 40

#ifdef HAVE_XDP
struct xdp_queue {
	struct xsk_ring_prod xq_fill;
	struct xsk_ring_cons xq_comp;
	struct xsk_ring_prod xq_tx;
	struct xsk_ring_cons xq_rx;
	int xq_tx_outstanding;
	int xq_fd;
	struct xsk_umem *xq_umem;
	struct xsk_socket *xq_xsk;
};
#endif

struct thread {
	struct spinlock t_lock;
	struct dlist t_pkt_head;
	struct dlist t_pkt_pending_head;
	void (*t_rx_op)(void *, int);
	void (*t_io_init_op)(const char *);
	bool (*t_io_is_tx_throttled_op)();
	void (*t_io_init_tx_packet_op)(struct packet *);
	void (*t_io_deinit_tx_packet_op)(struct packet *);
	bool (*t_io_tx_packet_op)(struct packet *);
	void (*t_io_tx_op)();
	void (*t_io_rx_op)();
	u_char t_id;
	u_char t_toy;
	u_char t_done;
	u_char t_Lflag;
	u_char t_so_debug;
	u_char t_ip_do_incksum;
	u_char t_ip_do_outcksum;
	u_char t_tcp_do_incksum;
	u_char t_tcp_do_outcksum;
	int t_tcp_rttdflt;
	u_char t_tcp_do_wscale;
	u_char t_tcp_do_timestamps;
	u_int t_nflag;
	be16_t t_port;
	u_short t_mtu;
	u_short t_burst_size;
	u_char t_rss_queue_num;
	u_char t_rss_queue_id;
	u_char t_rss_key[RSS_KEY_SIZE];
	struct pollfd t_pfds[256];
	int t_pfd_num;
#ifdef HAVE_NETMAP
	struct nm_desc *t_nmd;
#endif
#ifdef HAVE_PCAP
	pcap_t *t_pcap;
#endif
#ifdef HAVE_XDP
	struct xdp_queue *t_xdp_queues;
	int t_xdp_queue_num;
	uint32_t t_xdp_prog_id;
	uint64_t *t_xdp_frame;
	int t_xdp_frame_free;
	int t_xdp_frame_num;
	void *t_xdp_tx_buf;
	uint32_t t_xdp_tx_idx;
	int t_xdp_tx_queue_idx;
	void *t_xdp_buf;
#endif
	struct ip_socket *t_dst_cache;
	int t_dst_cache_size;
	int t_dst_cache_i;
	struct dlist t_so_pool;
	struct dlist t_so_txq;
	struct dlist t_sob_pool;
	int t_n_conns;
	int t_n_requests;
	int t_concurrency;
	uint64_t t_tsc;
	uint64_t t_time;
	uint32_t t_tcp_now; /* for RFC 1323 timestamps */
	uint64_t t_tcp_nowage;
	uint64_t t_tcp_twtimo;  /* max seg lifetime (hah!) */
	uint64_t t_tcp_fintimo;
	u_char t_eth_laddr[6];
	u_char t_eth_faddr[6];
	uint32_t t_ip_laddr_min;
	uint32_t t_ip_laddr_max;
	uint32_t t_ip_faddr_min;
	uint32_t t_ip_faddr_max;
	uint32_t t_ip_laddr_connect;
	uint32_t t_ip_faddr_connect;
	uint16_t t_ip_lport_connect;
	char *t_http;
	int t_http_len;
	htable_t t_in_htable;
	void *t_in_binded[EPHEMERAL_MIN];
	u_char t_udp;
	u_char t_transport;
	int t_affinity;
	pthread_t t_pthread;
	char t_ifname[IFNAMSIZ];
	uint64_t *t_counters;
};

extern int verbose;
extern int n_counters;

extern counter64_t if_ibytes;
extern counter64_t if_ipackets;
extern counter64_t if_obytes;
extern counter64_t if_opackets;
extern counter64_t if_imcasts;

extern int n_threads;
extern __thread struct thread *current;
extern struct thread threads[N_THREADS_MAX];

extern struct udpstat udpstat;
extern struct tcpstat tcpstat;
extern struct ipstat ipstat;
extern struct icmpstat icmpstat;
extern const char *tcpstates[TCP_NSTATES];

#endif
