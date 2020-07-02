#ifndef CON_GEN__GLOBAL_H
#define CON_GEN__GLOBAL_H

#include "subr.h"
#include "netstat.h"
#include "gbtcp/htable.h"

#define RSS_QID_NONE 255
#define RSS_KEY_SIZE 40

struct thread {
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
	u_char t_tx_throttled;
	u_char t_n_rss_q;
	u_char t_rss_qid;
	u_char t_rss_key[RSS_KEY_SIZE];
	struct nm_desc *t_nmd;
	struct dlist t_dst_cache;
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
	int t_affinity;
	int t_dst_cache_size;
	pthread_t t_pthread;
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
