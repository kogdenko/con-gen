#ifndef CON_GEN__SUBR_H
#define CON_GEN__SUBR_H

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <emmintrin.h>
#ifdef __linux__
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/epoll.h>
#else // __linux__
#include <pthread_np.h>
#endif // __linux__

#ifdef HAVE_DPDK
#include <rte_ring.h>

struct rte_mbuf;

#define DPDK_MAX_PKT_BURST 256
#endif

#include "list.h"
#include "htable.h"

#define CG_TX_PENDING_MAX 2048

#define EPHEMERAL_MIN 5000
#define EPHEMERAL_MAX 65535
#define NEPHEMERAL (EPHEMERAL_MAX - EPHEMERAL_MIN + 1)

#define RSS_QUEUE_ID_MAX 128
#define RSS_KEY_SIZE 40

#define	TCP_NSTATES	11

#define	TCPS_CLOSED		0	/* closed */
#define	TCPS_LISTEN		1	/* listening for connection */
#define	TCPS_SYN_SENT		2	/* active, have sent syn */
#define	TCPS_SYN_RECEIVED	3	/* have send and received syn */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define	TCPS_ESTABLISHED	4	/* established */
#define	TCPS_CLOSE_WAIT		5	/* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define	TCPS_FIN_WAIT_1		6	/* have closed, sent fin */
#define	TCPS_CLOSING		7	/* closed xchd FIN; await FIN ACK */
#define	TCPS_LAST_ACK		8	/* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define	TCPS_FIN_WAIT_2		9	/* have closed, fin is acked */
#define	TCPS_TIME_WAIT		10	/* in 2*msl quiet wait after close */

#define NANOSECONDS_SECOND  1000000000llu
#define NANOSECONDS_MILLISECOND 1000000llu
#define NANOSECONDS_MICROSECOND 1000llu

#define TRANSPORT_NETMAP 0
#define TRANSPORT_XDP 1
#define TRANSPORT_PCAP 2
#define TRANSPORT_DPDK 3

#ifdef HAVE_NETMAP
#define TRANSPORT_DEFAULT TRANSPORT_NETMAP
#elif defined HAVE_XDP
#define TRANSPORT_DEFAULT TRANSPORT_XDP
#elif defined HAVE_DPDK
#define TRANSPORT_DEFAULT TRANSPORT_DPDK
#else
#define TRANSPORT_DEFAULT TRANSPORT_PCAP
#endif

// Macros
#define STRSZ(s) (s), (sizeof(s) - 1)

#define UNUSED(x) ((void)x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#define powerof2(x)	((((x)-1)&(x))==0)

/* Macros for min/max. */
#define	MIN(a,b) (((a)<(b))?(a):(b))
#define	MAX(a,b) (((a)>(b))?(a):(b))

#define CAT_RES(_, res) res
#define CAT3_MED(x, y, z) CAT_RES(~, x##y##z)
#define CAT3(x, y, z) CAT3_MED(x, y, z)
#define UNIQV(name) CAT3(name, uniqv_, __LINE__)

#define HTONS(x) ((x) = htons((short)(x)))
#define NTOHS(x) ((x) = ntohs((short)(x)))
#define NTOHL(x) ((x) = ntohl((long)(x)))
#define HTONL(x) ((x) = htonl((long)(x)))

#define MEM_PREFETCH(ptr) \
	__builtin_prefetch(ptr)


#if 1
#define cg_counter64_add(t, c, a) \
do { \
	assert(*(c)); \
	t->t_counters[*(c)] += (a); \
} while (0)
#else // 1
#define cg_counter64_add(t, c, a)
#endif // 1
#define cg_counter64_inc(t, c) cg_counter64_add(t, c, 1)
#define cg_counter64_dec(t, c) cg_counter64_add(t, c, -1)

#define panic(errnum, fmt, ...) \
	panic3(__FILE__, __LINE__, errnum, fmt, ##__VA_ARGS__)

#define dbg(fmt, ...) \
	dbg5(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__)

#define dbg_rl(t, period, fmt, ...) \
do { \
	static uint64_t UNIQV(last); \
	static uint64_t UNIQV(now); \
	static int UNIQV(cnt); \
 \
	UNIQV(now) = (t)->t_time; \
	if (UNIQV(now) - UNIQV(last) >= (period) * NANOSECONDS_SECOND) { \
		UNIQV(last) = UNIQV(now); \
		dbg5(__FILE__, __LINE__, __func__, UNIQV(cnt), \
		     fmt, ##__VA_ARGS__); \
	} else { \
		UNIQV(cnt)++; \
	} \
} while (0)

#define ip_cksum(ip) in_cksum(ip, (ip)->ip_hl << 2)
#define tcp_cksum udp_cksum

#define SO_HASH(faddr, lport, fport) \
	((faddr) ^ ((faddr) >> 16) ^ ntohs((lport) ^ (fport)))

// Type
typedef uint16_t be16_t;
typedef uint32_t be32_t;


#ifdef HAVE_NETMAP
struct nm_desc;
struct netmap_ring;
struct netmap_slot;
#endif
#ifdef HAVE_XDP
struct xdp_queue;
#endif

struct spinlock {
	volatile int spinlock_locked;
};

typedef int counter64_t;

void counter64_init(counter64_t *);
uint64_t counter64_get(counter64_t *);

struct socket_info {
	be32_t soi_laddr;
	be32_t soi_faddr;
	be16_t soi_lport;
	be16_t soi_fport;
	int soi_ipproto;
	int soi_state;
	int soi_idle;
	char soi_debug[64];
};

struct if_addr {
	struct dlist *ifa_ports;
	struct dlist ifa_port_head;
};

struct ip_socket {
	struct dlist ipso_list;
	union {
		struct ip_socket *ipso_cache;
		uint32_t ipso_hash;
	};
	be32_t ipso_laddr;
	be32_t ipso_faddr;
	be16_t ipso_lport;
	be16_t ipso_fport;
};

struct packet {
	struct packet_header {
		struct dlist list;
		u_char *buf;
		int len;
		union {
#ifdef HAVE_NETMAP
			struct {
				struct netmap_ring *txr;
				struct netmap_slot *slot;
			};
#endif
#ifdef HAVE_XDP
			struct {
				uint32_t idx;
				int queue_idx;
			};
#endif
#ifdef HAVE_DPDK
			struct rte_mbuf *mbuf;
#endif
		};
	} pkt;
	u_char pkt_body[2048 - sizeof(struct packet_header)];
};

struct cg_timer_ring;

struct cg_task {
	struct spinlock t_lock;
	
	struct dlist list;
	volatile int t_done;

	struct dlist t_available_head;
	struct dlist t_pending_head;
	unsigned t_n_pending;

	int t_n_timer_rings;
	struct cg_timer_ring *t_timer_rings;
	uint64_t t_timers_last_time;

	u_char t_busyloop;
	u_short t_mtu;
	u_char t_rss_queue_num;
	u_char t_rss_queue_id;
	u_char *t_rss_key;
	int t_rss_key_size;
	struct pollfd t_pfds[256];
	int t_pfd_num;
	union {
#ifdef HAVE_NETMAP
		struct {
			struct nm_desc *t_nmd;
		};
#endif
#ifdef HAVE_PCAP
		struct {
			void *t_pcap;
		};
#endif
#ifdef HAVE_XDP
		struct {
			struct xdp_queue *t_xdp_queues;
			int t_xdp_queue_num;
			uint32_t t_xdp_prog_id;
		};
#endif
#ifdef HAVE_DPDK
		struct {
			uint16_t t_dpdk_port_id;
			int t_dpdk_tx_bufsiz;
			struct rte_mbuf *t_dpdk_tx_buf[DPDK_MAX_PKT_BURST];
		};
#endif
	};
	struct ip_socket *t_dst_cache;
	int t_dst_cache_size;
	int t_dst_cache_i;
	int t_n_conns;
	int t_concurrency;
	uint64_t t_tsc;
	uint64_t t_time;
	u_char t_eth_laddr[6];
	u_char t_eth_faddr[6];
	uint32_t t_ip_laddr_min;
	uint32_t t_ip_laddr_max;
	uint32_t t_ip_faddr_min;
	uint32_t t_ip_faddr_max;
	uint32_t t_ip_laddr_connect;
	uint32_t t_ip_faddr_connect;
	uint16_t t_ip_lport_connect;
	htable_t t_in_htable;
	void *t_in_binded[EPHEMERAL_MIN];
	int t_affinity;
	pthread_t t_pthread;
	char t_ifname[IFNAMSIZ];
	uint64_t *t_counters;

	// BSD44
	be16_t t_port;
	u_char t_so_debug;
	int t_tcp_rttdflt;
	u_char t_Lflag;
	u_char t_tcp_do_wscale;
	u_char t_tcp_do_timestamps;
	u_int t_nflag;
	int t_n_requests;
	struct dlist t_so_pool;
	struct dlist t_so_txq;
	struct dlist t_sob_pool;
	uint32_t t_tcp_now; // for RFC 1323 timestamps
	uint64_t t_tcp_nowage;
	uint64_t t_tcp_twtimo;  // max seg lifetime (hah!)
	uint64_t t_tcp_fintimo;
	char *t_http;
	int t_http_len;
};

struct transport_ops {
	void (*tr_io_process_op)(struct cg_task *, void *, int);
	void (*tr_io_init_op)(void);
	bool (*tr_io_is_tx_throttled_op)(struct cg_task *);
	void (*tr_io_init_tx_packet_op)(struct cg_task *, struct packet *);
	void (*tr_io_deinit_tx_packet_op)(struct packet *);
	bool (*tr_io_tx_packet_op)(struct cg_task *, struct packet *);
	void (*tr_io_tx_op)(void);
	int (*tr_io_rx_op)(struct cg_task *, int);
};

extern uint8_t freebsd_rss_key[RSS_KEY_SIZE];

// Function
void dbg5(const char *, u_int, const char *, int, const char *, ...)
	__attribute__((format(printf, 5, 6)));

void print_hexdump_ascii(const void *, int);

int ffs64(uint64_t x);


void *xmalloc(size_t);

void panic3(const char *, int, int, const char *, ...)
	__attribute__((format(printf, 4, 5)));

char *strzcpy(char *, const char *, size_t);

int read_rss_key(const char *ifname, u_char **rss_key);

uint32_t toeplitz_hash(const u_char *, int, const u_char *, int);
uint32_t rss_hash4(be32_t, be32_t, be16_t, be16_t, u_char *, int);

uint16_t in_cksum(void *, int);
uint16_t udp_cksum(struct ip *, int);

int parse_http(const char *, int, u_char *);

void spinlock_init(struct spinlock *);
void spinlock_lock(struct spinlock *);
int spinlock_trylock(struct spinlock *);
void spinlock_unlock(struct spinlock *);

void set_transport(int transport);

void add_pending_packet(struct cg_task *, struct packet *);

void io_init(void);
bool io_is_tx_throttled(struct cg_task *);
void io_init_tx_packet(struct cg_task *, struct packet *);
void io_deinit_tx_packet(struct packet *);
int io_tx_packet(struct cg_task *, struct packet *);
void io_tx(void);
int io_rx(struct cg_task *, int);
void io_process(struct cg_task *, void *pkt, int pkt_len);

int multiplexer_add(struct cg_task *, int);
void multiplexer_pollout(struct cg_task *, int);
int multiplexer_get_events(struct cg_task *, int);

int ip_connect(struct cg_task *, struct ip_socket *, uint32_t *);
void ip_disconnect(struct cg_task *, struct ip_socket *);

void ifaddr_init(struct if_addr *);
uint16_t ifaddr_alloc_ephemeral_port(struct if_addr *);
void ifaddr_free_ephemeral_port(struct if_addr *, uint16_t);

int alloc_ephemeral_port(uint32_t *, uint16_t *);
void free_ephemeral_port(uint32_t, uint16_t);

extern int verbose;
extern int n_counters;

extern counter64_t if_ibytes;
extern counter64_t if_ipackets;
extern counter64_t if_obytes;
extern counter64_t if_opackets;
extern counter64_t if_imcasts;

extern struct dlist g_cg_task_head;

#define CG_TASK_FOREACH(t) \
	DLIST_FOREACH(t, &g_cg_task_head, list)


#endif // CON_GEN__SUBR_H
