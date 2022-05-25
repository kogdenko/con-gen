#ifndef CON_GEN__SUBR_H
#define CON_GEN__SUBR_H

#define _GNU_SOURCE
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

#ifdef HAVE_NETMAP
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

#ifdef HAVE_XDP
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#endif

#include "gbtcp/list.h"
#include "gbtcp/htable.h"

// Define
#define N_THREADS_MAX 32

#define EPHEMERAL_MIN 5000
#define EPHEMERAL_MAX 65535
#define NEPHEMERAL (EPHEMERAL_MAX - EPHEMERAL_MIN + 1)

#define RSS_QUEUE_ID_NONE 255
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

#if 0
#define DEV_PREFETCH(ring)
#else
#define DEV_PREFETCH(ring) \
	MEM_PREFETCH(NETMAP_BUF((ring), \
		((ring)->slot + nm_ring_next(ring, (ring)->cur))->buf_idx))
#endif

#if 1
#define counter64_add(c, a) \
do { \
	assert(*(c)); \
	current->t_counters[*(c)] += (a); \
} while (0)
#else // 1
#define counter64_add(c, a)
#endif // 1
#define counter64_inc(c) counter64_add(c, 1)
#define counter64_dec(c) counter64_add(c, -1)

#define panic(errnum, fmt, ...) \
	panic3(__FILE__, __LINE__, errnum, fmt, ##__VA_ARGS__)

#define dbg(fmt, ...) \
	dbg5(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__)

#define dbg_rl(period, fmt, ...) \
do { \
	static uint64_t UNIQV(last); \
	static uint64_t UNIQV(now); \
	static int UNIQV(cnt); \
 \
	UNIQV(now) = current->t_time; \
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

typedef int counter64_t;

enum {
#ifdef HAVE_NETMAP
	TRANSPORT_NETMAP,
#endif
#ifdef HAVE_PCAP
	TRANSPORT_PCAP,
#endif
#ifdef HAVE_XDP
	TRANSPORT_XDP,
#endif
};

struct spinlock {
	volatile int spinlock_locked;
};

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
		};
	} pkt;
	u_char pkt_body[2048 - sizeof(struct packet_header)];
};

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

// Function
void dbg5(const char *, u_int, const char *, int, const char *, ...)
	__attribute__((format(printf, 5, 6)));

void *xmalloc(size_t);

void panic3(const char *, int, int, const char *, ...)
	__attribute__((format(printf, 4, 5)));

char *strzcpy(char *, const char *, size_t);
uint32_t toeplitz_hash(const u_char *, int, const u_char *);
uint32_t rss_hash4(be32_t, be32_t, be16_t, be16_t, u_char *);

uint16_t in_cksum(void *, int);
uint16_t udp_cksum(struct ip *, int);

int parse_http(const char *, int, u_char *);

void spinlock_init(struct spinlock *);
void spinlock_lock(struct spinlock *);
int spinlock_trylock(struct spinlock *);
void spinlock_unlock(struct spinlock *);

void counter64_init(counter64_t *);
uint64_t counter64_get(counter64_t *);

struct thread;
void set_transport(struct thread *, int);

void io_init(const char *);
bool io_is_tx_throttled();
void io_init_tx_packet(struct packet *);
void io_deinit_tx_packet(struct packet *);
bool io_tx_packet(struct packet *);
void io_tx();
void io_rx();

int multiplexer_add(int);
void multiplexer_pollout(int);
int multiplexer_get_events(int);

int ip_connect(struct ip_socket *, uint32_t *);
void ip_disconnect(struct ip_socket *);

void ifaddr_init(struct if_addr *);
uint16_t ifaddr_alloc_ephemeral_port(struct if_addr *);
void ifaddr_free_ephemeral_port(struct if_addr *, uint16_t);

int alloc_ephemeral_port(uint32_t *, uint16_t *);
void free_ephemeral_port(uint32_t, uint16_t);

uint32_t select_faddr();

#endif // CON_GEN__SUBR_H
