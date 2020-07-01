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
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <pthread.h>
#ifndef __linux__
#include <pthread_np.h>
#endif

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "gbtcp/list.h"

typedef uint16_t be16_t;
typedef uint32_t be32_t;

#define N_THREADS_MAX 32

#define EPHEMERAL_MIN 5000
#define EPHEMERAL_MAX 65535
#define NEPHEMERAL (EPHEMERAL_MAX - EPHEMERAL_MIN + 1)

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

#define STRSZ(s) (s), (sizeof(s) - 1)

#define UNUSED(x) ((void)x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define NANOSECONDS_SECOND  1000000000llu
#define NANOSECONDS_MILLISECOND 1000000llu
#define NANOSECONDS_MICROSECOND 1000llu

#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#define powerof2(x)	((((x)-1)&(x))==0)

/* Macros for min/max. */
#define	MIN(a,b) (((a)<(b))?(a):(b))
#define	MAX(a,b) (((a)>(b))?(a):(b))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

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

#define DEV_PREFETCH(ring) \
	MEM_PREFETCH(NETMAP_BUF((ring), \
		((ring)->slot + nm_ring_next(ring, (ring)->cur))->buf_idx))

void dbg5(const char *, u_int, const char *, int, const char *, ...)
	__attribute__((format(printf, 5, 6)));

#define panic(errnum, fmt, ...) \
	panic3(__FILE__, __LINE__, errnum, fmt, ##__VA_ARGS__)

#define dbg(format, ...) \
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

uint16_t in_cksum(void *, int);
#define ip_cksum(ip) in_cksum(ip, (ip)->ip_hl << 2)
uint16_t udp_cksum(struct ip *, int);
#define tcp_cksum udp_cksum


struct socket_info {
	be32_t soi_laddr;
	be32_t soi_faddr;
	be16_t soi_lport;
	be16_t soi_fport;
	int soi_ipproto;
	int soi_state;
	char soi_debug[64];
};

void *xmalloc(size_t);

void panic3(const char *, int, int, const char *, ...)
	__attribute__((format(printf, 4, 5)));

#define SO_HASH(faddr, lport, fport) \
	((faddr) ^ ((faddr) >> 16) ^ ntohs((lport) ^ (fport)))

struct netmap_ring *not_empty_txr(struct netmap_slot **);
void ether_output(struct netmap_ring *, struct netmap_slot *);

int parse_http(const char *, int, u_char *);

typedef int counter64_t;

void counter64_init(counter64_t *);
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
uint64_t counter64_get(counter64_t *);

struct if_addr {
	struct dlist *ifa_ports;
	struct dlist ifa_port_head;
};

void ifaddr_init(struct if_addr *);
uint16_t ifaddr_alloc_ephemeral_port(struct if_addr *);
void ifaddr_free_ephemeral_port(struct if_addr *, uint16_t);
int alloc_ephemeral_port(uint32_t *, uint16_t *);
void free_ephemeral_port(uint32_t, uint16_t);

uint32_t select_faddr();

#endif // CON_GEN__SUBR_H
