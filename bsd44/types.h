/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef BSD44_TYPES_H
#define	BSD44_TYPES_H

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
//#include <sys/ioctl.h>
//#include <sys/stat.h>
//#include <net/if.h>*/


#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>


typedef uint16_t be16_t;
typedef uint32_t be32_t;

#define STRSZ(s) (s), (sizeof(s) - 1)


#define UNUSED(x) ((void)x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define	M_BCAST		0x0100	/* send/received as link-level broadcast */
#define	M_MCAST		0x0200	/* send/received as link-level multicast */

struct netmap_ring *not_empty_txr(struct netmap_slot **pslot);

uint32_t murmur(const void * key, u_int len, uint32_t initval);

#define field_off(type, field) ((intptr_t)&((type *)0)->field)
#define container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - field_off(type, field)))

#define NANOSECONDS_SECOND  1000000000llu
#define NANOSECONDS_MILLISECOND 1000000llu
#define NANOSECONDS_MICROSECOND 1000llu

uint16_t in_cksum(void *data, int len);
#define ip_cksum(ip) in_cksum(ip, (ip)->ip_hl << 2)
uint16_t udp_cksum(struct ip *ip, int);
#define tcp_cksum udp_cksum

#define	PRU_DETACH		1	/* detach protocol from up */
#define	PRU_BIND		2	/* bind socket to address */
#define	PRU_LISTEN		3	/* listen for connection */
#define	PRU_CONNECT		4	/* establish connection to peer */
#define	PRU_ACCEPT		5	/* accept connection from peer */
#define	PRU_DISCONNECT		6	/* disconnect from peer */
#define	PRU_SHUTDOWN		7	/* won't send any more data */
#define	PRU_SEND		9	/* send this data */
#define	PRU_ABORT		10	/* abort (fast DISCONNECT, DETATCH) */
/* begin for protocols internal use */
#define	PRU_FASTTIMO		18	/* 200ms timeout */
#define	PRU_SLOWTIMO		19	/* 500ms timeout */

#define	PRU_NREQ		21


#define	PRCO_GETOPT	0
#define	PRCO_SETOPT	1


#define PR_SLOWHZ       2               /* 2 slow timeouts per second */
#define PR_FASTHZ       5               /* 5 fast timeouts per second */
 
/*
 * Values for pr_flags.
 * PR_ADDR requires PR_ATOMIC;
 * PR_ADDR and PR_CONNREQUIRED are mutually exclusive.
 */
#define PR_ATOMIC       0x01            /* exchange atomic messages only */
#define PR_ADDR         0x02            /* addresses given with messages */
#define PR_CONNREQUIRED 0x04            /* connection required by protocol */
#define PR_WANTRCVD     0x08            /* want PRU_RCVD calls */
#define PR_RIGHTS       0x10            /* passes capabilities */


#define panic(...) panic3(__FILE__, __LINE__, __VA_ARGS__)
#define dbg0 printf("D %-30s %-4d %-20s ", __FILE__, __LINE__, __func__)
#define dbg(format, ...) \
do { \
	dbg0; \
	printf(format, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

void panic3(const char *, int,  const char *format, ...)
	__attribute__((format(printf, 3, 4)));


#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#define powerof2(x)	((((x)-1)&(x))==0)

/* Macros for min/max. */
#define	MIN(a,b) (((a)<(b))?(a):(b))
#define	MAX(a,b) (((a)>(b))?(a):(b))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define HTONS(x) ((x) = htons((short)(x)))
#define NTOHS(x) ((x) = ntohs((short)(x)))
#define NTOHL(x) ((x) = ntohl((long)(x)))
#define HTONL(x) ((x) = htonl((long)(x)))

extern u_char eth_laddr[6];
extern u_char eth_faddr[6]; 
extern uint32_t ip_laddr_min;
extern uint32_t ip_laddr_max;
extern int if_mtu;
extern uint64_t if_ibytes;
extern uint64_t if_ipackets;
extern uint64_t if_obytes;
extern uint64_t if_opackets;
extern uint64_t if_imcasts;
extern u_char etherbroadcastaddr[6];
extern uint64_t nanosec;

#endif /* BSD44_TYPES_H */
