/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#ifndef BSD44_IP_VAR_H
#define BSD44_IP_VAR_H

#include "types.h"

struct	ipstat {
	uint64_t ips_total;             /* total packets received */
	uint64_t ips_badsum;            /* checksum bad */
	uint64_t ips_tooshort;          /* packet too short */
	uint64_t ips_toosmall;          /* not enough data */
	uint64_t ips_badhlen;           /* ip header length < data size */
	uint64_t ips_badlen;            /* ip length < ip header length */
	uint64_t ips_fragments;         /* fragments received */
	uint64_t ips_fragdropped;       /* frags dropped (dups, out of space) */
	uint64_t ips_fragtimeout;       /* fragments timed out */
	uint64_t ips_forward;           /* packets forwarded */
	uint64_t ips_cantforward;       /* packets rcvd for unreachable dest */
	uint64_t ips_redirectsent;      /* packets forwarded on same net */
	uint64_t ips_noproto;           /* unknown or unsupported protocol */
	uint64_t ips_delivered;         /* datagrams delivered to upper level*/
	uint64_t ips_localout;          /* total ip packets generated here */
	uint64_t ips_odropped;          /* lost packets due to nobufs, etc. */
	uint64_t ips_reassembled;       /* total packets reassembled ok */
	uint64_t ips_fragmented;        /* datagrams sucessfully fragmented */
	uint64_t ips_ofragments;        /* output fragments created */
	uint64_t ips_cantfrag;          /* don't fragment flag was set, etc. */
	uint64_t ips_badoptions;        /* error in option processing */
	uint64_t ips_noroute;           /* packets discarded due to no route */
	uint64_t ips_badvers;           /* ip version != 4 */
	uint64_t ips_rawout;            /* total raw ip packets generated */
};

struct ip;
struct	ipstat	ipstat;
u_short	ip_id;				/* ip packet ctr, for ids */

void	 ip_drain(void);
void	 ip_init(void);
void	 ip_output(struct netmap_ring *txr, struct netmap_slot *m, struct ip *);
void	 ip_input(struct ip *ip, int, int);

#endif
