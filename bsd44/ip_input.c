/*
 * Copyright (c) 1982, 1986, 1988, 1993
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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp_var.h"
#include "udp_var.h"
#include "ip_icmp.h"

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init()
{
	ip_id = (nanosec & 0xffff);
}

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct ip *ip, int len, int eth_flags)
{
	uint16_t ip_sum;
	uint32_t ia;
	int hlen;

	ipstat.ips_total++;
	if (len < sizeof(struct ip)) {
		ipstat.ips_toosmall++;
		return;
	}
	if (ip->ip_v != IPVERSION) {
		ipstat.ips_badvers++;
		return;
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) {	/* minimum header length */
		ipstat.ips_badhlen++;
		return;
	}
	if (hlen > len) {
		ipstat.ips_badhlen++;
		return;
	}
	ip_sum = ip->ip_sum;
	ip->ip_sum = 0;
	ip->ip_sum = ip_cksum(ip);
	if (ip->ip_sum != ip_sum) {
		ipstat.ips_badsum++;
		return;
	}

	/*
	 * Convert fields to host representation.
	 */
	NTOHS(ip->ip_len);
	if (ip->ip_len < hlen) {
		ipstat.ips_badlen++;
		return;
	}
	NTOHS(ip->ip_id);
	NTOHS(ip->ip_off);

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IP header would have us expect.
	 * Drop packet if shorter than we expect.
	 */
	if (len < ip->ip_len) {
		ipstat.ips_tooshort++;
		return;
	}

	/*
	 * Check our list of addresses, to see if the packet is for us.
	 */
	for (ia = ip_laddr_min; ia <= ip_laddr_max; ++ia) {
		if (ia == ntohl(ip->ip_dst.s_addr)) {
			goto ours;
		}
	}

	/*
	 * Not for us.
	 */
	icmp_error(ip, ICMP_UNREACH, ICMP_UNREACH_NET, 0);
	return;

ours:
	if (ip->ip_off &~ IP_DF) {
		ipstat.ips_fragments++;
		return;
	}
	ip->ip_len -= hlen;
	ipstat.ips_delivered++;
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		tcp_input(ip, hlen, eth_flags);
		break;
	case IPPROTO_UDP:
		udp_input(ip, hlen, eth_flags);
		break;
	case IPPROTO_ICMP:
		icmp_input(ip, hlen);
		break;
	default:
		break;
	}
}
