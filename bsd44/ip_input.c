// SPDX-License-Identifier: BSD-4-Clause

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp_var.h"
#include "udp_var.h"
#include "ip_icmp.h"
#include "../netstat.h"

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct cg_task *t, struct ip *ip, int len, int eth_flags)
{
	uint16_t ip_sum;
	uint32_t ia;
	int hlen;

	cg_counter64_inc(t, &ipstat.ips_total);
	if (len < sizeof(struct ip)) {
		cg_counter64_inc(t, &ipstat.ips_toosmall);
		return;
	}
	if (ip->ip_v != IPVERSION) {
		cg_counter64_inc(t, &ipstat.ips_badvers);
		return;
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) {	/* minimum header length */
		cg_counter64_inc(t, &ipstat.ips_badhlen);
		return;
	}
	if (hlen > len) {
		cg_counter64_inc(t, &ipstat.ips_badhlen);
		return;
	}
	ip_sum = ip->ip_sum;
	if (ip_sum == 0) {
		ip_sum = 0xffff;
	}
	ip->ip_sum = 0;
	if (t->t_ip_do_incksum) {
		ip->ip_sum = ip_cksum(ip);
		if (ip->ip_sum != ip_sum) {
			cg_counter64_inc(t, &ipstat.ips_badsum);
			if (t->t_ip_do_incksum) {
				return;
			}
		}
	}

	/*
	 * Convert fields to host representation.
	 */
	NTOHS(ip->ip_len);
	if (ip->ip_len < hlen) {
		cg_counter64_inc(t, &ipstat.ips_badlen);
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
		cg_counter64_inc(t, &ipstat.ips_tooshort);
		return;
	}

	// Check our list of addresses, to see if the packet is for us.
	for (ia = t->t_ip_laddr_min; ia <= t->t_ip_laddr_max; ++ia) {
		if (ia == ntohl(ip->ip_dst.s_addr)) {
			goto ours;
		}
	}

	// Not for us.
	icmp_error(t, ip, ICMP_UNREACH, ICMP_UNREACH_NET, 0);
	return;

ours:
	if (ip->ip_off &~ IP_DF) {
		cg_counter64_inc(t, &ipstat.ips_fragments);
		return;
	}
	ip->ip_len -= hlen;
	cg_counter64_inc(t, &ipstat.ips_delivered);
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		tcp_input(t, ip, hlen, eth_flags);
		break;
	case IPPROTO_ICMP:
		icmp_input(t, ip, hlen);
		break;
	default:
		break;
	}
}
