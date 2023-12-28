// SPDX-License-Identifier: BSD-4-Clause

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "if_ether.h"
#include "netstat.h"

static __thread uint16_t ip_id;	// ip packet ctr, for ids

int
ip_output(struct packet *pkt, struct ip *ip)
{
	int rc;
	struct ether_header *eh;

	pkt->pkt.len = sizeof(struct ether_header) + ip->ip_len;
	
	// Fill in IP header.
	ip->ip_v = IPVERSION;
	ip->ip_off = IP_DF;
	ip->ip_id = htons(ip_id++);
	ip->ip_ttl = IPDEFTTL;
	ip->ip_tos = 0;
	ip->ip_hl = sizeof(*ip) >> 2;
	counter64_inc(&ipstat.ips_localout);
	assert((u_short)ip->ip_len <= current->t_mtu);
	ip->ip_len = htons((u_short)ip->ip_len);
	ip->ip_off = htons((u_short)ip->ip_off);
	ip->ip_sum = 0;
	if (current->t_ip_do_outcksum) {
		ip->ip_sum = ip_cksum(ip);
	}
	eh = ((struct ether_header *)ip) - 1;
	eh->ether_type = htons(ETHERTYPE_IP);
 	memcpy(eh->ether_shost, current->t_eth_laddr, sizeof(eh->ether_shost));
 	memcpy(eh->ether_dhost, current->t_eth_faddr, sizeof(eh->ether_dhost));

	rc = io_tx_packet(pkt);

	return rc;
}
