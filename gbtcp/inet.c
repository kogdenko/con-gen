#include "../global.h"
#include "../netstat.h"
#include "inet.h"

#define SHIFT(p, size) \
	do { \
		p->inp_cur += size; \
		p->inp_rem -= size; \
	} while (0)

void
inet_parser_init(struct inet_parser *p, void *data, int len)
{
	p->inp_cur = data;
	p->inp_rem = len;
	p->inp_errnum = 0;
	p->inp_ipproto = 0;
	p->inp_emb_ipproto = 0;
}

void
arp_reply(struct arp_hdr *ah)
{
	struct eth_hdr *eh_rpl;
	struct arp_hdr *ah_rpl;
	struct netmap_ring *txr;
	struct netmap_slot *m;

	txr = not_empty_txr(&m);
	if (txr == NULL) {
		//arps.arps_txrepliesdropped++;
		return;
	}
	m->len = sizeof(struct eth_hdr) + sizeof(struct arp_hdr);
	eh_rpl = (struct eth_hdr *)NETMAP_BUF(txr, m->buf_idx);
	ah_rpl = (struct arp_hdr *)(eh_rpl + 1);
	eh_rpl->eh_type = ETH_TYPE_ARP_BE;
	memcpy(eh_rpl->eh_saddr, eth_laddr, 6);
	memcpy(eh_rpl->eh_daddr, ah->ah_data.aip_sha, 6);
	ah_rpl->ah_hrd = ARP_HRD_ETH_BE;
	ah_rpl->ah_pro = ETH_TYPE_IP4_BE;
	ah_rpl->ah_hlen = 6;
	ah_rpl->ah_plen = sizeof(be32_t);
	ah_rpl->ah_op = ARP_OP_REPLY_BE;
	memcpy(&ah_rpl->ah_data.aip_sha, eth_laddr, 6);
	ah_rpl->ah_data.aip_sip = ah->ah_data.aip_tip;
	memcpy(&ah_rpl->ah_data.aip_tha, ah->ah_data.aip_sha, 6);
	ah_rpl->ah_data.aip_tip = ah->ah_data.aip_sip;
	//arps.arps_txreplies++;
	ether_output(txr, m);
}

static int
arp_in(struct inet_parser *p)
{
//	int i, is_req;
	//be32_t sip/*, tip*/;
//	struct route_if_addr *ifa;
//	struct arp_advert_msg msg;

	//arps.arps_received++;
	if (p->inp_rem < sizeof(struct arp_hdr)) {
		//arps->arps_toosmall++;
		return IN_DROP;
	}
	p->inp_ah = (struct arp_hdr *)p->inp_cur;
	SHIFT(p, sizeof(struct arp_hdr));
	if (p->inp_ah->ah_hrd != ARP_HRD_ETH_BE) {
		//arps->arps_badhrd++;
		return IN_DROP;
	}
	if (p->inp_ah->ah_pro != ETH_TYPE_IP4_BE) {
		//arps->arps_badpro++;
		return IN_DROP;
	}
	//tip = p->inp_ah->ah_data.aip_tip;
	//sip = p->inp_ah->ah_data.aip_sip;
	//ifa = route_ifaddr_get4(tip);
	//if (ifa == NULL) {
	//	//arps->arps_bypassed++;
	//	return IN_BYPASS;
	//}
	if (p->inp_ah->ah_hlen != 6) {
		//arps->arps_badhlen++;
		return IN_DROP;
	}
	if (p->inp_ah->ah_plen != sizeof(be32_t)) {
		//arps->arps_badplen++;
		return IN_DROP;
	}
	//if (ipaddr4_is_loopback(tip)) {
	//	p->inp_arps->arps_badaddr++;
	//	return IN_DROP;
	//}
	//if (ipaddr4_is_bcast(tip)) {
	//	p->inp_arps->arps_badaddr++;
	//	return IN_DROP;
	//}
	//if (ipaddr4_is_loopback(sip)) {
	//	p->inp_arps->arps_badaddr++;
	//	return IN_DROP;
	//}
	//if (ipaddr4_is_bcast(sip)) {
	//	p->inp_arps->arps_badaddr++;
	//	return IN_DROP;
	//}
	// IP4 duplicate address detection
	//if (sip == 0) {
	//	// TODO: reply
	//	return IN_OK;
	//}
	if (p->inp_ah->ah_op == ARP_OP_REQUEST_BE) {
		//arps.arps_rxrequests++;
		//is_req = 1;
		arp_reply(p->inp_ah);
	}
	return IN_OK;
}

static int
tcp_in(struct inet_parser *p)
{
	int len, win, tmp, cksum;

	if (p->inp_rem < sizeof(struct tcp_hdr)) {
		tcpstat.tcps_rcvshort++;
		return IN_DROP;
	}
	p->inp_th = (struct tcp_hdr *)p->inp_cur;
	p->inp_th_len = TCP_HDR_LEN(p->inp_th->th_data_off);
	if (p->inp_rem < p->inp_th_len) {
		tcpstat.tcps_rcvshort++;
		return IN_DROP;
	}
	SHIFT(p, p->inp_th_len);
	win = ntohs(p->inp_th->th_win_size);
	len = p->inp_ip_payload_len - p->inp_th_len;
	p->inp_tcb.tcb_win = win;
	p->inp_tcb.tcb_len = len;
	p->inp_tcb.tcb_flags = p->inp_th->th_flags;
	p->inp_tcb.tcb_seq = ntohl(p->inp_th->th_seq);
	p->inp_tcb.tcb_ack = ntohl(p->inp_th->th_ack);
	p->inp_payload = (u_char *)p->inp_th + p->inp_th_len;
	cksum = p->inp_th->th_cksum;
	p->inp_th->th_cksum = 0;
	if (tcp_do_incksum) {
		tmp = tcp_cksum((struct ip *)p->inp_ih, p->inp_ip_payload_len);
		if (cksum != tmp) {
			tcpstat.tcps_rcvbadsum++;
			return IN_DROP;
		}
	}
	p->inp_th->th_cksum = cksum;
	if (p->inp_th_len > sizeof(*p->inp_th)) {
		tcpstat.tcps_rcvbadoff++;
		return IN_DROP;
	}
	return IN_OK;
}

static int
icmp4_in(struct inet_parser *p)
{
	int ih_len, type, code;

	if (p->inp_rem < sizeof(struct icmp4_hdr)) {
		icmpstat.icps_tooshort++;
		return IN_DROP;
	}
	p->inp_icp = (struct icmp4_hdr *)p->inp_cur;
	SHIFT(p, sizeof(struct icmp4_hdr));
	type = p->inp_icp->icmp_type;
	code = p->inp_icp->icmp_code;	
	if (type > ICMP_MAXTYPE) {
		return IN_DROP;
	}
	icmpstat.icps_inhist[type]++;
	switch (type) {
	case ICMP_UNREACH:
		switch (code) {
		case ICMP_UNREACH_NET:
		case ICMP_UNREACH_HOST:
		case ICMP_UNREACH_PROTOCOL:
		case ICMP_UNREACH_PORT:
		case ICMP_UNREACH_SRCFAIL:
		case ICMP_UNREACH_NET_UNKNOWN:
		case ICMP_UNREACH_NET_PROHIB:
		case ICMP_UNREACH_TOSNET:
		case ICMP_UNREACH_HOST_UNKNOWN:
		case ICMP_UNREACH_ISOLATED:
		case ICMP_UNREACH_HOST_PROHIB:
		case ICMP_UNREACH_TOSHOST:
			p->inp_errnum = EHOSTUNREACH;
			break;
		case ICMP_UNREACH_NEEDFRAG:
			p->inp_errnum = EMSGSIZE;
			break;
		default:
			icmpstat.icps_badcode++;
			return IN_DROP;
		}
		break;
	case ICMP_TIMXCEED:
		if (code > 1) {
			icmpstat.icps_badcode++;
			return IN_DROP;
		}
		// TODO:
		break;
	case ICMP_PARAMPROB:
		if (code > 1) {
			icmpstat.icps_badcode++;
			return IN_DROP;
		}
		p->inp_errnum = ENOPROTOOPT;
		break;
	case ICMP_SOURCEQUENCH:
		if (code) {
			icmpstat.icps_badcode++;
			return IN_DROP;
		}
		// TODO:
		break;
	case ICMP_REDIRECT:
		if (code > 3) {
			icmpstat.icps_badcode++;
			return IN_DROP;
		}
		// TODO:
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
	p->inp_emb_ih = NULL;
	p->inp_emb_th = NULL;
	if (p->inp_rem < sizeof(*p->inp_emb_ih)) {
		icmpstat.icps_badlen++;
		return IN_DROP;
	}
	p->inp_emb_ih = (struct ip4_hdr *)p->inp_cur;
	ih_len = IP4_HDR_LEN(p->inp_emb_ih->ih_ver_ihl);
	if (ih_len < sizeof(*p->inp_emb_ih)) {
		icmpstat.icps_badlen++;
		return IN_DROP;
	}
	SHIFT(p, ih_len);
	p->inp_emb_ipproto = p->inp_emb_ih->ih_proto;
	switch (p->inp_emb_ipproto) {
	case IPPROTO_UDP:
		if (p->inp_rem < sizeof(*p->inp_emb_uh)) {
			icmpstat.icps_badlen++;
			return IN_DROP;
		}
		p->inp_emb_uh = (struct udp_hdr *)p->inp_cur;
		return IN_OK;
	case IPPROTO_TCP:
		if (p->inp_rem < sizeof(*p->inp_emb_th)) {
			icmpstat.icps_badlen++;
			return IN_BYPASS;
		}
		p->inp_emb_th = (struct tcp_hdr *)p->inp_cur;
		return IN_OK;
	case IPPROTO_ICMP:
		if (p->inp_rem < sizeof(*p->inp_emb_icp)) {
			icmpstat.icps_badlen++;
			return IN_DROP;
		}
		p->inp_emb_icp = (struct icmp4_hdr *)p->inp_cur;
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
}

static int
ip_in(struct inet_parser *p)
{
	int rc, tmp, total_len, cksum;

	ipstat.ips_total++;
	ipstat.ips_delivered++;
	if (p->inp_rem < sizeof(struct ip4_hdr)) {
		ipstat.ips_toosmall++;
		return IN_DROP;
	}
	p->inp_ih = (struct ip4_hdr *)(p->inp_eh + 1);
	if (p->inp_ih->ih_ttl < 1) {
		return IN_DROP;
	}
	//if (ipaddr4_is_mcast(p->inp_ih->ih_saddr)) {
	//	return IN_BYPASS;
	//}
	if (p->inp_ih->ih_frag_off & IP4_FRAG_MASK) {
		ipstat.ips_fragments++;
		ipstat.ips_fragdropped++;
		return IN_BYPASS;
	}
	p->inp_ih_len = IP4_HDR_LEN(p->inp_ih->ih_ver_ihl);
	if (p->inp_ih_len < sizeof(*p->inp_ih)) {
		ipstat.ips_badhlen++;
		return IN_DROP;
	}
	if (p->inp_rem < p->inp_ih_len) {
		ipstat.ips_badhlen++;
		return IN_DROP;
	}
	SHIFT(p, p->inp_ih_len);
	total_len = ntohs(p->inp_ih->ih_total_len);
	if (total_len < p->inp_ih_len) {
		ipstat.ips_badlen++;
		return IN_DROP;
	}
	p->inp_ip_payload_len = total_len - p->inp_ih_len;
	if (p->inp_ip_payload_len > p->inp_rem) {
		ipstat.ips_tooshort++;
		return IN_DROP;
	}
	p->inp_ipproto = p->inp_ih->ih_proto;
	cksum = p->inp_ih->ih_cksum;
	p->inp_ih->ih_cksum = 0;
	if (ip_do_incksum) {
		tmp = ip_cksum((struct ip *)p->inp_ih);
		if (tmp != cksum) {
			ipstat.ips_badsum++;
			return IN_DROP;
		}
	}
	p->inp_ih->ih_cksum = cksum;
	switch (p->inp_ipproto) {
	case IPPROTO_UDP:
		if (p->inp_rem < sizeof(struct udp_hdr)) {
			udpstat.udps_badlen++;
			return IN_DROP;
		}
		p->inp_uh = (struct udp_hdr *)p->inp_cur;
		SHIFT(p, sizeof(struct udp_hdr));
		return IN_OK;
	case IPPROTO_TCP:
		rc = tcp_in(p);
		break;
	case IPPROTO_ICMP:
		rc = icmp4_in(p);
		return rc;
	default:
		ipstat.ips_noproto++;
		rc = IN_BYPASS;
		break;
	}
	return rc;
}

int
eth_in(struct inet_parser *p)
{
	int rc, eh_type;

	p->inp_eh = (struct eth_hdr *)p->inp_cur;
	SHIFT(p, sizeof(struct eth_hdr));
	eh_type = ntohs(p->inp_eh->eh_type);
	switch (eh_type) {
	case ETH_TYPE_IP4:
		p->inp_ipproto = IPPROTO_IP;
		rc = ip_in(p);
		break;
	case ETH_TYPE_ARP:
		rc = arp_in(p);
		break;
	default:
		rc = IN_BYPASS;
	}
	return rc;
}
