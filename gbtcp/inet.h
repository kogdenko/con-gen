// gpl2 license
#ifndef GBTCP_INET_H
#define GBTCP_INET_H

#include "../subr.h"

#define ETH_TYPE_IP4 0x0800
#define ETH_TYPE_IP4_BE htons(ETH_TYPE_IP4)
#define ETH_TYPE_IP6 0x86DD
#define ETH_TYPE_IP6_BE htons(ETH_TYPE_IP6)
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_ARP_BE htons(ETH_TYPE_ARP)

#define ARP_HRD_ETH 1
#define ARP_HRD_ETH_BE htons(ARP_HRD_ETH)

#define ARP_OP_REQUEST 1
#define ARP_OP_REQUEST_BE htons(ARP_OP_REQUEST)
#define ARP_OP_REPLY 2
#define ARP_OP_REPLY_BE htons(ARP_OP_REPLY)

#define IP4_MTU_MIN 68

#define IP4_VER_IHL (0x40|0x05)
#define IP4_FRAG_MASK 0xFF3F

#define IP4H_FLAG_DF (1 << 6)
#define IP4H_FLAG_MF (1 << 5)

#define IP6_MTU_GT_MIN 1280

#define IP6H_VER_TC_FL 0x60

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define TCP_OPT_EOL 0 
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2 
#define TCP_OPT_WSCALE 3
#define TCP_OPT_SACK_PERMITED 4
#define TCP_OPT_TIMESTAMPS 8
#define TCP_OPT_MAX 9

#define IN_OK -1
#define IN_DROP -2
#define IN_BYPASS -3

struct eth_hdr {
	u_char eh_daddr[6];
	u_char eh_saddr[6];
	be16_t eh_type;
} __attribute__((packed));

struct ip4_hdr {
	uint8_t ih_ver_ihl;
	uint8_t ih_tos;
	be16_t ih_total_len;
	be16_t ih_id;
	be16_t ih_frag_off;
	uint8_t ih_ttl;
	uint8_t ih_proto;
	uint16_t ih_cksum;
	be32_t ih_saddr;
	be32_t ih_daddr;
} __attribute__((packed, aligned(4)));

struct udp_hdr {
	be16_t uh_sport;
	be16_t uh_dport;
	be16_t uh_len;
	uint16_t uh_cksum;
} __attribute__((packed));

struct tcp_hdr {
	be16_t th_sport;
	be16_t th_dport;
	be32_t th_seq;
	be32_t th_ack;
	uint8_t th_data_off;
	uint8_t th_flags;
	be16_t th_win_size;
	uint16_t th_cksum;
	be16_t th_urgent_ptr;
} __attribute__((packed));

struct icmp4_hdr {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	union {
		uint32_t icmp_unused;
		struct {
			be16_t icmp_echo_id;
			be16_t icmp_echo_seq;
		} icmp4h_echo;
		struct {
			uint8_t icmp_ppm_ptr;
			uint8_t icmp_ppm_unused[3];
		} icmp4h_ppm; // Parameter Problem Message
		struct {
 			be16_t icmp_ptb_unused;
			be16_t icmp_ptb_mtu;
		} icmp4h_ptb; // Packet Too Big
	};
} __attribute__((packed));

struct arp_ip4 {
	u_char aip_sha[6];
	be32_t aip_sip;
	u_char aip_tha[6];
	be32_t aip_tip;
} __attribute__((packed));

struct arp_hdr {
	be16_t ah_hrd;
	be16_t ah_pro;
	uint8_t ah_hlen;
	uint8_t ah_plen;
	be16_t ah_op;
	struct arp_ip4 ah_data;
} __attribute__((packed));

struct tcb {
	uint16_t tcb_win;
	uint16_t tcb_len;
	uint8_t tcb_flags;
	uint32_t tcb_seq;
	uint32_t tcb_ack;
};

struct inet_parser {
	u_char *inp_cur;
	int inp_rem;
	int inp_errnum;
	struct eth_hdr *inp_eh;
	struct arp_hdr *inp_ah;
	struct ip4_hdr *inp_ih;
	int inp_ih_len;
	uint16_t inp_ip_payload_len;
	uint8_t inp_ipproto;
	uint8_t inp_emb_ipproto;
	int inp_th_len;
	struct tcb inp_tcb;
	union {
		struct udp_hdr *inp_uh;
		struct tcp_hdr *inp_th;
		struct icmp4_hdr *inp_icp;
	};
	struct ip4_hdr *inp_emb_ih;
	union {
		struct udp_hdr *inp_emb_uh;
		struct tcp_hdr *inp_emb_th;
		struct icmp4_hdr *inp_emb_icp;
	};
	void *inp_payload;
};

#define IP4_HDR_LEN(ver_ihl) (((ver_ihl) & 0x0f) << 2)
#define TCP_HDR_LEN(data_off) ((data_off & 0xf0) >> 2)

void inet_parser_init(struct inet_parser *, void *, int);
int eth_in(struct inet_parser *);

#endif // GBTCP_INET_H
