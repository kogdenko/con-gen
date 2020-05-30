#ifndef CON_GEN__GLOBAL_H
#define CON_GEN__GLOBAL_H

#include "subr.h"
#include "netstat.h"
#include "gbtcp/htable.h"

extern int nflag;
extern int Lflag;
extern int use_toy;
extern be16_t pflag_port;
extern int so_debug_flag;
extern int done;
extern int concurrency;
extern int verbose;
extern int tx_full;
extern struct dlist so_txq;
extern struct nm_desc *nmd;
extern u_char eth_laddr[6];
extern u_char eth_faddr[6]; 
extern uint32_t ip_laddr_min;
extern uint32_t ip_laddr_max;
extern uint32_t ip_faddr_min;
extern uint32_t ip_faddr_max;
extern struct if_addr *if_addrs;
extern int n_if_addrs;
extern int http_len;
extern char http[1500];
extern int ip_do_incksum;
extern int ip_do_outcksum;
extern int tcp_do_incksum;
extern int tcp_do_outcksum;
extern int if_mtu;
extern uint64_t if_ibytes;
extern uint64_t if_ipackets;
extern uint64_t if_obytes;
extern uint64_t if_opackets;
extern uint64_t if_imcasts;
extern struct udpstat udpstat;
extern struct tcpstat tcpstat;
extern struct ipstat ipstat;
extern struct icmpstat icmpstat;
extern const char *tcpstates[TCP_NSTATES];

extern uint64_t nanosec;
extern int in_length;
extern htable_t in_htable;

#endif
