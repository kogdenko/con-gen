/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
#ifndef CON_GEN__NETSTAT_H
#define CON_GEN__NETSTAT_H

#include "subr.h"

struct ipstat {
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

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct tcpstat {
	uint64_t tcps_connattempt;      /* connections initiated */
	uint64_t tcps_accepts;          /* connections accepted */
	uint64_t tcps_connects;         /* connections established */
	uint64_t tcps_drops;            /* connections dropped */
	uint64_t tcps_conndrops;        /* embryonic connections dropped */
	uint64_t tcps_listendrop;
	uint64_t tcps_badsyn;
	uint64_t tcps_closed;           /* conn. closed (includes drops) */
	uint64_t tcps_segstimed;        /* segs where we tried to get rtt */
	uint64_t tcps_rttupdated;       /* times we succeeded */
	uint64_t tcps_delack;           /* delayed acks sent */
	uint64_t tcps_timeoutdrop;      /* conn. dropped in rxmt timeout */
	uint64_t tcps_rexmttimeo;       /* retransmit timeouts */
	uint64_t tcps_persisttimeo;     /* persist timeouts */
	uint64_t tcps_keeptimeo;        /* keepalive timeouts */
	uint64_t tcps_keepprobe;        /* keepalive probes sent */
	uint64_t tcps_keepdrops;        /* connections dropped in keepalive */

	uint64_t tcps_sndtotal;	        /* total packets sent */
	uint64_t tcps_sndpack;          /* data packets sent */
	uint64_t tcps_sndbyte;          /* data bytes sent */
	uint64_t tcps_sndrexmitpack;    /* data packets retransmitted */
	uint64_t tcps_sndrexmitbyte;    /* data bytes retransmitted */
	uint64_t tcps_sndacks;          /* ack-only packets sent */
	uint64_t tcps_sndprobe;         /* window probes sent */
	uint64_t tcps_sndurg;           /* packets sent with URG only */
	uint64_t tcps_sndwinup;         /* window update-only packets sent */
	uint64_t tcps_sndctrl;          /* control (SYN|FIN|RST) packets sent */

	uint64_t tcps_rcvtotal;         /* total packets received */
	uint64_t tcps_rcvpack;          /* packets received in sequence */
	uint64_t tcps_rcvbyte;          /* bytes received in sequence */
	uint64_t tcps_rcvbadsum;        /* packets received with ccksum errs */
	uint64_t tcps_rcvbadoff;        /* packets received with bad offset */
	uint64_t tcps_rcvshort;         /* packets received too short */
	uint64_t tcps_rcvduppack;       /* duplicate-only packets received */
	uint64_t tcps_rcvdupbyte;       /* duplicate-only bytes received */
	uint64_t tcps_rcvpartduppack;   /* packets with some duplicate data */
	uint64_t tcps_rcvpartdupbyte;   /* dup. bytes in part-dup. packets */
	uint64_t tcps_rcvoopack;        /* out-of-order packets received */
	uint64_t tcps_rcvoobyte;        /* out-of-order bytes received */
	uint64_t tcps_rcvpackafterwin;  /* packets with data after window */
	uint64_t tcps_rcvbyteafterwin;  /* bytes rcvd after window */
	uint64_t tcps_rcvafterclose;    /* packets rcvd after "close" */
	uint64_t tcps_rcvwinprobe;      /* rcvd window probe packets */
	uint64_t tcps_rcvdupack;        /* rcvd duplicate acks */
	uint64_t tcps_rcvacktoomuch;    /* rcvd acks for unsent data */
	uint64_t tcps_rcvackpack;       /* rcvd ack packets */
	uint64_t tcps_rcvackbyte;       /* bytes acked by rcvd acks */
	uint64_t tcps_rcvwinupd;        /* rcvd window update packets */
	uint64_t tcps_pawsdrop;         /* segments dropped due to PAWS */
	uint64_t tcps_predack;          /* times hdr predict ok for acks */
	uint64_t tcps_preddat;          /* times hdr predict ok for data pkts */
};

struct udpstat {
	uint64_t udps_ipackets;         /* total input packets */
	uint64_t udps_hdrops;           /* packet shorter than header */
	uint64_t udps_badsum;           /* checksum error */
	uint64_t udps_badlen;           /* data length larger than packet */
	uint64_t udps_noport;           /* no socket on port */
	uint64_t udps_noportbcast;      /* of above, arrived as broadcast */
	uint64_t udps_fullsock;         /* not delivered, input socket full */
	uint64_t udpps_pcbcachemiss;    /* input packets missing pcb cache */
	uint64_t udps_opackets;	        /* total output packets */
};

/*
 * Variables related to this implementation
 * of the internet control message protocol.
 */
struct	icmpstat {
/* statistics related to icmp packets generated */
	uint64_t icps_error;            /* # of calls to icmp_error */
	uint64_t icps_oldicmp;          /* no error 'cuz old was icmp */
	uint64_t icps_outhist[ICMP_MAXTYPE + 1];
/* statistics related to input messages processed */
 	uint64_t icps_badcode;          /* icmp_code out of range */
	uint64_t icps_tooshort;         /* packet < ICMP_MINLEN */
	uint64_t icps_checksum;         /* bad checksum */
	uint64_t icps_badlen;           /* calculated bound mismatch */
	uint64_t icps_reflect;          /* number of responses */
	uint64_t icps_inhist[ICMP_MAXTYPE + 1];
};

void pr_sockets();
void pr_stats();

#endif // CON_GEN__NETSTAT_H
