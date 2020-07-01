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
	counter64_t ips_total;             /* total packets received */
	counter64_t ips_badsum;            /* checksum bad */
	counter64_t ips_tooshort;          /* packet too short */
	counter64_t ips_toosmall;          /* not enough data */
	counter64_t ips_badhlen;           /* ip header length < data size */
	counter64_t ips_badlen;            /* ip length < ip header length */
	counter64_t ips_fragments;         /* fragments received */
	counter64_t ips_fragdropped;       /* frags dropped (dups, out of space) */
	counter64_t ips_fragtimeout;       /* fragments timed out */
	counter64_t ips_forward;           /* packets forwarded */
	counter64_t ips_cantforward;       /* packets rcvd for unreachable dest */
	counter64_t ips_redirectsent;      /* packets forwarded on same net */
	counter64_t ips_noproto;           /* unknown or unsupported protocol */
	counter64_t ips_delivered;         /* datagrams delivered to upper level*/
	counter64_t ips_localout;          /* total ip packets generated here */
	counter64_t ips_odropped;          /* lost packets due to nobufs, etc. */
	counter64_t ips_reassembled;       /* total packets reassembled ok */
	counter64_t ips_fragmented;        /* datagrams sucessfully fragmented */
	counter64_t ips_ofragments;        /* output fragments created */
	counter64_t ips_cantfrag;          /* don't fragment flag was set, etc. */
	counter64_t ips_badoptions;        /* error in option processing */
	counter64_t ips_noroute;           /* packets discarded due to no route */
	counter64_t ips_badvers;           /* ip version != 4 */
	counter64_t ips_rawout;            /* total raw ip packets generated */
};

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct tcpstat {
	counter64_t tcps_connattempt;      /* connections initiated */
	counter64_t tcps_accepts;          /* connections accepted */
	counter64_t tcps_connects;         /* connections established */
	counter64_t tcps_drops;            /* connections dropped */
	counter64_t tcps_conndrops;        /* embryonic connections dropped */
	counter64_t tcps_listendrop;
	counter64_t tcps_badsyn;
	counter64_t tcps_closed;           /* conn. closed (includes drops) */
	counter64_t tcps_segstimed;        /* segs where we tried to get rtt */
	counter64_t tcps_rttupdated;       /* times we succeeded */
	counter64_t tcps_delack;           /* delayed acks sent */
	counter64_t tcps_timeoutdrop;      /* conn. dropped in rxmt timeout */
	counter64_t tcps_rexmttimeo;       /* retransmit timeouts */
	counter64_t tcps_persisttimeo;     /* persist timeouts */
	counter64_t tcps_keeptimeo;        /* keepalive timeouts */
	counter64_t tcps_keepprobe;        /* keepalive probes sent */
	counter64_t tcps_keepdrops;        /* connections dropped in keepalive */

	counter64_t tcps_sndtotal;	        /* total packets sent */
	counter64_t tcps_sndpack;          /* data packets sent */
	counter64_t tcps_sndbyte;          /* data bytes sent */
	counter64_t tcps_sndrexmitpack;    /* data packets retransmitted */
	counter64_t tcps_sndrexmitbyte;    /* data bytes retransmitted */
	counter64_t tcps_sndacks;          /* ack-only packets sent */
	counter64_t tcps_sndprobe;         /* window probes sent */
	counter64_t tcps_sndurg;           /* packets sent with URG only */
	counter64_t tcps_sndwinup;         /* window update-only packets sent */
	counter64_t tcps_sndctrl;          /* control (SYN|FIN|RST) packets sent */

	counter64_t tcps_rcvtotal;         /* total packets received */
	counter64_t tcps_rcvpack;          /* packets received in sequence */
	counter64_t tcps_rcvbyte;          /* bytes received in sequence */
	counter64_t tcps_rcvbadsum;        /* packets received with ccksum errs */
	counter64_t tcps_rcvbadoff;        /* packets received with bad offset */
	counter64_t tcps_rcvshort;         /* packets received too short */
	counter64_t tcps_rcvduppack;       /* duplicate-only packets received */
	counter64_t tcps_rcvdupbyte;       /* duplicate-only bytes received */
	counter64_t tcps_rcvpartduppack;   /* packets with some duplicate data */
	counter64_t tcps_rcvpartdupbyte;   /* dup. bytes in part-dup. packets */
	counter64_t tcps_rcvoopack;        /* out-of-order packets received */
	counter64_t tcps_rcvoobyte;        /* out-of-order bytes received */
	counter64_t tcps_rcvpackafterwin;  /* packets with data after window */
	counter64_t tcps_rcvbyteafterwin;  /* bytes rcvd after window */
	counter64_t tcps_rcvafterclose;    /* packets rcvd after "close" */
	counter64_t tcps_rcvwinprobe;      /* rcvd window probe packets */
	counter64_t tcps_rcvdupack;        /* rcvd duplicate acks */
	counter64_t tcps_rcvacktoomuch;    /* rcvd acks for unsent data */
	counter64_t tcps_rcvackpack;       /* rcvd ack packets */
	counter64_t tcps_rcvackbyte;       /* bytes acked by rcvd acks */
	counter64_t tcps_rcvwinupd;        /* rcvd window update packets */
	counter64_t tcps_pawsdrop;         /* segments dropped due to PAWS */
	counter64_t tcps_predack;          /* times hdr predict ok for acks */
	counter64_t tcps_preddat;          /* times hdr predict ok for data pkts */
};

struct udpstat {
	counter64_t udps_ipackets;         /* total input packets */
	counter64_t udps_hdrops;           /* packet shorter than header */
	counter64_t udps_badsum;           /* checksum error */
	counter64_t udps_badlen;           /* data length larger than packet */
	counter64_t udps_noport;           /* no socket on port */
	counter64_t udps_noportbcast;      /* of above, arrived as broadcast */
	counter64_t udps_fullsock;         /* not delivered, input socket full */
	counter64_t udpps_pcbcachemiss;    /* input packets missing pcb cache */
	counter64_t udps_opackets;	        /* total output packets */
};

/*
 * Variables related to this implementation
 * of the internet control message protocol.
 */
struct	icmpstat {
	/* statistics related to icmp packets generated */
	counter64_t icps_error;            /* # of calls to icmp_error */
	counter64_t icps_oldicmp;          /* no error 'cuz old was icmp */
	counter64_t icps_outhist[ICMP_MAXTYPE + 1];
	/* statistics related to input messages processed */
 	counter64_t icps_badcode;          /* icmp_code out of range */
	counter64_t icps_tooshort;         /* packet < ICMP_MINLEN */
	counter64_t icps_checksum;         /* bad checksum */
	counter64_t icps_badlen;           /* calculated bound mismatch */
	counter64_t icps_reflect;          /* number of responses */
	counter64_t icps_inhist[ICMP_MAXTYPE + 1];
};

void print_sockets();
void print_stats();

#endif // CON_GEN__NETSTAT_H
