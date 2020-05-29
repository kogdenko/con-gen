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
#include "common.h"
//#include "./bsd44/types.h"
//#include "./bsd44/socket.h"
//#include "./bsd44/tcp_var.h"
//#include "./bsd44/udp_var.h"
//#include "./bsd44/icmp_var.h"
//#include "./gbtcp/timer.h"

static const char *icmpnames[ICMP_MAXTYPE + 1] = {
	[ICMP_ECHOREPLY] = "echo reply",
	[ICMP_UNREACH] = "destination unreachable",
	[ICMP_SOURCEQUENCH] = "routing redirect",
	[ICMP_REDIRECT] = "routing redirect",
	[ICMP_ECHO] = "echo",
	[ICMP_TIMXCEED] = "time exceeded",
	[ICMP_PARAMPROB] = "parameter problem",
	[ICMP_TSTAMP] = "time stamp",
	[ICMP_TSTAMPREPLY] = "time stamp reply",
	[ICMP_IREQ] = "information request",
	[ICMP_IREQREPLY] = "information request reply",
	[ICMP_MASKREQ] = "address mask request",
	[ICMP_MASKREPLY] = "address mask reply",
};

void
print_tcpstat(int verbose)
{
	printf("tcp:\n");
	if (tcpstat.tcps_sndtotal || verbose) {
		printf("\t%"PRIu64" packets sent\n",
		       tcpstat.tcps_sndtotal);
	}
	if (tcpstat.tcps_sndpack || tcpstat.tcps_sndbyte || verbose) {
		printf("\t\t%"PRIu64" data packets (%"PRIu64" bytes)\n",
		       tcpstat.tcps_sndpack, tcpstat.tcps_sndbyte);
	}
	if (tcpstat.tcps_sndrexmitpack || tcpstat.tcps_sndrexmitbyte ||
	    verbose) {
		printf("\t\t%"PRIu64" data packets (%"PRIu64" bytes) retransmitted\n",
		       tcpstat.tcps_sndrexmitpack, tcpstat.tcps_sndrexmitbyte);
	}
//	printf("\t\t%llu data packets unnecessarily retransmitted\n",
//	       tcpstat.tcps_sndrexmitbad);
//	printf("\t\t%llu resends initiated by MTU discovery\n",
//	       tcpstat.tcps_mturesent);
	if (tcpstat.tcps_sndacks || tcpstat.tcps_delack || verbose) {
		printf("\t\t%"PRIu64" ack-only packets (%"PRIu64" delayed)\n",
		       tcpstat.tcps_sndacks, tcpstat.tcps_delack);
	}
	if (tcpstat.tcps_sndurg || verbose) {
		printf("\t\t%"PRIu64" URG only packets\n",
		       tcpstat.tcps_sndurg);
	}
	if (tcpstat.tcps_sndprobe || verbose) {
		printf("\t\t%"PRIu64" window probe packets\n",
		       tcpstat.tcps_sndprobe);
	}
	if (tcpstat.tcps_sndwinup || verbose) {
		printf("\t\t%"PRIu64" window update packets\n",
		       tcpstat.tcps_sndwinup);
	}
	if (tcpstat.tcps_sndctrl || verbose) {
		printf("\t\t%"PRIu64" control packets\n",
		       tcpstat.tcps_sndctrl);
	}
	// packets received
	if (tcpstat.tcps_rcvtotal || verbose) {
		printf("\t%"PRIu64" packets received\n",
		       tcpstat.tcps_rcvtotal);
	}
	if (tcpstat.tcps_rcvackpack || tcpstat.tcps_rcvackbyte || verbose) {
		printf("\t\t%"PRIu64" acks (for %"PRIu64" bytes)\n",
		       tcpstat.tcps_rcvackpack, tcpstat.tcps_rcvackbyte);
	}
	if (tcpstat.tcps_rcvdupack || verbose) {
		printf("\t\t%"PRIu64" duplicate acks\n",
		       tcpstat.tcps_rcvdupack);
	}
	if (tcpstat.tcps_rcvacktoomuch || verbose) {
		printf("\t\t%"PRIu64" acks for unsent data\n",
		       tcpstat.tcps_rcvacktoomuch);
	}
	if (tcpstat.tcps_rcvpack || tcpstat.tcps_rcvbyte || verbose) {
		printf("\t\t%"PRIu64" packets (%"PRIu64" bytes) received in-sequence\n",
		       tcpstat.tcps_rcvpack, tcpstat.tcps_rcvbyte);
	}
	if (tcpstat.tcps_rcvduppack || tcpstat.tcps_rcvdupbyte || verbose) {
		printf("\t\t%"PRIu64" completely duplicate packets (%"PRIu64" bytes)\n",
		       tcpstat.tcps_rcvduppack, tcpstat.tcps_rcvdupbyte);
	}
	if (tcpstat.tcps_pawsdrop || verbose) {
		printf("\t\t%"PRIu64" old duplicate packets\n",
		       tcpstat.tcps_pawsdrop);
	}
	if (tcpstat.tcps_rcvpartduppack || tcpstat.tcps_rcvpartdupbyte ||
	    verbose) {
		printf("\t\t%"PRIu64" packets with some dup. data (%"PRIu64" bytes duped)\n",
		       tcpstat.tcps_rcvpartduppack,
		       tcpstat.tcps_rcvpartdupbyte);
	}
	if (tcpstat.tcps_rcvoopack || tcpstat.tcps_rcvoobyte || verbose) {
		printf("\t\t%"PRIu64" out-of-order packets (%"PRIu64" bytes)\n",
		       tcpstat.tcps_rcvoopack, tcpstat.tcps_rcvoobyte);
	}
	if (tcpstat.tcps_rcvpackafterwin || tcpstat.tcps_rcvbyteafterwin ||
	    verbose) {
		printf("\t\t%"PRIu64" packets (%"PRIu64" bytes) of data after window\n",
		       tcpstat.tcps_rcvpackafterwin,
		       tcpstat.tcps_rcvbyteafterwin);
	}
	if (tcpstat.tcps_rcvwinprobe || verbose) {
		printf("\t\t%"PRIu64" window probes\n",
		       tcpstat.tcps_rcvwinprobe);
	}
	if (tcpstat.tcps_rcvwinupd || verbose) {
		printf("\t\t%"PRIu64" window update packets\n",
		       tcpstat.tcps_rcvwinupd);
	}
	if (tcpstat.tcps_rcvafterclose || verbose) {
		printf("\t\t%"PRIu64" packets received after close\n",
		       tcpstat.tcps_rcvafterclose);
	}
	if (tcpstat.tcps_rcvbadsum || verbose) {
		printf("\t\t%"PRIu64" discarded for bad checksums\n",
		       tcpstat.tcps_rcvbadsum);
	}
	if (tcpstat.tcps_rcvbadoff || verbose) {
		printf("\t\t%"PRIu64" discarded for bad header offset fields\n",
		       tcpstat.tcps_rcvbadoff);
	}
	if (tcpstat.tcps_rcvshort || verbose) {
		printf("\t\t%"PRIu64" discarded because packet too short\n",
		       tcpstat.tcps_rcvshort);
	}
//	printf("\t\t%llu discarded due to memory problems\n",
//	       tcpstat.tcps_rcvmemdrop);
	// connection requests
	if (tcpstat.tcps_connattempt || verbose) {
		printf("\t%"PRIu64" connection requests\n",
		       tcpstat.tcps_connattempt);
	}
	if (tcpstat.tcps_accepts || verbose) {
		printf("\t%"PRIu64" connection accepts\n",
		       tcpstat.tcps_accepts);
	}
	//printf("\t%llu bad connection attempts\n", tcpstat.tcps_badsyn);
	if (tcpstat.tcps_listendrop || verbose) {
		printf("\t%"PRIu64" listen queue overflows\n",
		       tcpstat.tcps_listendrop);
	}
	//printf("\t%llu ignored RSTs in the windows\n", tcpstat.tcps_badrst);
	if (tcpstat.tcps_connects || verbose) {
		printf("\t%"PRIu64" connections established (including accepts)\n",
		       tcpstat.tcps_connects);
	}
	if (tcpstat.tcps_closed || tcpstat.tcps_drops || verbose) {
		printf("\t%"PRIu64" connections closed (including %"PRIu64" drops)\n",
		       tcpstat.tcps_closed, tcpstat.tcps_drops);
	}
//	printf("\t\t%llu times used RTT from hostcache\n", tcpstat.tcps_usedrtt);
//	printf("\t\t%llu times used RTT variance from hostcache\n",
//	       tcpstat.tcps_usedrttvar);
//	printf("\t\t%llu times used slow-start threshold from hostcache\n",
//	       tcpstat.tcps_usedssthresh);
//	printf("\t\t%llu connections updated cached RTT on close\n",
//	       tcpstat.tcps_cachedrtt);
//	printf("\t\t%llu connections updated cached RTT variance on close\n",
//	       tcpstat.tcps_cachedrttvar);
//	printf("\t\t%llu connections updated cached ssthresh on close\n",
//	       tcpstat.tcps_cachedssthresh);
	if (tcpstat.tcps_conndrops || verbose) {
		printf("\t%"PRIu64" embryonic connections dropped\n",
		       tcpstat.tcps_conndrops);
	}
	if (tcpstat.tcps_rttupdated || tcpstat.tcps_segstimed || verbose) {
		printf("\t%"PRIu64" segments updated rtt (of %"PRIu64" attempts)\n",
		       tcpstat.tcps_rttupdated, tcpstat.tcps_segstimed);
	}
	if (tcpstat.tcps_rexmttimeo || verbose) {
		printf("\t%"PRIu64" retransmit timeouts\n",
		       tcpstat.tcps_rexmttimeo);
	}
	if (tcpstat.tcps_timeoutdrop || verbose) {
		printf("\t\t%"PRIu64" connections dropped by rexmit timeout\n",
		       tcpstat.tcps_timeoutdrop);
	}
	if (tcpstat.tcps_persisttimeo || verbose) {
		printf("\t%"PRIu64" persist timeouts\n",
		       tcpstat.tcps_persisttimeo);
	}
//	printf("\t\t%llu connections dropped by persist timeout\n",
//	       tcpstat.tcps_persistdrop);
	if (tcpstat.tcps_keeptimeo || verbose) {
		printf("\t%"PRIu64" keepalive timeouts\n",
		       tcpstat.tcps_keeptimeo);
	}
	if (tcpstat.tcps_keepprobe || verbose) {
		printf("\t\t%"PRIu64" keepalive probes sent\n",
		       tcpstat.tcps_keepprobe);
	}
	if (tcpstat.tcps_keepdrops || verbose) {
		printf("\t\t%"PRIu64" connections dropped by keepalive\n",
		       tcpstat.tcps_keepdrops);
	}
	if (tcpstat.tcps_predack || verbose) {
		printf("\t%"PRIu64" correct ACK header predictions\n",
		       tcpstat.tcps_predack);
	}
	if (tcpstat.tcps_preddat || verbose) {
		printf("\t%"PRIu64" correct data packet header predictions\n",
		       tcpstat.tcps_preddat);
	}
}

void
print_udpstat(int verbose)
{
	uint64_t delivered;

	printf("udp:\n");
	if (udpstat.udps_ipackets || verbose) {
		printf("\t%"PRIu64" datagrams received\n",
		       udpstat.udps_ipackets);
	}
	if (udpstat.udps_hdrops || verbose) {
		printf("\t%"PRIu64" with incomplete header\n",
		       udpstat.udps_hdrops);
	}
	if (udpstat.udps_badlen || verbose) {
		printf("\t%"PRIu64" with bad data length field\n",
		       udpstat.udps_badlen);
	}
	if (udpstat.udps_badsum || verbose) {
		printf("\t%"PRIu64" with bad checksum\n", udpstat.udps_badsum);
	}
//	printf("\t%llu with no checksum\n", udpstat.udps_nosum);
	if (udpstat.udps_noport || verbose) {
		printf("\t%"PRIu64" dropped due to no socket\n",
		       udpstat.udps_noport);
	}
	if (udpstat.udps_noportbcast || verbose) {
		printf("\t%"PRIu64" broadcast/multicast datagrams undelivered\n",
		       udpstat.udps_noportbcast);
	}
	if (udpstat.udps_fullsock || verbose) {
		printf("\t%"PRIu64" dropped due to full socket buffers\n",
		       udpstat.udps_fullsock);
	}
	delivered = udpstat.udps_ipackets -
	            udpstat.udps_hdrops -
	            udpstat.udps_badlen -
	            udpstat.udps_badsum -
	            udpstat.udps_noport -
	            udpstat.udps_noportbcast -
	            udpstat.udps_fullsock;
	if (delivered || verbose) {
		printf("\t%"PRIu64" delivered\n", delivered);
	}
	if (udpstat.udps_opackets || verbose) {
		printf("\t%"PRIu64" datagrams output\n",
		       udpstat.udps_opackets);
	}
}

static void
print_ipstat(int verbose)
{
	printf("ip:\n");
	if (ipstat.ips_total || verbose) {
		printf("\t%"PRIu64" total packets received\n",
		       ipstat.ips_total);
	}
	if (ipstat.ips_badsum || verbose) {
		printf("\t%"PRIu64" bad header checksums\n",
		       ipstat.ips_badsum);
	}
	if (ipstat.ips_toosmall || verbose) {
		printf("\t%"PRIu64" with size smaller than minimum\n",
		       ipstat.ips_toosmall);
	}
	if (ipstat.ips_tooshort || verbose) {
		printf("\t%"PRIu64" with data size < data length\n",
		       ipstat.ips_tooshort);
	}
	//printf("\t%llu with ip length > max ip packet size\n", ipstat.ips_toolong);
	if (ipstat.ips_badhlen | verbose) {
		printf("\t%"PRIu64" with header length < data size\n",
		       ipstat.ips_badhlen);
	}
	if (ipstat.ips_badlen || verbose) {
		printf("\t%"PRIu64" with data length < header length\n",
		       ipstat.ips_badlen);
	}
	if (ipstat.ips_badoptions || verbose) {
		printf("\t%"PRIu64" with bad options\n",
		       ipstat.ips_badoptions);
	}
	if (ipstat.ips_badvers || verbose) {
		printf("\t%"PRIu64" with incorrect version number\n",
		       ipstat.ips_badvers);
	}
	if (ipstat.ips_fragments || verbose) {
		printf("\t%"PRIu64" fragments received\n",
		       ipstat.ips_fragments);
	}
	if (ipstat.ips_fragdropped || verbose) {
		printf("\t%"PRIu64" fragments dropped (dup or out of space)\n",
		       ipstat.ips_fragdropped);
	}
	if (ipstat.ips_fragtimeout || verbose) {
		printf("\t%"PRIu64" fragments dropped after timeout\n",
		       ipstat.ips_fragtimeout);
	}
	if (ipstat.ips_reassembled || verbose) {
		printf("\t%"PRIu64" packets reassembled ok\n",
		       ipstat.ips_reassembled);
	}
	if (ipstat.ips_delivered || verbose) {
		printf("\t%"PRIu64" packets for this host\n",
		       ipstat.ips_delivered);
	}
	if (ipstat.ips_noproto || verbose) {
		printf("\t%"PRIu64" packets for unknown/unsupported protocol\n",
		       ipstat.ips_noproto);
	}
	if (ipstat.ips_localout || verbose) {
		printf("\t%"PRIu64" packets sent from this host\n",
		       ipstat.ips_localout);
	}
	if (ipstat.ips_noroute || verbose) {
		printf("\t%"PRIu64" output packets discarded due to no route\n",
		       ipstat.ips_noroute);
	}
	if (ipstat.ips_fragmented || verbose) {
		printf("\t%"PRIu64" output datagrams fragmented\n",
		       ipstat.ips_fragmented);
	}
	if (ipstat.ips_cantfrag || verbose) {
		printf("\t%"PRIu64" datagrams that can't be fragmented\n",
		       ipstat.ips_cantfrag);
	}
}

static void
print_icmpstat(int verbose)
{
	int i;

	printf("icmp:\n");
	if (icmpstat.icps_error || verbose) {
		printf("\t%"PRIu64" calls to icmp_error\n",
		       icmpstat.icps_error);
	}
	if (icmpstat.icps_oldicmp || verbose) {
		printf("\t%"PRIu64" errors not generated in response to an icmp message\n",
		       icmpstat.icps_oldicmp);
	}
	for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
		if (icmpstat.icps_outhist[i]) {
			break;
		}
	}
	if (i < ICMP_MAXTYPE + 1) {
		printf("\tOutput histogram:\n");
		for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
			if (icmpstat.icps_outhist[i]) {
				printf("\t\t");
				if (icmpnames[i] == NULL) {
					printf("#%d", i);
				} else {
					printf("%s", icmpnames[i]);
				}
				printf(": %"PRIu64"\n", icmpstat.icps_outhist[i]);
			}
		}
	}
	if (icmpstat.icps_badcode || verbose) {
		printf("\t%"PRIu64" messages with bad code fields\n",
		       icmpstat.icps_badcode);
	}
	if (icmpstat.icps_tooshort || verbose) {
		printf("\t%"PRIu64" messages less than the minimum length\n",
		       icmpstat.icps_tooshort);
	}
	if (icmpstat.icps_checksum || verbose) {
		printf("\t%"PRIu64" messages with bad checksum\n",
		       icmpstat.icps_checksum);
	}
	if (icmpstat.icps_badlen || verbose) {
		printf("\t%"PRIu64" messages with bad length\n",
		       icmpstat.icps_badlen);
	}
//	printf("\t%"PRIu64" multicast echo requests ignored\n",
//	       icmpstat.icps_bmcastecho);
//	printf("\t%"PRIu64" multicast timestamp requests ignored",
//	       icmpstat.icps_bmcasttstamp);
	for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
		if (icmpstat.icps_inhist[i]) {
			break;
		}
	}
	if (i < ICMP_MAXTYPE + 1) {
		printf("Input histogram:\n");
		for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
			if (icmpstat.icps_inhist[i]) {
				printf("\t\t");
				if (icmpnames[i] == NULL) {
					printf("#%d", i);
				} else {
					printf("%s", icmpnames[i]);
				}
				printf(": %"PRIu64"\n", icmpstat.icps_inhist[i]);
			}
		}
	}
	if (icmpstat.icps_reflect || verbose) {
		printf("\t%"PRIu64" message responses generated\n",
		       icmpstat.icps_reflect);
	}
//	printf("\t%"PRIu64" invalid return addresses\n", icmpstat.icps_badaddr);
//	printf("\t%"PRIu64" no return routes\n", icmpstat.icps_noroute);
	//printf(\tICMP address mask responses are disabled\n");
}

void
pr_stats(int verbose)
{
	print_tcpstat(verbose);
	print_udpstat(verbose);
	print_ipstat(verbose);
	print_icmpstat(verbose);
}

#if 0
static void
print_conn(struct socket *so)
{
	struct in_addr tmp;
	struct tcpcb *tp;
	const char *state;
	char bl[64], bf[64];

	tp = sototcpcb(so);
	tmp.s_addr = so->inp_laddr;
	snprintf(bl, sizeof(bl), "%s:%hu",
	         inet_ntoa(tmp), ntohs(so->inp_lport));
	tmp.s_addr = so->inp_faddr;
	snprintf(bf, sizeof(bf), "%s:%hu",
	         inet_ntoa(tmp), ntohs(so->inp_fport));
	if (tp->t_state < ARRAY_SIZE(tcpstates)) {
		state = tcpstates[tp->t_state];
	} else {
		state = "???";
	}
	printf("%-5.5s %-22.22s %-22.22s %-11.11s\n", "TCP", bl, bf, state);
}

void
print_conns()
{
	printf("%-5.5s %-22.22s %-22.22s %-11.11s\n",
	       "Proto", "Local Address", "Foreign Address", "State ");
	in_pcbforeach(print_conn);
}
#endif

void
pr_sockets()
{
}
