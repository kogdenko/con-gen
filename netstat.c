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
#include "global.h"

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
print_tcpstat(FILE *file, int verbose)
{
	uint64_t sndtotal;
	uint64_t sndpack, sndbyte;
	uint64_t sndrexmitpack, sndrexmitbyte;
	uint64_t sndacks, delack;
	uint64_t sndurg;
	uint64_t sndprobe;
	uint64_t sndwinup;
	uint64_t sndctrl;
	uint64_t rcvtotal;
	uint64_t rcvackpack, rcvackbyte;
	uint64_t rcvdupack;
	uint64_t rcvacktoomuch;
	uint64_t rcvpack, rcvbyte;
	uint64_t rcvduppack, rcvdupbyte;
	uint64_t pawsdrop;
	uint64_t rcvpartduppack, rcvpartdupbyte;
	uint64_t rcvoopack, rcvoobyte;
	uint64_t rcvpackafterwin, rcvbyteafterwin;
	uint64_t rcvwinprobe;
	uint64_t rcvwinupd;
	uint64_t rcvafterclose;
	uint64_t rcvbadsum;
	uint64_t rcvbadoff;
	uint64_t rcvshort;
	uint64_t connattempt;
	uint64_t accepts;
	uint64_t listendrop;
	uint64_t connects;
	uint64_t closed, drops;
	uint64_t conndrops;
	uint64_t rttupdated, segstimed;
	uint64_t rexmttimeo;
	uint64_t timeoutdrop;
	uint64_t persisttimeo;
	uint64_t keeptimeo;
	uint64_t keepprobe;
	uint64_t keepdrops;
	uint64_t predack;
	uint64_t preddat;

	fprintf(file, "tcp:\n");
	sndtotal = counter64_get(&tcpstat.tcps_sndtotal);
	if (sndtotal || verbose) {
		fprintf(file, "\t%"PRIu64" packets sent\n", sndtotal);
	}
	sndpack = counter64_get(&tcpstat.tcps_sndpack);
	sndbyte = counter64_get(&tcpstat.tcps_sndbyte);
	if (sndpack || sndbyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" data packets (%"PRIu64" bytes)\n",
			sndpack, sndbyte);
	}
	sndrexmitpack = counter64_get(&tcpstat.tcps_sndrexmitpack);
	sndrexmitbyte = counter64_get(&tcpstat.tcps_sndrexmitbyte);
	if (sndrexmitpack || sndrexmitbyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" data packets (%"PRIu64" bytes) retransmitted\n",
			sndrexmitpack, sndrexmitbyte);
	}
//	printf("\t\t%llu data packets unnecessarily retransmitted\n",
//	       tcpstat.tcps_sndrexmitbad);
//	printf("\t\t%llu resends initiated by MTU discovery\n",
//	       tcpstat.tcps_mturesent);
	sndacks = counter64_get(&tcpstat.tcps_sndacks);
	delack = counter64_get(&tcpstat.tcps_delack);
	if (sndacks || delack || verbose) {
		fprintf(file, "\t\t%"PRIu64" ack-only packets (%"PRIu64" delayed)\n",
			sndacks, delack);
	}
	sndurg = counter64_get(&tcpstat.tcps_sndurg);
	if (sndurg || verbose) {
		fprintf(file, "\t\t%"PRIu64" URG only packets\n", sndurg);
	}
	sndprobe = counter64_get(&tcpstat.tcps_sndprobe);
	if (sndprobe || verbose) {
		fprintf(file, "\t\t%"PRIu64" window probe packets\n", sndprobe);
	}
	sndwinup = counter64_get(&tcpstat.tcps_sndwinup);
	if (sndwinup || verbose) {
		fprintf(file, "\t\t%"PRIu64" window update packets\n", sndwinup);
	}
	sndctrl = counter64_get(&tcpstat.tcps_sndctrl);
	if (sndctrl || verbose) {
		fprintf(file, "\t\t%"PRIu64" control packets\n", sndctrl);
	}
	// packets received
	rcvtotal = counter64_get(&tcpstat.tcps_rcvtotal);
	if (rcvtotal || verbose) {
		fprintf(file, "\t%"PRIu64" packets received\n", rcvtotal);
	}
	rcvackpack = counter64_get(&tcpstat.tcps_rcvackpack);
	rcvackbyte = counter64_get(&tcpstat.tcps_rcvackbyte);
	if (rcvackpack || rcvackbyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" acks (for %"PRIu64" bytes)\n",
			rcvackpack, rcvackbyte);
	}
	rcvdupack = counter64_get(&tcpstat.tcps_rcvdupack);
	if (rcvdupack || verbose) {
		fprintf(file, "\t\t%"PRIu64" duplicate acks\n", rcvdupack);
	}
	rcvacktoomuch = counter64_get(&tcpstat.tcps_rcvacktoomuch);
	if (rcvacktoomuch || verbose) {
		fprintf(file, "\t\t%"PRIu64" acks for unsent data\n",
			rcvacktoomuch);
	}
	rcvpack = counter64_get(&tcpstat.tcps_rcvpack);
	rcvbyte = counter64_get(&tcpstat.tcps_rcvbyte);
	if (rcvpack || rcvbyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" packets (%"PRIu64" bytes) received in-sequence\n",
			rcvpack, rcvbyte);
	}
	rcvduppack = counter64_get(&tcpstat.tcps_rcvduppack);
	rcvdupbyte = counter64_get(&tcpstat.tcps_rcvdupbyte);
	if (rcvduppack || rcvdupbyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" completely duplicate packets (%"PRIu64" bytes)\n",
			rcvduppack, rcvdupbyte);
	}
	pawsdrop = counter64_get(&tcpstat.tcps_pawsdrop);
	if (pawsdrop || verbose) {
		fprintf(file, "\t\t%"PRIu64" old duplicate packets\n", pawsdrop);
	}
	rcvpartduppack = counter64_get(&tcpstat.tcps_rcvpartduppack);
	rcvpartdupbyte = counter64_get(&tcpstat.tcps_rcvpartdupbyte);
	if (rcvpartduppack || rcvpartdupbyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" packets with some dup. data (%"PRIu64" bytes duped)\n",
			rcvpartduppack, rcvpartdupbyte);
	}
	rcvoopack = counter64_get(&tcpstat.tcps_rcvoopack);
	rcvoobyte = counter64_get(&tcpstat.tcps_rcvoobyte);
	if (rcvoopack || rcvoobyte || verbose) {
		fprintf(file, "\t\t%"PRIu64" out-of-order packets (%"PRIu64" bytes)\n",
			rcvoopack, rcvoobyte);
	}
	rcvpackafterwin = counter64_get(&tcpstat.tcps_rcvpackafterwin);
	rcvbyteafterwin = counter64_get(&tcpstat.tcps_rcvbyteafterwin);
	if (rcvpackafterwin || rcvbyteafterwin || verbose) {
		fprintf(file, "\t\t%"PRIu64" packets (%"PRIu64" bytes) of data after window\n",
			rcvpackafterwin, rcvbyteafterwin);
	}
	rcvwinprobe = counter64_get(&tcpstat.tcps_rcvwinprobe);
	if (rcvwinprobe || verbose) {
		fprintf(file, "\t\t%"PRIu64" window probes\n", rcvwinprobe);
	}
	rcvwinupd = counter64_get(&tcpstat.tcps_rcvwinupd);
	if (rcvwinupd || verbose) {
		fprintf(file, "\t\t%"PRIu64" window update packets\n", rcvwinupd);
	}
	rcvafterclose = counter64_get(&tcpstat.tcps_rcvafterclose);
	if (rcvafterclose || verbose) {
		fprintf(file, "\t\t%"PRIu64" packets received after close\n",
			rcvafterclose);
	}
	rcvbadsum = counter64_get(&tcpstat.tcps_rcvbadsum);
	if (rcvbadsum || verbose) {
		fprintf(file, "\t\t%"PRIu64" discarded for bad checksums\n",
			rcvbadsum);
	}
	rcvbadoff = counter64_get(&tcpstat.tcps_rcvbadoff);
	if (rcvbadoff || verbose) {
		fprintf(file, "\t\t%"PRIu64" discarded for bad header offset fields\n",
			rcvbadoff);
	}
	rcvshort = counter64_get(&tcpstat.tcps_rcvshort);
	if (rcvshort || verbose) {
		fprintf(file, "\t\t%"PRIu64" discarded because packet too short\n",
			rcvshort);
	}
//	printf("\t\t%llu discarded due to memory problems\n",
//	       tcpstat.tcps_rcvmemdrop);
	// connection requests
	connattempt = counter64_get(&tcpstat.tcps_connattempt);
	if (connattempt || verbose) {
		fprintf(file, "\t%"PRIu64" connection requests\n", connattempt);
	}
	accepts = counter64_get(&tcpstat.tcps_accepts);
	if (accepts || verbose) {
		fprintf(file, "\t%"PRIu64" connection accepts\n", accepts);
	}
	//printf("\t%llu bad connection attempts\n", tcpstat.tcps_badsyn);
	listendrop = counter64_get(&tcpstat.tcps_listendrop);
	if (listendrop || verbose) {
		fprintf(file, "\t%"PRIu64" listen queue overflows\n", listendrop);
	}
	//printf("\t%llu ignored RSTs in the windows\n", tcpstat.tcps_badrst);
	connects = counter64_get(&tcpstat.tcps_connects);
	if (connects || verbose) {
		fprintf(file, "\t%"PRIu64" connections established (including accepts)\n",
		       connects);
	}
	closed = counter64_get(&tcpstat.tcps_closed);
	drops = counter64_get(&tcpstat.tcps_drops);
	if (closed || drops || verbose) {
		fprintf(file, "\t%"PRIu64" connections closed (including %"PRIu64" drops)\n",
		       closed, drops);
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
	conndrops = counter64_get(&tcpstat.tcps_conndrops);
	if (conndrops || verbose) {
		fprintf(file, "\t%"PRIu64" embryonic connections dropped\n",
		       conndrops);
	}
	rttupdated = counter64_get(&tcpstat.tcps_rttupdated);
	segstimed = counter64_get(&tcpstat.tcps_segstimed);
	if (rttupdated || segstimed || verbose) {
		fprintf(file, "\t%"PRIu64" segments updated rtt (of %"PRIu64" attempts)\n",
			rttupdated, segstimed);
	}
	rexmttimeo = counter64_get(&tcpstat.tcps_rexmttimeo);
	if (rexmttimeo || verbose) {
		fprintf(file, "\t%"PRIu64" retransmit timeouts\n", rexmttimeo);
	}
	timeoutdrop = counter64_get(&tcpstat.tcps_timeoutdrop);
	if (timeoutdrop || verbose) {
		fprintf(file, "\t\t%"PRIu64" connections dropped by rexmit timeout\n",
			timeoutdrop);
	}
	persisttimeo = counter64_get(&tcpstat.tcps_persisttimeo);
	if (persisttimeo || verbose) {
		fprintf(file, "\t%"PRIu64" persist timeouts\n", persisttimeo);
	}
//	printf("\t\t%llu connections dropped by persist timeout\n",
//	       tcpstat.tcps_persistdrop);
	keeptimeo = counter64_get(&tcpstat.tcps_keeptimeo);
	if (keeptimeo || verbose) {
		fprintf(file, "\t%"PRIu64" keepalive timeouts\n", keeptimeo);
	}
	keepprobe = counter64_get(&tcpstat.tcps_keepprobe);
	if (keepprobe || verbose) {
		fprintf(file, "\t\t%"PRIu64" keepalive probes sent\n", keepprobe);
	}
	keepdrops = counter64_get(&tcpstat.tcps_keepdrops);
	if (keepdrops || verbose) {
		fprintf(file, "\t\t%"PRIu64" connections dropped by keepalive\n",
			keepdrops);
	}
	predack = counter64_get(&tcpstat.tcps_predack);
	if (predack || verbose) {
		fprintf(file, "\t%"PRIu64" correct ACK header predictions\n", predack);
	}
	preddat = counter64_get(&tcpstat.tcps_preddat);
	if (preddat || verbose) {
		fprintf(file, "\t%"PRIu64" correct data packet header predictions\n",
		       preddat);
	}
}

void
print_udpstat(FILE *file, int verbose)
{
	uint64_t ipackets;
	uint64_t hdrops;
	uint64_t badlen;
	uint64_t badsum;
	uint64_t noport;
	uint64_t noportbcast;
	uint64_t fullsock;
	uint64_t delivered;
	uint64_t opackets;

	fprintf(file, "udp:\n");
	ipackets = counter64_get(&udpstat.udps_ipackets);
	delivered = ipackets;
	if (ipackets || verbose) {
		fprintf(file, "\t%"PRIu64" datagrams received\n", ipackets);
	}
	hdrops = counter64_get(&udpstat.udps_hdrops);
	delivered -= hdrops;
	if (hdrops || verbose) {
		fprintf(file, "\t%"PRIu64" with incomplete header\n", hdrops);
	}
	badlen = counter64_get(&udpstat.udps_badlen);
	delivered -= badlen;
	if (badlen || verbose) {
		fprintf(file, "\t%"PRIu64" with bad data length field\n", badlen);
	}
	badsum = counter64_get(&udpstat.udps_badsum);
	delivered -= badsum;
	if (badsum || verbose) {
		fprintf(file, "\t%"PRIu64" with bad checksum\n", badsum);
	}
//	printf("\t%llu with no checksum\n", udpstat.udps_nosum);
	noport = counter64_get(&udpstat.udps_noport);
	delivered -= noport;
	if (noport || verbose) {
		fprintf(file, "\t%"PRIu64" dropped due to no socket\n", noport);
	}
	noportbcast = counter64_get(&udpstat.udps_noportbcast);
	delivered -= noportbcast;
	if (noportbcast || verbose) {
		fprintf(file, "\t%"PRIu64" broadcast/multicast datagrams undelivered\n",
		       noportbcast);
	}
	fullsock = counter64_get(&udpstat.udps_fullsock);
	delivered -= fullsock;
	if (fullsock || verbose) {
		fprintf(file, "\t%"PRIu64" dropped due to full socket buffers\n",
		       fullsock);
	}
	if (delivered || verbose) {
		fprintf(file, "\t%"PRIu64" delivered\n", delivered);
	}
	opackets = counter64_get(&udpstat.udps_opackets);
	if (opackets || verbose) {
		fprintf(file, "\t%"PRIu64" datagrams output\n", opackets);
	}
}

static void
print_ipstat(FILE *file, int verbose)
{
	uint64_t total;
	uint64_t badsum;
	uint64_t toosmall;
	uint64_t tooshort;
	uint64_t badhlen;
	uint64_t badlen;
	uint64_t badoptions;
	uint64_t badvers;
	uint64_t fragments;
	uint64_t fragdropped;
	uint64_t fragtimeout;
	uint64_t reassembled;
	uint64_t delivered;
	uint64_t noproto;
	uint64_t localout;
	uint64_t noroute;
	uint64_t fragmented;
	uint64_t cantfrag;

	fprintf(file, "ip:\n");
	total = counter64_get(&ipstat.ips_total);
	if (total || verbose) {
		fprintf(file, "\t%"PRIu64" total packets received\n", total);
	}
	badsum = counter64_get(&ipstat.ips_badsum);
	if (badsum || verbose) {
		fprintf(file, "\t%"PRIu64" bad header checksums\n", badsum);
	}
	toosmall = counter64_get(&ipstat.ips_toosmall);
	if (toosmall || verbose) {
		fprintf(file, "\t%"PRIu64" with size smaller than minimum\n",
			toosmall);
	}
	tooshort = counter64_get(&ipstat.ips_tooshort);
	if (tooshort || verbose) {
		fprintf(file, "\t%"PRIu64" with data size < data length\n", tooshort);
	}
	//printf("\t%llu with ip length > max ip packet size\n", ipstat.ips_toolong);
	badhlen = counter64_get(&ipstat.ips_badhlen);
	if (badhlen | verbose) {
		fprintf(file, "\t%"PRIu64" with header length < data size\n",
			badhlen);
	}
	badlen = counter64_get(&ipstat.ips_badlen);
	if (badlen || verbose) {
		fprintf(file, "\t%"PRIu64" with data length < header length\n",
			badlen);
	}
	badoptions = counter64_get(&ipstat.ips_badoptions);
	if (badoptions || verbose) {
		fprintf(file, "\t%"PRIu64" with bad options\n", badoptions);
	}
	badvers = counter64_get(&ipstat.ips_badvers);
	if (badvers || verbose) {
		fprintf(file, "\t%"PRIu64" with incorrect version number\n", badvers);
	}
	fragments = counter64_get(&ipstat.ips_fragments);
	if (fragments || verbose) {
		fprintf(file, "\t%"PRIu64" fragments received\n", fragments);
	}
	fragdropped = counter64_get(&ipstat.ips_fragdropped);
	if (fragdropped || verbose) {
		fprintf(file, "\t%"PRIu64" fragments dropped (dup or out of space)\n",
			fragdropped);
	}
	fragtimeout = counter64_get(&ipstat.ips_fragtimeout);
	if (fragtimeout || verbose) {
		fprintf(file, "\t%"PRIu64" fragments dropped after timeout\n",
			fragtimeout);
	}
	reassembled = counter64_get(&ipstat.ips_reassembled);
	if (reassembled || verbose) {
		fprintf(file, "\t%"PRIu64" packets reassembled ok\n", reassembled);
	}
	delivered = counter64_get(&ipstat.ips_delivered);
	if (delivered || verbose) {
		fprintf(file, "\t%"PRIu64" packets for this host\n", delivered);
	}
	noproto = counter64_get(&ipstat.ips_noproto);
	if (noproto || verbose) {
		fprintf(file, "\t%"PRIu64" packets for unknown/unsupported protocol\n",
			noproto);
	}
	localout = counter64_get(&ipstat.ips_localout);
	if (localout || verbose) {
		fprintf(file, "\t%"PRIu64" packets sent from this host\n",
			localout);
	}
	noroute = counter64_get(&ipstat.ips_noroute);
	if (noroute || verbose) {
		fprintf(file, "\t%"PRIu64" output packets discarded due to no route\n",
			noroute);
	}
	fragmented = counter64_get(&ipstat.ips_fragmented);
	if (fragmented || verbose) {
		fprintf(file, "\t%"PRIu64" output datagrams fragmented\n",
			fragmented);
	}
	cantfrag = counter64_get(&ipstat.ips_cantfrag);
	if (cantfrag || verbose) {
		fprintf(file, "\t%"PRIu64" datagrams that can't be fragmented\n",
			cantfrag);
	}
}

static void
print_icmpstat(FILE *file, int verbose)
{
	int i;
	uint64_t error;
	uint64_t oldicmp;
	uint64_t outhist;
	uint64_t badcode;
	uint64_t tooshort;
	uint64_t checksum;
	uint64_t badlen;
	uint64_t inhist;
	uint64_t reflect;

	fprintf(file, "icmp:\n");
	error = counter64_get(&icmpstat.icps_error);
	if (error || verbose) {
		fprintf(file, "\t%"PRIu64" calls to icmp_error\n", error);
	}
	oldicmp = counter64_get(&icmpstat.icps_oldicmp);
	if (oldicmp || verbose) {
		fprintf(file, "\t%"PRIu64" errors not generated in response to an icmp message\n",
			oldicmp);
	}
	for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
		outhist = counter64_get(icmpstat.icps_outhist + i);
		if (outhist) {
			break;
		}
	}
	if (i < ICMP_MAXTYPE + 1) {
		fprintf(file, "\tOutput histogram:\n");
		for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
			outhist = counter64_get(icmpstat.icps_outhist + i);
			if (outhist) {
				fprintf(file, "\t\t");
				if (icmpnames[i] == NULL) {
					fprintf(file, "#%d", i);
				} else {
					fprintf(file, "%s", icmpnames[i]);
				}
				fprintf(file, ": %"PRIu64"\n", outhist);
			}
		}
	}
	badcode = counter64_get(&icmpstat.icps_badcode);
	if (badcode || verbose) {
		fprintf(file, "\t%"PRIu64" messages with bad code fields\n", badcode);
	}
	tooshort = counter64_get(&icmpstat.icps_tooshort);
	if (tooshort || verbose) {
		fprintf(file, "\t%"PRIu64" messages less than the minimum length\n",
			tooshort);
	}
	checksum = counter64_get(&icmpstat.icps_checksum);
	if (checksum || verbose) {
		fprintf(file, "\t%"PRIu64" messages with bad checksum\n", checksum);
	}
	badlen = counter64_get(&icmpstat.icps_badlen);
	if (badlen || verbose) {
		fprintf(file, "\t%"PRIu64" messages with bad length\n", badlen);
	}
//	printf("\t%"PRIu64" multicast echo requests ignored\n",
//	       icmpstat.icps_bmcastecho);
//	printf("\t%"PRIu64" multicast timestamp requests ignored",
//	       icmpstat.icps_bmcasttstamp);
	for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
		inhist = counter64_get(icmpstat.icps_inhist + i);
		if (inhist) {
			break;
		}
	}
	if (i < ICMP_MAXTYPE + 1) {
		fprintf(file, "Input histogram:\n");
		for (i = 0; i < ICMP_MAXTYPE + 1; ++i) {
			inhist = counter64_get(icmpstat.icps_inhist + i);
			if (inhist) {
				fprintf(file, "\t\t");
				if (icmpnames[i] == NULL) {
					fprintf(file, "#%d", i);
				} else {
					fprintf(file, "%s", icmpnames[i]);
				}
				fprintf(file, ": %"PRIu64"\n", inhist);
			}
		}
	}
	reflect = counter64_get(&icmpstat.icps_reflect);
	if (reflect || verbose) {
		fprintf(file, "\t%"PRIu64" message responses generated\n", reflect);
	}
//	printf("\t%"PRIu64" invalid return addresses\n", icmpstat.icps_badaddr);
//	printf("\t%"PRIu64" no return routes\n", icmpstat.icps_noroute);
	//printf(\tICMP address mask responses are disabled\n");
}

void
print_stats(FILE *file, int verbose)
{
	print_tcpstat(file, verbose);
	print_udpstat(file, verbose);
	print_ipstat(file, verbose);
	print_icmpstat(file, verbose);
}

void bsd_get_so_info(void *, struct socket_info *);
void toy_get_so_info(void *, struct socket_info *);

struct print_socket_udata {
	struct thread *prsud_thread;
	FILE *prsud_file;
};

void
print_socket(void *udata, void *e)
{
	struct in_addr tmp;
	FILE *file;
	const char *state, *proto;
	char bl[64], bf[64];
	struct thread *t;
	struct socket_info x;

	t = ((struct print_socket_udata *)udata)->prsud_thread;
	file = ((struct print_socket_udata *)udata)->prsud_file;
	memset(&x, 0, sizeof(x));
	if (t->t_toy) {
		toy_get_so_info(e, &x);
	} else {
		bsd_get_so_info(e, &x);
	}
	tmp.s_addr = x.soi_laddr;
	snprintf(bl, sizeof(bl), "%s:%hu", inet_ntoa(tmp), ntohs(x.soi_lport));
	tmp.s_addr = x.soi_faddr;
	snprintf(bf, sizeof(bf), "%s:%hu", inet_ntoa(tmp), ntohs(x.soi_fport));
	if (x.soi_ipproto == IPPROTO_TCP) {
		proto = "TCP";
		if (x.soi_state < ARRAY_SIZE(tcpstates)) {
			state = tcpstates[x.soi_state];
		} else {
			state = "???";
		}
	} else {
		proto = "UDP";
		state = "";
	}
	fprintf(file, "%-5.5s %-22.22s %-22.22s %-11.11s %-5u %s\n",
		proto, bl, bf, state,
		t->t_tcp_now - x.soi_idle,
		x.soi_debug);
}

void
print_sockets(FILE *file)
{
	int i;
	struct thread *t;
	struct print_socket_udata udata;

	fprintf(file, "%-5.5s %-22.22s %-22.22s %-11.11s %-5.5s %s\n",
	       "Proto", "Local Address", "Foreign Address", "State ", "Idle", "Debug");
	for (i = 0; i < n_threads; ++i) {
		t = threads + i;
		udata.prsud_thread = t;
		udata.prsud_file = file;
		spinlock_lock(&t->t_lock);
		htable_foreach(&t->t_in_htable, &udata, print_socket);
		spinlock_unlock(&t->t_lock);
	}
}
