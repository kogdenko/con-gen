/*
 * Copyright (c) 1982, 1986, 1993, 1994
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

/*
 * Kernel variables for tcp.
 */

#ifndef BSD44_TCP_VAR_H
#define BSD44_TCP_VAR_H

#include "types.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "../gbtcp/timer.h"

struct socket;

/*
 * Tcp control block, one per tcp; fields:
 */
struct tcpcb {
	short	t_state;		/* state of this connection */
	struct timer t_timer[TCPT_NTIMERS];	/* tcp timers */
	struct timer t_timer_delack;
	short	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	short	t_rxtcur;		/* current retransmit value */
	short	t_dupacks;		/* consecutive dup acks recd */
	u_short	t_maxseg;		/* maximum segment size */
	char	t_force;		/* 1 if forcing out a byte */
	u_short	t_flags;
#define	TF_ACKNOW	0x0001		/* ack peer immediately */
#define	TF_DELACK	0x0002		/* ack, but try to delay it */
#define	TF_NODELAY	0x0004		/* don't delay packets to coalesce */
#define	TF_NOOPT	0x0008		/* don't use tcp options */
#define	TF_SENTFIN	0x0010		/* have sent FIN */
#define	TF_REQ_SCALE	0x0020		/* have/will request window scaling */
#define	TF_RCVD_SCALE	0x0040		/* other side has requested scaling */
#define	TF_REQ_TSTMP	0x0080		/* have/will request timestamps */
#define	TF_RCVD_TSTMP	0x0100		/* a timestamp was received in SYN */

/*
 * The following fields are used as in the protocol specification.
 * See RFC783, Dec. 1981, page 21.
 */
/* send sequence variables */
	tcp_seq	snd_una;		/* send unacknowledged */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	u_long	snd_wnd;		/* send window */
/* receive sequence variables */
	tcp_seq	rcv_nxt;		/* receive next */
/*
 * Additional variables for this implementation.
 */
/* receive variables */
	tcp_seq	rcv_adv;		/* advertised window */
/* retransmit variables */
	tcp_seq	snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
/* congestion control (for slow start, source quench, retransmit after loss) */
	u_long	snd_cwnd;		/* congestion-controlled window */
	u_long	snd_ssthresh;		/* snd_cwnd size threshhold for
					 * for slow start exponential to
					 * linear switch
					 */
/*
 * transmit timing stuff.  See below for scale of srtt and rttvar.
 * "Variance" is actually smoothed difference.
 */
	uint32_t t_idle;			/* inactivity time */
	short	t_rtt;			/* round trip time */
	tcp_seq	t_rtseq;		/* sequence number being timed */
	short	t_srtt;			/* smoothed round-trip time */
	short	t_rttvar;		/* variance in round-trip time */
	u_long	max_sndwnd;		/* largest window peer has offered */

#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
	short	t_softerror;		/* possible error not yet reported */

/* RFC 1323 variables */
	u_char	snd_scale;		/* window scaling for send window */
	u_char	rcv_scale;		/* window scaling for recv window */
	u_char	request_r_scale;	/* pending window scaling */
	u_char	requested_s_scale;
	uint32_t ts_recent;		/* timestamp echo data */
	uint32_t ts_recent_age;		/* when last updated */
	tcp_seq	last_ack_sent;
};

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		8	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		3	/* shift for srtt; 3 bits frac. */
#define	TCP_RTTVAR_SCALE	4	/* multiplier for rttvar; 2 bits */
#define	TCP_RTTVAR_SHIFT	2	/* multiplier for rttvar; 2 bits */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TCP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define	TCP_REXMTVAL(tp) \
	(((tp)->t_srtt >> TCP_RTT_SHIFT) + (tp)->t_rttvar)

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

extern struct	tcpstat tcpstat;	/* tcp statistics */
extern uint32_t tcp_now;		/* for RFC 1323 timestamps */

void	 tcp_attach(struct socket *);
void	 tcp_canceltimers(struct tcpcb *);
void	 tcp_settimer(struct tcpcb *, int, uint64_t);
void	 tcp_setslowtimer(struct tcpcb *, int, u_short);
void	 tcp_setdelacktimer(struct tcpcb *);
struct tcpcb *
	 tcp_close(struct tcpcb *);
void	 tcp_ctlinput(int, int, be32_t, struct ip *);
int	 tcp_ctloutput(int, struct socket *, int, int, void *, int*);
struct tcpcb *
	 tcp_drop(struct tcpcb *, int);
void	 tcp_dooptions(struct tcpcb *,
	    u_char *, int, struct tcp_hdr *, int *, uint32_t *, uint32_t *);
void	 tcp_drain(void);
void	 tcp_fasttimo(void);
void	 tcp_init(void);
void	 tcp_input(struct ip *, int, int);
int	 tcp_mss(struct tcpcb *, u_int);
struct tcpcb *
	 tcp_newtcpcb(struct socket *);
void	 tcp_notify(struct socket *, int);
void	 tcp_output(struct tcpcb *);
int	 tcp_output_real(struct tcpcb *);
void	 tcp_quench(struct socket *, int);
void	 tcp_respond(struct tcpcb *, struct ip *, struct tcp_hdr *,
	             tcp_seq, tcp_seq, int);
void	 tcp_setpersist(struct tcpcb *);
void	 tcp_trace(int, int, struct tcpcb *, struct ip *, struct tcp_hdr *, int);
struct tcpcb *
	 tcp_usrclosed(struct tcpcb *);
void	 tcp_xmit_timer(struct tcpcb *, short);
void tcp_template(struct tcpcb *, struct ip *, struct tcp_hdr *);
int tcp_connect(struct socket *so, const struct sockaddr_in *);
int tcp_send(struct socket *so, const void *, int);
int tcp_disconnect(struct socket *so);
int tcp_listen(struct socket *so);
void tcp_accept(struct socket *so);
void tcp_rcvseqinit(struct tcpcb *tp, uint32_t irs);
void tcp_sendseqinit(struct tcpcb *, uint32_t h);
void tcp_abort(struct socket *so);
void tcp_shutdown(struct socket *so);

void tcp_2MSL_timo(struct timer *);
void tcp_REXMT_timo(struct timer *);
void tcp_PERSIST_timo(struct timer *);
void tcp_KEEP_timo(struct timer *);

#define	TCP_NSTATES	11

#define	TCPS_CLOSED		0	/* closed */
#define	TCPS_LISTEN		1	/* listening for connection */
#define	TCPS_SYN_SENT		2	/* active, have sent syn */
#define	TCPS_SYN_RECEIVED	3	/* have send and received syn */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define	TCPS_ESTABLISHED	4	/* established */
#define	TCPS_CLOSE_WAIT		5	/* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define	TCPS_FIN_WAIT_1		6	/* have closed, sent fin */
#define	TCPS_CLOSING		7	/* closed xchd FIN; await FIN ACK */
#define	TCPS_LAST_ACK		8	/* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define	TCPS_FIN_WAIT_2		9	/* have closed, fin is acked */
#define	TCPS_TIME_WAIT		10	/* in 2*msl quiet wait after close */

#define	TCPS_HAVERCVDSYN(s)	((s) >= TCPS_SYN_RECEIVED)
#define	TCPS_HAVERCVDFIN(s)	((s) >= TCPS_TIME_WAIT)

extern const char *tcpstates[TCP_NSTATES];
extern int tcp_do_wscale;
extern int tcp_do_timestamps;
extern uint64_t tcp_fintimo;
extern uint64_t tcp_twtimo;

#endif /* BSD44_TCP_VAR_H */
