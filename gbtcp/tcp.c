#include "tcp.h"
#include "inet.h"

#define MSS (current->t_mtu - 40)

#define so_list so_base.ipso_list
#define so_laddr so_base.ipso_laddr
#define so_faddr so_base.ipso_faddr
#define so_lport so_base.ipso_lport
#define so_fport so_base.ipso_fport

struct sock {
	struct ip_socket so_base;
	struct dlist tx_list;
	union {
		uint32_t flags;
		struct {
			u_int used : 1;
			u_int closed : 1;
			u_int state : 4;
			u_int ack : 1;
			u_int rst : 1;
			u_int rsyn : 1;
			u_int rfin : 1;
			u_int ssyn : 1;
			u_int ssyn_acked : 1;
			u_int sfin : 1;
			u_int sfin_sent : 1;
			u_int sfin_acked : 1;
			u_int so_rexmit : 1;
			u_int so_rexmited : 1;
			u_int probe : 1;
			u_int nr_tries : 3;
			u_int nagle : 1;
			u_int nagle_acked : 1;
			u_int in_txq : 1;
			u_char rstate;
		};
	};
	struct timer timer;
	struct timer timer_delack;
	struct local_ip *ip;
	uint32_t rseq;
	uint32_t spos;
	uint32_t sack;
	uint16_t ssnt;
	uint16_t swnd;
	uint16_t rwnd;
	uint16_t rwnd_max;
	uint16_t ip_id;
};

static int in_length = -1;

static int  tcp_set_state(struct sock *, int);
static int  tcp_timer_set_probe(struct sock *);
static void tcp_timeout_rexmit(struct timer *);
static void tcp_timeout_delack(struct timer *);
static void tcp_timeout_probe(struct timer *);

#define PRIi4 "hhu.%hhu.%hhu.%hhu"
#define PRIi4f(x) \
	(unsigned char)(((x) >>  0) & 0xff), \
	(unsigned char)(((x) >>  8) & 0xff), \
	(unsigned char)(((x) >> 16) & 0xff), \
	(unsigned char)(((x) >> 24) & 0xff)

#define TCP_IS_REXMIT(so) \
({ \
	assert(so->so_rexmit || so->ssnt == 0); \
	so->so_rexmit; \
})

uint32_t
diff_seq(uint32_t start, uint32_t end)
{
	return end - start;
}

#define CHECK_FLAG(val, name) \
	if (tcp_flags & val) { \
		*ptr++ = name; \
	}

const char *
tcp_flags_string(uint8_t tcp_flags)
{
	static char buf[8];
	char *ptr;

	ptr = buf;
	CHECK_FLAG(TCP_FLAG_FIN, 'F');
	CHECK_FLAG(TCP_FLAG_SYN, 'S');
	CHECK_FLAG(TCP_FLAG_RST, 'R');
	CHECK_FLAG(TCP_FLAG_PSH, 'P');
	CHECK_FLAG(TCP_FLAG_ACK, '.');
	CHECK_FLAG(TCP_FLAG_URG, 'U');
	*ptr = '\0';
	return buf;
}

#undef CHECK_FLAG

/*const char *
tcp_param_string(struct tcp_param *p)
{
	static char buf[BUFSIZ];

	snprintf(buf, sizeof(buf),
	         "%"PRIi4".%hu-%"PRIi4".%hu",
	         PRIi4f(p->laddr), ntohs(p->lport),
	         PRIi4f(p->faddr), ntohs(p->fport));
	return buf;
}*/

static void
tcp_into_sndq(struct sock *so)
{
	assert(so->used);
	if (so->in_txq == 0) {
		so->in_txq = 1;
		DLIST_INSERT_TAIL(&current->t_so_txq, so, tx_list);
	}
}

static void
tcp_del_sndq(struct sock *so)
{
	assert(so->in_txq);
	so->in_txq = 0;
	DLIST_REMOVE(so, tx_list);
}

static void
tcp_into_ackq(struct sock *so)
{
	so->ack = 1;
	tcp_into_sndq(so);
}

static void
tcp_into_rstq(struct sock *so)
{
	so->rst = 1;
	tcp_into_sndq(so);
}

static void
tcp_shut(struct sock *so)
{
	assert(so->state >= TCPS_ESTABLISHED);
	if (so->sfin == 0) {
		so->sfin = 1;
		tcp_into_sndq(so);
	}
}

static void
tcp_on_rcv(struct sock *so, const char *payload, int len)
{
	int rc;

	if (len < 0) {
		tcp_shut(so);
		return;
	}
	if (in_length >= 0) {
		if (so->rstate < in_length) {
			so->rstate += len;
			if (so->rstate >= in_length) {
				tcp_shut(so);
			}
		}
		return;	
	}
	if (so->rstate < 4) {
		rc = parse_http(payload, len, &so->rstate);
		if (rc) {
			tcp_shut(so);
		}
	}
}

static struct sock *
tcp_open()
{
	struct sock *so;

	if (dlist_is_empty(&current->t_so_pool)) {
		so = xmalloc(sizeof(*so));
	} else {
		so = DLIST_FIRST(&current->t_so_pool, struct sock, so_list);
		DLIST_REMOVE(so, so_list);
	}
	current->t_n_clients++;
	assert(so->used == 0);
	so->flags = 0;
	so->used = 1;
	so->nagle = 1;
	so->nagle_acked = 1;
	so->ssnt = 0;
	so->spos = 0;
	so->swnd = 0;
	so->rwnd = 0;
	so->rwnd_max = 0;
	so->ip_id = 1;
	so->ip = NULL;
	timer_init(&so->timer);
	timer_init(&so->timer_delack);
	return so;
}

uint32_t
toy_socket_hash(struct dlist *p)
{
	uint32_t h;
	struct sock *so;

	so = container_of(p, struct sock, so_list);
	h = SO_HASH(so->so_faddr, so->so_lport, so->so_fport);
	return h;
}

static void
set_isn(struct sock *so, uint32_t h)
{
	so->sack = h + (uint32_t)(current->t_time >> 6);
}

static struct sock *
tcp_get(be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	uint32_t h;
	struct sock *so;
	struct dlist *b;

	h = SO_HASH(faddr, lport, fport);
	b = htable_bucket_get(&current->t_in_htable, h);
	DLIST_FOREACH(so, b, so_list) {
		if (so->so_laddr == laddr &&
		    so->so_faddr == faddr &&
		    so->so_lport == lport &&
		    so->so_fport == fport) {
			return so;
		}
	}
	return NULL;
}

void
toy_get_so_info(void *p, struct socket_info *x)
{
	struct sock *so;

	so = container_of(p, struct sock, so_list);
	x->soi_laddr = so->so_laddr;
	x->soi_faddr = so->so_faddr;
	x->soi_lport = so->so_lport;
	x->soi_fport = so->so_fport;
	x->soi_ipproto = IPPROTO_TCP;
	x->soi_state = so->state;
}

static int
tcp_connect()
{
	int rc;
	uint32_t h;
	struct sock *so;

	so = tcp_open();
	counter64_inc(&tcpstat.tcps_connattempt);
	rc = ip_connect(&so->so_base, &h);
	if (rc) {
		return rc;
	}
	set_isn(so, h);
	tcp_set_state(so, TCPS_SYN_SENT);
	tcp_into_sndq(so);
	return 0;
}

void
toy_client_connect()
{
	tcp_connect();
}

void
toy_server_listen(int ipproto)
{
	uint32_t lport;

	if (ipproto != IPPROTO_TCP) {
		panic(0, "unsupported protocol: %d", ipproto);
	}
	lport = ntohs(current->t_port);
	if (lport > EPHEMERAL_MAX) {
		panic(EADDRNOTAVAIL, "toy_bind() failed");
	}
}

static void
tcp_close(struct sock *so)
{
	int rc;

	if (so->in_txq) {
		so->closed = 1;
		return;
	}
	timer_cancel(&so->timer);
	timer_cancel(&so->timer_delack);
	htable_del(&current->t_in_htable, &so->so_list);
	so->used = 0;
	DLIST_INSERT_HEAD(&current->t_so_pool, so, so_list);
	current->t_n_clients--;
	current->t_n_requests++;
	counter64_inc(&tcpstat.tcps_closed);
	if (current->t_done == 0) {
		if (current->t_nflag &&
		    current->t_n_requests >= current->t_nflag) {
			current->t_done = 1;
		} else if (current->t_Lflag == 0) {
			while (current->t_n_clients < current->t_concurrency) {
				rc = tcp_connect();
				if (rc) {
					break;
				}
			}
		}
	}
}

static void
tcp_establish(struct sock *so)
{
	counter64_inc(&tcpstat.tcps_connects);
	if (current->t_Lflag == 0) {
		tcp_into_sndq(so);
	}
}

static int
tcp_set_state(struct sock *so, int state)
{
	assert(state != TCPS_LISTEN);
	assert(state != TCPS_CLOSED);
	assert(so->state != TCPS_LISTEN);
	assert(state != so->state);
	so->state = state;
	if (so->state == TCPS_ESTABLISHED) {
		tcp_establish(so);
	}
	return 0;
}

static void
tcp_timer_set_rexmit(struct sock *so)
{
	uint64_t expires;

	assert(so->sfin_acked == 0);
	if (so->so_rexmit == 0) {
		so->so_rexmit = 1;
		so->probe = 0;
		so->nr_tries = 0;
	}
	if (so->state < TCPS_ESTABLISHED) {
		expires = NANOSECONDS_SECOND;
	} else {
		expires = NANOSECONDS_SECOND/2;
	}
	expires <<= so->nr_tries;
	timer_set(&so->timer, expires, tcp_timeout_rexmit);
}

static void
calc_cksum(struct ip4_hdr *ih, struct tcp_hdr *th, int len)
{
	if (current->t_ip_do_outcksum) {
		ih->ih_cksum = ip_cksum((struct ip *)ih);
	}
	if (current->t_tcp_do_outcksum) {
		th->th_cksum = tcp_cksum((struct ip *)ih, len);
	}
}

static int
tcp_fill(struct sock *so, void *buf, struct tcb *tcb, int len_max)
{
	u_int th_len, total_len;
	struct ip4_hdr *ih;
	struct tcp_hdr *th;

	assert(tcb->tcb_len <= len_max);
	ih = (struct ip4_hdr *)(buf);
	th = (struct tcp_hdr *)(ih + 1);
	if (so->state >= TCPS_ESTABLISHED &&
		(tcb->tcb_flags & TCP_FLAG_RST) == 0) {
		tcb->tcb_flags |= TCP_FLAG_ACK;
		if (tcb->tcb_len == 0 && len_max && so->rwnd > so->ssnt) {
			tcb->tcb_len = MIN(len_max, so->rwnd - so->ssnt);
		}
	}
	if (tcb->tcb_len) {
		assert(tcb->tcb_len <= so->rwnd - so->ssnt);
		if (so->spos + so->ssnt + tcb->tcb_len == current->t_http_len ||
			(so->rwnd - so->ssnt) - tcb->tcb_len <= MSS) {
			tcb->tcb_flags |= TCP_FLAG_PSH;
		}
	}
	tcb->tcb_win = so->swnd;
	if (so->probe && tcb->tcb_len == 0) {
		tcb->tcb_seq = so->sack - 1;
	} else {
		tcb->tcb_seq = so->sack + so->ssnt;
		if (so->sfin_sent && (tcb->tcb_flags & TCP_FLAG_FIN) == 0) {
			tcb->tcb_seq++;
		}
	}
	tcb->tcb_ack = so->rseq;
	assert(so->spos + so->ssnt + tcb->tcb_len <= current->t_http_len);
	memcpy(th + 1, current->t_http + so->spos + so->ssnt, tcb->tcb_len);
	th_len = sizeof(*th);
	total_len = sizeof(*ih) + th_len + tcb->tcb_len;
	ih->ih_ver_ihl = IP4_VER_IHL;
	ih->ih_type_of_svc = 0;
	ih->ih_total_len = htons(total_len);
	ih->ih_id = htons(so->ip_id);
	ih->ih_frag_off = 0;
	ih->ih_ttl = 64;
	ih->ih_proto = IPPROTO_TCP;
	ih->ih_cksum = 0;
	ih->ih_saddr = so->so_laddr;
	ih->ih_daddr = so->so_faddr;
	th->th_sport = so->so_lport;
	th->th_dport = so->so_fport;
	th->th_seq = htonl(tcb->tcb_seq);
	th->th_ack = htonl(tcb->tcb_ack);
	th->th_data_off = th_len << 2;
	th->th_flags = tcb->tcb_flags;
	th->th_win_size = htons(16000);
	th->th_cksum = 0;
	th->th_urgent_ptr = 0;
	calc_cksum(ih, th, th_len + tcb->tcb_len);
	so->ip_id++;
	so->ssnt += tcb->tcb_len;
	if (tcb->tcb_flags & TCP_FLAG_SYN) {
		so->ssyn = 1;
		assert(so->ssyn_acked == 0);
	}
	if (tcb->tcb_len || (tcb->tcb_flags & (TCP_FLAG_SYN|TCP_FLAG_FIN))) {
		tcp_timer_set_rexmit(so);
	}
	timer_cancel(&so->timer_delack);
	return total_len;
}

static void
tcp_xmit_out(struct netmap_ring *txr, struct netmap_slot *m, struct sock *so,
	uint8_t tcp_flags, int len_max, int len)
{
	int total_len;
	struct eth_hdr *eh;
	struct tcb tcb;

	eh = (struct eth_hdr *)NETMAP_BUF(txr, m->buf_idx);
	memcpy(eh->eh_saddr, current->t_eth_laddr, sizeof(eh->eh_saddr));
	memcpy(eh->eh_daddr, current->t_eth_faddr, sizeof(eh->eh_daddr));
	eh->eh_type = ETH_TYPE_IP4_BE;
	tcb.tcb_flags = tcp_flags;
	tcb.tcb_len = len;
	total_len = tcp_fill(so, eh + 1, &tcb, len_max);
	m->len = sizeof(*eh) + total_len;
	counter64_inc(&tcpstat.tcps_sndtotal);
	if (tcb.tcb_len) {
		counter64_inc(&tcpstat.tcps_sndpack);
		counter64_add(&tcpstat.tcps_sndbyte, tcb.tcb_len);
	}
	if (so->so_rexmited &&
	    (tcb.tcb_len || tcb.tcb_flags & (TCP_FLAG_SYN|TCP_FLAG_FIN))) {
		so->so_rexmited = 0;
		counter64_inc(&tcpstat.tcps_sndrexmitpack);
		counter64_add(&tcpstat.tcps_sndrexmitbyte, tcb.tcb_len);
	}
	if (tcb.tcb_flags == TCP_FLAG_ACK) {
		counter64_inc(&tcpstat.tcps_sndacks);
	}
	ether_output(txr, m);
}

static int
tcp_sender(struct sock *so, u_int cnt)
{
	int can;

	assert(cnt);
	if (so->rwnd <= so->ssnt) {
		return 0;
	}
	can = so->rwnd - so->ssnt;
	if (can >= MSS && cnt >= MSS) {
		return MSS;
	}
	if (so->nagle_acked == 0) {
		return 0;
	}
	if (cnt <= can) {
		return cnt;
	}
	return can >= (so->rwnd_max >> 1) ? can : 0;
}

static int
tcp_timer_set_probe(struct sock *so)
{
	if (TCP_IS_REXMIT(so)) {
		return 0;
	}
	if (timer_is_running(&so->timer)) {
		return 0;
	}
	timer_set(&so->timer, 10 * NANOSECONDS_SECOND, tcp_timeout_probe);
	return 1;
}

static int
tcp_xmit_established(struct netmap_ring *txr, struct netmap_slot *m, struct sock *so)
{
	int len_max, len;
	uint8_t tcp_flags;

	if (so->state < TCPS_ESTABLISHED) {
		return 0;
	}
	if (so->sfin_acked || so->sfin_sent) {
		return 0;
	}
	tcp_flags = 0;
	len_max = 0;
	if (current->t_Lflag == 0 || so->rstate == 4) {
		// rstate == 4 - mean that peer send '\r\n\r\n'
		len_max = current->t_http_len - (so->spos + so->ssnt);
		assert(len_max >= 0);
	}
	if (len_max == 0) {
		len = 0;
	} else {
		len = tcp_sender(so, len_max);
		if (len) {
			tcp_flags = TCP_FLAG_ACK;
		} else {
			if (tcp_timer_set_probe(so)) {
				so->probe = 1;
			}

			return 0;
		}
	}
	if (len == len_max && so->sfin) {
		switch (so->state) {
		case TCPS_ESTABLISHED:
			tcp_set_state(so, TCPS_FIN_WAIT_1);
			break;
		case TCPS_CLOSE_WAIT:
			tcp_set_state(so, TCPS_LAST_ACK);
			break;
		}
		so->sfin_sent = 1;
		tcp_flags |= TCP_FLAG_FIN;
	}
	if (tcp_flags) {
		tcp_xmit_out(txr, m, so, tcp_flags, len_max, len);
		return 1;
	} else {
		return 0;
	}
}

//  0 - can send more
//  1 - sent all
static int
tcp_xmit(struct netmap_ring *txr, struct netmap_slot *m, struct sock *so)
{
	int rc;

	if (so->rst) {
		tcp_xmit_out(txr, m, so, TCP_FLAG_RST, 0, 0);
		return 1;
	}
	switch (so->state) {
	case TCPS_CLOSED:
		assert(0);
		return 1;
	case TCPS_LISTEN:
		assert(0);
		return 1;
	case TCPS_SYN_SENT:
		tcp_xmit_out(txr, m, so, TCP_FLAG_SYN, 0, 0);
		return 1;
	case TCPS_SYN_RECEIVED:
		tcp_xmit_out(txr, m, so, TCP_FLAG_SYN|TCP_FLAG_ACK, 0, 0);
		return 1;
	default:
		rc = tcp_xmit_established(txr, m, so);
		if (rc == 0) {
			if (so->ack) {
				so->ack = 0;
				tcp_xmit_out(txr, m, so, TCP_FLAG_ACK, 0, 0);
			}
			return 1;
		} else {
			so->ack = 0;
			return 0;
		}
	}
}

void
toy_flush()
{
	int rc;
	struct netmap_ring *txr;
	struct netmap_slot *m;
	struct sock *so;

	while (!dlist_is_empty(&current->t_so_txq)) {
		so = DLIST_FIRST(&current->t_so_txq, struct sock, tx_list);
		while (1) {
			txr = not_empty_txr(&m);
			if (txr == NULL) {
				return;
			}
			DEV_PREFETCH(txr);
			rc = tcp_xmit(txr, m, so);
			if (rc) {
				break;
			}
		}
		tcp_del_sndq(so);
		if (so->closed) {
			tcp_close(so);
		}
	}
}

static int
tcp_process_dupack(struct sock *so)
{
	if (so->state >= TCPS_ESTABLISHED) {
		counter64_inc(&tcpstat.tcps_rcvduppack);
		so->ssnt = 0;
	} else {
		tcp_into_rstq(so);
		tcp_close(so);
	}
	return -1;
}

static int
tcp_enter_TIME_WAIT(struct sock *so)
{
	tcp_set_state(so, TCPS_TIME_WAIT);
	// TODO: Wait 2MSL - optionaly
	tcp_close(so);
	return -1;
}

static int
tcp_process_ack(struct sock *so, struct tcb *tcb)
{
	uint32_t acked;

	acked = diff_seq(so->sack, tcb->tcb_ack);
	if (acked == 0) {
		return 0;
	}
	if (so->ssyn && so->ssyn_acked == 0) {
		acked--;
	}
	if (acked > so->ssnt) {
		if (so->sfin) {
			acked--;
		}
		if (acked > so->ssnt) {
			return tcp_process_dupack(so);
		}
	}
	if (so->state == TCPS_SYN_RECEIVED) {
		tcp_set_state(so, TCPS_ESTABLISHED);
	}
	if (so->ssyn && so->ssyn_acked == 0) {
		so->ssyn_acked = 1;
		so->sack++;
	}
	if (acked == so->ssnt) {
		so->so_rexmit = 0;
		so->nr_tries = 0;
		timer_cancel(&so->timer);
		so->nagle_acked = 1;
		if (so->sfin && so->sfin_acked == 0) {
			so->sfin_acked = 1;
			switch (so->state) {
			case TCPS_FIN_WAIT_1:
				tcp_set_state(so, TCPS_FIN_WAIT_2);
				break;
			case TCPS_CLOSING:
				if (tcp_enter_TIME_WAIT(so)) {
					return -1;
				}
				break;
			case TCPS_LAST_ACK:
				tcp_close(so);
				return -1;
			default:
				assert(0);
				break;
			}
		}
	}
	so->sack += acked;
	so->ssnt -= acked;
	so->spos += acked;
	return 0;
}

static int
tcp_is_in_order(struct sock *so, struct tcb *tcb)
{
	uint32_t len, off;

	len = tcb->tcb_len;
	if (tcb->tcb_flags & (TCP_FLAG_SYN|TCP_FLAG_FIN)) {
		len++;
	}
	off = diff_seq(tcb->tcb_seq, so->rseq);
	if (off > len) {
		return 0;
	} else {
		return 1;
	}
}

static void
tcp_set_risn(struct sock *so, uint32_t seq)
{
	so->rsyn = 1;
	so->rseq = seq + 1;
}

static void
tcp_delack(struct sock *so)
{
	if (timer_is_running(&so->timer_delack)) {
		timer_cancel(&so->timer_delack);
		tcp_into_ackq(so);
	}
	timer_set(&so->timer_delack, 100 * NANOSECONDS_MILLISECOND,
	          tcp_timeout_delack);
}

static void
tcp_rcv_syn_sent(struct sock *so, struct tcb *tcb)
{
	switch (tcb->tcb_flags) {
	case TCP_FLAG_SYN|TCP_FLAG_ACK:
		tcp_set_state(so, TCPS_ESTABLISHED);
		so->ack = 1;
		break;
	case TCP_FLAG_SYN:
		tcp_set_state(so, TCPS_SYN_RECEIVED);
		break;
	default:
		return;
	}
	tcp_set_risn(so, tcb->tcb_seq);
	tcp_into_sndq(so);
}

static void
tcp_rcv_data(struct sock *so, struct tcb *tcb, void *payload)
{
	uint32_t n, off;

	off = diff_seq(tcb->tcb_seq, so->rseq);
	n = tcb->tcb_len - off;
	if (off == 0) {
		counter64_inc(&tcpstat.tcps_rcvpack);
		counter64_add(&tcpstat.tcps_rcvbyte, tcb->tcb_len);
	} else if (off == tcb->tcb_len) {
		counter64_inc(&tcpstat.tcps_rcvduppack);
		counter64_add(&tcpstat.tcps_rcvdupbyte, tcb->tcb_len);
	} else if (off > tcb->tcb_len) {
		counter64_inc(&tcpstat.tcps_pawsdrop);
		return;
	} else {
		counter64_inc(&tcpstat.tcps_rcvpartduppack);
		counter64_add(&tcpstat.tcps_rcvpartdupbyte, n);
	}
	tcp_on_rcv(so, payload, n);
	so->rseq += n;
	tcp_delack(so);
}

static void
tcp_rcv_established(struct sock *so, struct tcb *tcb, void *payload)
{
	assert(so->state >= TCPS_ESTABLISHED);
	if (so->rfin) {
		if (tcb->tcb_len || (tcb->tcb_flags & TCP_FLAG_FIN)) {
			tcp_into_ackq(so);
		}
		return;
	}
	if (tcb->tcb_len) {
		tcp_rcv_data(so, tcb, payload);
	}
	if (tcb->tcb_flags & TCP_FLAG_SYN) {
		tcp_into_ackq(so);
	}
	if (tcb->tcb_flags & TCP_FLAG_FIN) {
		so->rfin = 1;
		so->rseq++;
		tcp_into_ackq(so);
		tcp_on_rcv(so, NULL, -1);
		switch (so->state) {
		case TCPS_ESTABLISHED:
			tcp_set_state(so, TCPS_LAST_ACK);
			break;
		case TCPS_FIN_WAIT_1:
			tcp_set_state(so, TCPS_CLOSING);
			break;
		case TCPS_FIN_WAIT_2:
			if (tcp_enter_TIME_WAIT(so)) {
				return;
			}
			break;
		}
	}
}

static void
tcp_rcv_open(struct sock *so, struct tcb *tcb, void *payload)
{
	if (tcb->tcb_flags & TCP_FLAG_RST) {
		// TODO: check seq
		if (so->state < TCPS_ESTABLISHED) {
			counter64_inc(&tcpstat.tcps_conndrops);
		} else {
			counter64_inc(&tcpstat.tcps_drops);
		}
		tcp_close(so);
		return;
	}
	if (so->rsyn) {
		if (!tcp_is_in_order(so, tcb)) {
			counter64_inc(&tcpstat.tcps_rcvoopack);
			tcp_into_ackq(so);
			return;
		}
	}
	if (tcb->tcb_flags & TCP_FLAG_ACK) {
		if (tcp_process_ack(so, tcb)) {
			return;
		}
		so->rwnd = tcb->tcb_win;
		so->rwnd_max = MAX(so->rwnd_max, so->rwnd);
	}
	switch (so->state) {
	case TCPS_CLOSED:
	case TCPS_LISTEN:
		assert(0);
		return;
	case TCPS_SYN_SENT:
		tcp_rcv_syn_sent(so, tcb);
		return;
	case TCPS_SYN_RECEIVED:
		break;
	default:
		assert(so->rsyn);
		tcp_rcv_established(so, tcb, payload);
		break;
	}
	if (so->sfin_acked == 0) {
		tcp_into_sndq(so);
	}
}

static void
tcp_rcv_syn(be32_t laddr, be32_t faddr, be16_t lport, be16_t fport,
	struct tcb *tcb)
{
	uint32_t h;
	struct sock *so;

	so = tcp_open();
	if (so == NULL) {
		return;
	}
	so->so_laddr = laddr;
	so->so_faddr = faddr;
	so->so_lport = lport;
	so->so_fport = fport;
	h = SO_HASH(so->so_faddr, so->so_lport, so->so_fport);
	htable_add(&current->t_in_htable, &so->so_list, h);
	set_isn(so, h);
	tcp_set_risn(so, tcb->tcb_seq);
	tcp_set_state(so, TCPS_SYN_RECEIVED);
	tcp_into_sndq(so);
}

static int
tcp_rcv_closed(be32_t laddr, be32_t faddr, be16_t lport, be16_t fport,
	struct tcb *tcb)
{
	uint32_t x;

	if (current->t_Lflag == 0) {
		return IN_BYPASS;
	}
	x = ntohl(laddr);
	if (current->t_ip_laddr_min != 0) {
		if (x < current->t_ip_laddr_min ||
		    x > current->t_ip_laddr_max) {
			return IN_BYPASS;
		}
	}
	if (lport != current->t_port) {
		return IN_BYPASS;
	}
	if (tcb->tcb_flags == TCP_FLAG_SYN) {
		counter64_inc(&tcpstat.tcps_accepts);
		tcp_rcv_syn(laddr, faddr, lport, fport, tcb);
	} else {
		counter64_inc(&tcpstat.tcps_badsyn);
	}
	return IN_OK;
}

int
toy_eth_in(void *data, int len)
{
	int rc;
	be32_t laddr, faddr;
	be16_t lport, fport;
	struct inet_parser p;
	struct sock *so;

	counter64_inc(&if_ipackets);
	counter64_add(&if_ibytes, len);
	inet_parser_init(&p, data, len);
	rc = eth_in(&p);
	if (rc != IN_OK) {
		return rc;
	}
	if (p.inp_ipproto != IPPROTO_TCP) {
		return IN_BYPASS;
	}
	counter64_inc(&tcpstat.tcps_rcvtotal);
	laddr = p.inp_ih->ih_daddr;
	faddr = p.inp_ih->ih_saddr;
	lport = p.inp_th->th_dport;
	fport = p.inp_th->th_sport;
	so = tcp_get(laddr, faddr, lport, fport);
	if (so == NULL) {
		rc = tcp_rcv_closed(laddr, faddr, lport, fport, &p.inp_tcb);
		return rc;
	}
	switch (so->state) {
	case TCPS_CLOSED:
	case TCPS_LISTEN:
		assert(0);
		return IN_DROP;
	case TCPS_TIME_WAIT:
		// TODO:
		//tcp_process_TIME_WAIT(so);
		return IN_OK;
	default:
		tcp_rcv_open(so, &p.inp_tcb, p.inp_payload);
		return IN_OK;
	}
}

static void
tcp_timeout_rexmit(struct timer *timer)
{
	struct sock *so;

	so = container_of(timer, struct sock, timer);
	assert(so->used);
	assert(so->sfin_acked == 0);
	assert(TCP_IS_REXMIT(so));
	counter64_inc(&tcpstat.tcps_rexmttimeo);
	so->ssnt = 0;
	so->sfin_sent = 0;
	so->so_rexmited = 1;
	if (so->nr_tries++ > 6) {
		counter64_inc(&tcpstat.tcps_timeoutdrop);
		tcp_close(so);
		return;
	}
	tcp_into_sndq(so);
}

static void
tcp_timeout_delack(struct timer *timer)
{
	struct sock *so;

	so = container_of(timer, struct sock, timer_delack);
	assert(so->used);
	counter64_inc(&tcpstat.tcps_delack);
	tcp_into_ackq(so);
}

static void
tcp_timeout_probe(struct timer *timer)
{
	struct sock *so;

	so = container_of(timer, struct sock, timer);
	assert(so->used);
	assert(so->sfin_acked == 0);
	assert(TCP_IS_REXMIT(so) == 0);
	assert(so->probe);
	counter64_inc(&tcpstat.tcps_persisttimeo);
	if (so->nr_tries < 7) {
		so->nr_tries++;
	}
	tcp_into_ackq(so);
	assert(tcp_timer_set_probe(so));
}
