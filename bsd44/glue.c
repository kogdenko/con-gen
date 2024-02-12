#include "socket.h"
#include "tcp_var.h"

struct conn {
	u_char cn_sent;
	u_char cn_http;
};

static void tcp_client(struct cg_task *, struct socket *, short, struct sockaddr_in *,
		void *, int);
static void tcp_server(struct cg_task *, struct socket *, short, struct sockaddr_in *,
		void *, int);
static void con_close(struct cg_task *);

static char http_request[1500];
static char http_reply[1500];
static int http_request_len;
static int http_reply_len;


void
bsd_init(void)
{
	int rc;
	char hostname[64];

	rc = gethostname(hostname, sizeof(hostname));
	if (rc == -1) {
		fprintf(stderr, "gethostname() failed (%s)\n", strerror(errno));
		strcpy(hostname, "127.0.0.1");
	} else {
		hostname[sizeof(hostname) - 1] = '\0';
	}

	http_request_len = snprintf(http_request, sizeof(http_request),
		"GET / HTTP/1.0\r\n"
		"Host: %s\r\n"
		"User-Agent: con-gen\r\n"
		"\r\n",
		hostname);

	http_reply_len = snprintf(http_reply, sizeof(http_reply), 
		"HTTP/1.0 200 OK\r\n"
		"Server: con-gen\r\n"
		"Content-Type: text/html\r\n"
		"Connection: close\r\n"
		"Hi\r\n\r\n");

}

//void
//bsd_set_option()
//{
//
//}

void
bsd_flush(struct cg_task *tb)
{
	int rc;
	struct socket *so;
	struct cg_bsd_task *t;

	t = cg_bsd_get_task(tb);

	while (!dlist_is_empty(&t->t_so_txq)) {
		so = DLIST_FIRST(&t->t_so_txq, struct socket, so_txlist);
		if (io_is_tx_throttled(tb)) {
			break;
		}

		rc = tcp_output_real(tb, sototcpcb(so));
		if (rc <= 0) {
			DLIST_REMOVE(so, so_txlist);
			so->so_state &= ~SS_ISTXPENDING;
			sofree(tb, so);
		}
	}
}

static void
cg_bsd_client_start(struct cg_task *tb)
{
	int rc;
	struct socket *so;
	struct cg_bsd_task *t;

	t = cg_bsd_get_task(tb);

	rc = bsd_socket(tb, IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}

	so->so_userfn = tcp_client;
	so->so_user = 0;

	if (t->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}

	rc = bsd_connect(tb, so);
	if (rc < 0) {
		panic(-rc, "bsd_connect() failed");
	}
}

static void
cg_bsd_server_accept(struct cg_task *tb, struct socket *so, short events, struct sockaddr_in *addr,
		void *dat, int len)
{
	int rc;
	struct socket *aso;

	do {
		rc = bsd_accept(so, &aso);
		if (rc == 0) {
			aso->so_user = 0;
			aso->so_userfn = tcp_server;
		}
	} while (rc != -EWOULDBLOCK);
}

static void
cg_bsd_server_start(struct cg_task *tb)
{
	int rc;
	struct socket *so;
	struct cg_bsd_task *t;

	t = cg_bsd_get_task(tb);

	rc = bsd_socket(tb, IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}

	if (t->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}

	so->so_userfn = cg_bsd_server_accept;
	so->so_user = 0;

	rc = bsd_bind(tb, so, tb->t_port);
	if (rc) {
		panic(-rc, "bsd_bind(%u) failed", ntohs(tb->t_port));
	}

	rc = bsd_listen(so);
	if (rc) {
		panic(-rc, "bsd_listen() failed");
	}
}

static void
con_close(struct cg_task *tb)
{
	struct cg_bsd_task *t;

	t = cg_bsd_get_task(tb);

	if (tb->t_done) {
		return;
	}

	t->t_n_requests++;
	if (t->t_nflag) {
		if (t->t_n_requests == t->t_nflag) {
			tb->t_done = 1;
			return;
		}
	}

	if (!tb->t_Lflag) {
		while (tb->t_n_conns < tb->t_concurrency) {
			cg_bsd_client_start(tb);
		}
	}
}

static void
conn_sendto(struct cg_task *tb, struct socket *so)
{
	int rc;
	char lb[INET_ADDRSTRLEN];
	char fb[INET_ADDRSTRLEN];
	struct cg_bsd_task *t;

	t = cg_bsd_get_task(tb);

	rc = bsd_sendto(tb, so, t->t_http, t->t_http_len, MSG_NOSIGNAL, NULL);
	if (rc == t->t_http_len) {
		return;
	} else if (rc > 0) {
		rc = 0;
	}
	panic(-rc, "bsd_sendto() failed, %s:%hu->%s:%hu",
			inet_ntop(AF_INET, &so->so_base.ipso_laddr, lb, sizeof(lb)),
			ntohs(so->so_base.ipso_lport),
			inet_ntop(AF_INET, &so->so_base.ipso_faddr, fb, sizeof(fb)),
			ntohs(so->so_base.ipso_fport));
}

static void
tcp_client(struct cg_task *tb, struct socket *so, short events, struct sockaddr_in *addr,
		void *dat, int len)
{
	int rc;
	char fb[INET_ADDRSTRLEN];
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close(tb);
		return;
	}
	if (cp->cn_sent == 0) {
		if (events & POLLERR) {
			panic(so->so_error, "Couldn't connect to %s:%hu",
				inet_ntop(AF_INET, &so->so_base.ipso_faddr, fb, sizeof(fb)),
				ntohs(so->so_base.ipso_fport));
		}
		if (events|POLLOUT) {
			cp->cn_sent = 1;
			conn_sendto(tb, so);
		}
	} else {
		if (events & POLLERR) {
			bsd_close(tb, so);
			return;
		}
	}
	if (events & POLLIN) {
		if (len) {
			rc = parse_http(dat, len, &cp->cn_http);
			if (rc) {
				bsd_close(tb, so);
				return;
			}
		} else {
			bsd_close(tb, so);
			return;
		}
	}
}

static void
tcp_server(struct cg_task *tb, struct socket *so, short events, struct sockaddr_in *addr,
		void *dat, int len)
{
	int rc;
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close(tb);
		return;
	}
	if (len) {
		rc = parse_http(dat, len, &cp->cn_http);
		if (rc) {
			conn_sendto(tb, so);
			bsd_close(tb, so);
		}
	} else if (events & (POLLERR|POLLIN)) {
		bsd_close(tb, so);
	}
}


void
bsd_start(struct cg_task *tb)
{
	struct cg_bsd_task *t;

	t = cg_bsd_get_task(tb);

	t->t_tcp_now = 1;
	t->t_tcp_nowage = tb->t_time;

	if (tb->t_Lflag) {
		t->t_http = http_reply;
		t->t_http_len = http_reply_len;
	} else {
		t->t_http = http_request;
		t->t_http_len = http_request_len;
	}

	if (tb->t_Lflag) {
		cg_bsd_server_start(tb);
	} else {
		cg_bsd_client_start(tb);
	}
}

void
bsd_update(struct cg_task *tb)
{
	struct cg_bsd_task *t;
	uint64_t age;

	t = cg_bsd_get_task(tb);

	age = t->t_tcp_nowage + NANOSECONDS_SECOND/PR_SLOWHZ;
	if (tb->t_time >= age) {
		t->t_tcp_now++;
		t->t_tcp_nowage += NANOSECONDS_SECOND/PR_SLOWHZ;
	}
}

struct cg_task *
bsd_alloc_task(struct cg_task *tmplb)
{
	struct cg_bsd_task *t, *tmpl;

	t = xmalloc(sizeof(*t));
	memset(t, 0, sizeof(*t));

	t->t_tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;
	dlist_init(&t->t_so_txq);
	dlist_init(&t->t_so_pool);
	dlist_init(&t->t_sob_pool);

	if (tmplb == NULL) {
		t->t_tcp_do_wscale = 1;
		t->t_tcp_do_timestamps = 1;
		t->t_tcp_fintimo = 60 * NANOSECONDS_SECOND;

	} else {
		tmpl = cg_bsd_get_task(tmplb);

		t->t_nflag = tmpl->t_nflag;
		t->t_so_debug = tmpl->t_so_debug;
		t->t_tcp_do_wscale = tmpl->t_tcp_do_wscale;
		t->t_tcp_do_timestamps = tmpl->t_tcp_do_wscale;
		t->t_tcp_twtimo = tmpl->t_tcp_twtimo;
		t->t_tcp_fintimo = tmpl->t_tcp_fintimo;
	}

	return &t->t_base;
}

