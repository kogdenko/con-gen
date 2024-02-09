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
static void con_close(struct cg_task *t);

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
bsd_flush(struct cg_task *t)
{
	int rc;
	struct socket *so;

	while (!dlist_is_empty(&t->t_so_txq)) {
		so = DLIST_FIRST(&t->t_so_txq, struct socket, so_txlist);
		if (io_is_tx_throttled(t)) {
			break;
		}

		rc = tcp_output_real(t, sototcpcb(so));
		if (rc <= 0) {
			DLIST_REMOVE(so, so_txlist);
			so->so_state &= ~SS_ISTXPENDING;
			sofree(t, so);
		}
	}
}

static void
cg_bsd_client_start(struct cg_task *t)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(t, IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	so->so_userfn = tcp_client;
	so->so_user = 0;
	if (t->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	rc = bsd_connect(t, so);
	if (rc < 0) {
		panic(-rc, "bsd_connect() failed");
	}
}

static void
cg_bsd_server_accept(struct cg_task *t, struct socket *so, short events, struct sockaddr_in *addr,
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
cg_bsd_server_start(struct cg_task *t)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(t, IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	if (t->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	so->so_userfn = cg_bsd_server_accept;
	so->so_user = 0;
	rc = bsd_bind(t, so, t->t_port);
	if (rc) {
		panic(-rc, "bsd_bind(%u) failed", ntohs(t->t_port));
	}
	rc = bsd_listen(so);
	if (rc) {
		panic(-rc, "bsd_listen() failed");
	}
}

static void
con_close(struct cg_task *t)
{
	if (t->t_done) {
		return;
	}

	t->t_n_requests++;
	if (t->t_nflag) {
		if (t->t_n_requests == t->t_nflag) {
			t->t_done = 1;
			return;
		}
	}

	if (!t->t_Lflag) {
		while (t->t_n_conns < t->t_concurrency) {
			cg_bsd_client_start(t);
		}
	}
}

static void
conn_sendto(struct cg_task *t, struct socket *so)
{
	int rc;
	char lb[INET_ADDRSTRLEN];
	char fb[INET_ADDRSTRLEN];

	rc = bsd_sendto(t, so, t->t_http, t->t_http_len, MSG_NOSIGNAL, NULL);
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
tcp_client(struct cg_task *t, struct socket *so, short events, struct sockaddr_in *addr,
		void *dat, int len)
{
	int rc;
	char fb[INET_ADDRSTRLEN];
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close(t);
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
			conn_sendto(t, so);
		}
	} else {
		if (events & POLLERR) {
			bsd_close(t, so);
			return;
		}
	}
	if (events & POLLIN) {
		if (len) {
			rc = parse_http(dat, len, &cp->cn_http);
			if (rc) {
				bsd_close(t, so);
				return;
			}
		} else {
			bsd_close(t, so);
			return;
		}
	}
}

static void
tcp_server(struct cg_task *t, struct socket *so, short events, struct sockaddr_in *addr,
		void *dat, int len)
{
	int rc;
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close(t);
		return;
	}
	if (len) {
		rc = parse_http(dat, len, &cp->cn_http);
		if (rc) {
			conn_sendto(t, so);
			bsd_close(t, so);
		}
	} else if (events & (POLLERR|POLLIN)) {
		bsd_close(t, so);
	}
}

#define cg_bsd_get_task(t) containter_of(t, struct cg_bsd_task, t_base)

void
bsd_start(struct cg_task *t)
{
//	struct cg_bsd_task *t;

//	t = cg_bsg_get_task(t_);

	if (t->t_Lflag) {
		t->t_http = http_reply;
		t->t_http_len = http_reply_len;
	} else {
		t->t_http = http_request;
		t->t_http_len = http_request_len;
	}

	if (t->t_Lflag) {
		cg_bsd_server_start(t);
	} else {
		cg_bsd_client_start(t);
	}
}


