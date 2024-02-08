#include "socket.h"
#include "tcp_var.h"

struct conn {
	u_char cn_sent;
	u_char cn_http;
};

static void udp_client(struct cg_task *, struct socket *, short, struct sockaddr_in *,
		void *, int);
static void tcp_client(struct cg_task *, struct socket *, short, struct sockaddr_in *,
		void *, int);
static void tcp_server(struct cg_task *, struct socket *, short, struct sockaddr_in *,
		void *, int);
static void con_close(struct cg_task *t);

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
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_output_real(t, sototcpcb(so));
			if (rc <= 0) {
				DLIST_REMOVE(so, so_txlist);
				so->so_state &= ~SS_ISTXPENDING;
				sofree(t, so);
			}
		} else {
//			DLIST_REMOVE(so, so_txlist);
			sosend(t, so, "xx", 2, NULL, 0);
//			so->so_state &= ~SS_ISTXPENDING;

//			bsd_close(so);
//			con_close();
		}
	}
}

void
bsd_client_connect(struct cg_task *t, int proto)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(t, proto, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	so->so_userfn = proto == IPPROTO_TCP ? tcp_client : udp_client;
	so->so_user = 0;
	if (t->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	rc = bsd_connect(t, so);
	if (rc < 0) {
		panic(-rc, "bsd_connect() failed");
	}
	if (proto == IPPROTO_UDP) {
		DLIST_INSERT_TAIL(&t->t_so_txq, so, so_txlist);
	}
}

static void
srv_accept(struct cg_task *t, struct socket *so, short events, struct sockaddr_in *addr,
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

void
bsd_server_listen(struct cg_task *t, int proto)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(t, proto, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	if (t->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	assert(proto == IPPROTO_TCP);
	so->so_userfn = srv_accept;
	so->so_user = 0;
	rc = bsd_bind(t, so, t->t_port);
	if (rc) {
		panic(-rc, "bsd_bind(%u) failed", ntohs(t->t_port));
	}
	if (proto == IPPROTO_TCP) {
		rc = bsd_listen(so);
		if (rc) {
			panic(-rc, "bsd_listen() failed");
		}
	}
}

extern int g_udp;

static void
con_close(struct cg_task *t)
{
	int proto;

	proto = IPPROTO_TCP;

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
			bsd_client_connect(t, proto);
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
udp_client(struct cg_task *t, struct socket *so, short events, struct sockaddr_in *addr,
		void *dat, int len)
{
	//if (events & POLLNVAL) {
	//	con_close();
	//}
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
