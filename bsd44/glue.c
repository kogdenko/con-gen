#include "socket.h"
#include "tcp_var.h"

struct conn {
	u_char cn_sent;
	u_char cn_http;
};

static void udp_client(struct socket *, short, struct sockaddr_in *, void *, int);
static void tcp_client(struct socket *, short, struct sockaddr_in *, void *, int);
static void tcp_server(struct socket *, short, struct sockaddr_in *, void *, int);
static void con_close(void);

void
bsd_flush(void)
{
	int rc;
	struct socket *so;

	while (!dlist_is_empty(&current->t_so_txq)) {
		so = DLIST_FIRST(&current->t_so_txq, struct socket, so_txlist);
		if (io_is_tx_throttled()) {
			break;
		}
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_output_real(sototcpcb(so));
			if (rc <= 0) {
				DLIST_REMOVE(so, so_txlist);
				so->so_state &= ~SS_ISTXPENDING;
				sofree(so);
			}
		} else {
//			DLIST_REMOVE(so, so_txlist);
			sosend(so, "xx", 2, NULL, 0);
//			so->so_state &= ~SS_ISTXPENDING;

//			bsd_close(so);
//			con_close();
		}
	}
}

void
bsd_client_connect(int proto)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(proto, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	so->so_userfn = proto == IPPROTO_TCP ? tcp_client : udp_client;
	so->so_user = 0;
	if (current->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	rc = bsd_connect(so);
	if (rc < 0) {
		panic(-rc, "bsd_connect() failed");
	}
	if (proto == IPPROTO_UDP) {
		DLIST_INSERT_TAIL(&current->t_so_txq, so, so_txlist);
	}
}

static void
srv_accept(struct socket *so, short events, struct sockaddr_in *addr, void *dat, int len)
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
bsd_server_listen(int proto)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(proto, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	if (current->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	assert(proto == IPPROTO_TCP);
	so->so_userfn = srv_accept;
	so->so_user = 0;
	rc = bsd_bind(so, current->t_port);
	if (rc) {
		panic(-rc, "bsd_bind(%u) failed", ntohs(current->t_port));
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
con_close(void)
{
	int proto;

	proto = g_udp ? IPPROTO_UDP : IPPROTO_TCP;

	if (current->t_done) {
		return;
	}
	current->t_n_requests++;
	if (current->t_nflag) {
		if (current->t_n_requests == current->t_nflag) {
			current->t_done = 1;
			return;
		}
	}
	if (!current->t_Lflag) {
		while (current->t_n_conns < current->t_concurrency) {
			bsd_client_connect(proto);
		}
	}
}

static void
conn_sendto(struct socket *so)
{
	int rc;
	char lb[INET_ADDRSTRLEN];
	char fb[INET_ADDRSTRLEN];

	rc = bsd_sendto(so, current->t_http, current->t_http_len, MSG_NOSIGNAL, NULL);
	if (rc == current->t_http_len) {
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
tcp_client(struct socket *so, short events, struct sockaddr_in *addr, void *dat, int len)
{
	int rc;
	char fb[INET_ADDRSTRLEN];
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close();
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
			conn_sendto(so);
		}
	} else {
		if (events & POLLERR) {
			bsd_close(so);
			return;
		}
	}
	if (events & POLLIN) {
		if (len) {
			rc = parse_http(dat, len, &cp->cn_http);
			if (rc) {
				bsd_close(so);
				return;
			}
		} else {
			bsd_close(so);
			return;
		}
	}
}

static void
udp_client(struct socket *so, short events, struct sockaddr_in *addr, void *dat, int len)
{
	//if (events & POLLNVAL) {
	//	con_close();
	//}
}

static void
tcp_server(struct socket *so, short events, struct sockaddr_in *addr, void *dat, int len)
{
	int rc;
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close();
		return;
	}
	if (len) {
		rc = parse_http(dat, len, &cp->cn_http);
		if (rc) {
			conn_sendto(so);
			bsd_close(so);
		}
	} else if (events & (POLLERR|POLLIN)) {
		bsd_close(so);
	}
}
