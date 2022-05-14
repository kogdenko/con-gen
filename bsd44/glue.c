#include "socket.h"
#include "tcp_var.h"

struct conn {
	u_char cn_sent;
	u_char cn_http;
};

static void client(struct socket *, short, struct sockaddr_in *, void *, int);
static void server(struct socket *, short, struct sockaddr_in *, void *, int);

void
bsd_flush()
{
	int rc;
	struct socket *so;

	while (!dlist_is_empty(&current->t_so_txq)) {
		so = DLIST_FIRST(&current->t_so_txq, struct socket, so_txlist);
		if (not_empty_txr(NULL) == NULL) {
			break;
		}
		rc = tcp_output_real(sototcpcb(so));
		if (rc <= 0) {
			DLIST_REMOVE(so, so_txlist);
			so->so_state &= ~SS_ISTXPENDING;
			sofree(so);
		}
	}
}

void
bsd_client_connect()
{
	int rc;
	struct socket *so;

	rc = bsd_socket(IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	so->so_userfn = client;
	so->so_user = 0;
	if (current->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	rc = bsd_connect(so);
	if (rc < 0) {
		panic(-rc, "bsd_connect() failed");
	}
}

static void
udp_echo(struct socket *so, short events, struct sockaddr_in *addr,
	void *dat, int len)
{
	bsd_sendto(so, dat, len, MSG_NOSIGNAL, addr);
}

static void
srv_accept(struct socket *so, short events,
           struct sockaddr_in *addr, void *dat, int len)
{
	int rc;
	struct socket *aso;

	do {
		rc = bsd_accept(so, &aso);
		if (rc == 0) {
			aso->so_user = 0;
			aso->so_userfn = server;
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
	so->so_userfn = proto == IPPROTO_TCP ? srv_accept : udp_echo;
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

static void
con_close()
{
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
			bsd_client_connect();
		}
	}
}

static void
conn_sendto(struct socket *so)
{
	int rc;
	char lb[INET_ADDRSTRLEN];
	char fb[INET_ADDRSTRLEN];

	rc = bsd_sendto(so, current->t_http, current->t_http_len,
		MSG_NOSIGNAL, NULL);
	if (rc == current->t_http_len) {
		return;
	} else if (rc > 0) {
		rc = 0;
	}
//	print_stats(stdout, 1);
	panic(-rc, "bsd_sendto() failed; %s:%hu->%s:%hu",
		inet_ntop(AF_INET, &so->so_base.ipso_laddr, lb, sizeof(lb)),
		ntohs(so->so_base.ipso_lport),
		inet_ntop(AF_INET, &so->so_base.ipso_faddr, fb, sizeof(fb)),
		ntohs(so->so_base.ipso_fport));
}

static void
client(struct socket *so, short events, struct sockaddr_in *addr,
	void *dat, int len)
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
			panic(so->so_error, "Could't connect to %s:%hu",
				inet_ntop(AF_INET, &so->so_base.ipso_faddr,
					fb, sizeof(fb)),
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
server(struct socket *so, short events, struct sockaddr_in *addr,
	void *dat, int len)
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
