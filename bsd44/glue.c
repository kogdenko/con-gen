#include "socket.h"
#include "tcp_var.h"

struct conn {
	u_char cn_sent;
	u_char cn_http;
};

static int nclients;
static int connections;

static void client(struct socket *, short, struct sockaddr_in *, void *, int);
static void server(struct socket *, short, struct sockaddr_in *, void *, int);

void
bsd_flush()
{
	int rc;
	struct socket *so;

	while (!dlist_is_empty(&so_txq)) {
		so = DLIST_FIRST(&so_txq, struct socket, so_txlist);
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
	uint32_t faddr;
	struct sockaddr_in addr;
	struct socket *so;

	rc = bsd_socket(IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	so->so_userfn = client;
	so->so_user = 0;
	if (so_debug_flag) {
		sosetopt(so, SO_DEBUG);
	}
	faddr = select_faddr();
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(faddr);
	addr.sin_port = pflag_port;
	rc = bsd_connect(so, &addr);
	if (rc < 0) {
		panic(-rc, "bsd_connect() failed");
	}
	nclients++;
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
	if (so_debug_flag) {
		sosetopt(so, SO_DEBUG);
	}
	so->so_userfn = proto == IPPROTO_TCP ? srv_accept : udp_echo;
	so->so_user = 0;
	rc = bsd_bind(so, pflag_port);
	if (rc) {
		panic(-rc, "bsd_bind(%u) failed", ntohs(pflag_port));
	}
	if (proto == IPPROTO_TCP) {
		rc = bsd_listen(so);
		if (rc) {
			panic(-rc, "bsd_listen() failed");
		}
	}
}

static void
con_close(int is_client)
{
	if (done) {
		return;
	}
	connections++;
	if (nflag) {
		if (connections == nflag) {
			done = 1;
			return;
		}
	}
	if (is_client) {
		nclients--;
		while (nclients < concurrency) {
			bsd_client_connect();
		}
	}
}

static void
conn_sendto(struct socket *so)
{
	int rc;

	rc = bsd_sendto(so, http, http_len, MSG_NOSIGNAL, NULL);
	if (rc < 0) {
		panic(-rc, "bsd_sendto() failed");
	} else if (rc != http_len) {
		panic(0, "bsd_sendto() stalled");
	}

}

static void
client(struct socket *so, short events, struct sockaddr_in *addr,
	void *dat, int len)
{
	int rc;
	struct conn *cp;

	cp = (struct conn *)&so->so_user;
	if (events & POLLNVAL) {
		con_close(1);
		return;
	}
	if (cp->cn_sent == 0) {
		if (events & POLLERR) {
			panic(so->so_error, "cant connect");
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
		con_close(0);
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


