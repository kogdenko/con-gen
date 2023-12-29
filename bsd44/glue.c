#include "../global.h"
#include "socket.h"
#include "tcp_var.h"
#include "netstat.h"

#define INIT_STAT(s) \
	init_counters((counter64_t *)&s, sizeof(s)/sizeof(counter64_t))

struct conn {
	u_char cn_sent;
	u_char cn_http;
};

static void tcp_client(struct socket *, short, struct sockaddr_in *, void *, int);
static void tcp_server(struct socket *, short, struct sockaddr_in *, void *, int);
static void con_close(void);
static void bsd_server_listen(int);
static void bsd_client_connect(int proto);



struct udpstat udpstat;
struct tcpstat tcpstat;
struct ipstat ipstat;
struct icmpstat icmpstat;

static void
init_counters(counter64_t *a, int n)
{
	int i;

	for (i = 0; i < n; ++i) {
		counter64_init(a + i);
	}
}

void
congen_plugin_init(void)
{
	INIT_STAT(udpstat);
	INIT_STAT(tcpstat);
	INIT_STAT(ipstat);
	INIT_STAT(icmpstat);
}

void
congen_plugin_current_init(void)
{
	current->t_tcp_now = 1;
	current->t_tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;
	if (current->t_Lflag) {
		bsd_server_listen(IPPROTO_TCP);
	} else {
		bsd_client_connect(IPPROTO_TCP);
	}
}

void
congen_plugin_command(int command, FILE *out, int verbose)
{
	switch (command) {
	case 's':
		print_stats(out, verbose);
		break;

	case 'c':
		print_sockets(out);
		break;
	}
}

void
congen_plugin_update(uint64_t tsc)
{
	uint64_t age;

	age = current->t_tcp_nowage + NANOSECONDS_SECOND/PR_SLOWHZ;
	if (current->t_time >= age) {
		current->t_tcp_now++;
		current->t_tcp_nowage += NANOSECONDS_SECOND/PR_SLOWHZ;
	}
}

void
congen_plugin_flush(void)
{
	int rc;
	struct socket *so;

	while (!cg_dlist_is_empty(&current->t_so_txq)) {
		so = CG_DLIST_FIRST(&current->t_so_txq, struct socket, so_txlist);
		if (io_is_tx_throttled()) {
			break;
		}
		rc = tcp_output_real(sototcpcb(so));
		if (rc <= 0) {
			CG_DLIST_REMOVE(so, so_txlist);
			so->so_state &= ~SS_ISTXPENDING;
			sofree(so);
		}
	}
}

static void
bsd_client_connect(int proto)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(proto, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	so->so_userfn = tcp_client;
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

static void
bsd_server_listen(int proto)
{
	int rc;
	struct socket *so;

	rc = bsd_socket(IPPROTO_TCP, &so);
	if (rc < 0) {
		panic(-rc, "bsd_socket() failed");
	}
	if (current->t_so_debug) {
		sosetopt(so, SO_DEBUG);
	}
	so->so_userfn = srv_accept;
	so->so_user = 0;
	rc = bsd_bind(so, current->t_port);
	if (rc) {
		panic(-rc, "bsd_bind(%u) failed", ntohs(current->t_port));
	}
	rc = bsd_listen(so);
	if (rc) {
		panic(-rc, "bsd_listen() failed");
	}
}

static void
con_close(void)
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
			bsd_client_connect(IPPROTO_TCP);
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
