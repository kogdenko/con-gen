/*
 * Copyright (c) 1982, 1986, 1991, 1993
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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "udp_var.h"
#include "../gbtcp/htable.h"


static uint32_t in_secret;
static be32_t in_ephip;
static int in_ephipcnt;
static uint16_t in_ephipport;
static int in_nephipport;
static int in_nephipport_max;

void
in_initephport()
{
	in_ephipport = nanosec;
	if (in_ephipport < EPHEMERAL_MIN) {
		in_ephipport += EPHEMERAL_MIN;
	}
}

uint32_t
in_pcbhash(struct dlist *l)
{
	uint32_t h;
	struct socket *so;

	so = container_of(l, struct socket, inp_list);
	h = murmur(so->inp_hkey, sizeof(so->inp_hkey), in_secret);
	return h;
}

int
in_init()
{
	int rc;

	in_secret = rand();
	in_ephip = htonl(ip_laddr_min);
	in_initephport();
	in_nephipport_max = (ip_laddr_max - ip_laddr_min + 1) * NEPHEMERAL;
	rc = htable_init(&in_htable, 1024, in_pcbhash);
	return rc;
}

int
in_pcbbind(struct socket *so, be16_t lport)
{
	uint16_t i;

	if (!lport) {
		return EINVAL;
	}
	if (so->inp_lport || so->inp_laddr != INADDR_ANY) {
		return EINVAL;
	}
	i = ntohs(lport);
	if (i >= ARRAY_SIZE(in_binded)) {
		return EADDRINUSE;
	}
	if (in_binded[i] != NULL) {
		return EADDRINUSE;
	}
	in_binded[i] = so;
	so->inp_laddr = htonl(ip_laddr_min);
	so->inp_lport = lport;
	return 0;
}

int
in_pcbattach(struct socket *so, uint32_t *ph)
{
	uint32_t h;
	struct dlist *bucket;
	struct socket *it;

	if (so->so_state & SS_ISATTACHED) {
		return -EALREADY;
	}
	h = in_pcbhash(&so->inp_list);
	bucket = htable_bucket_get(&in_htable, h);
	DLIST_FOREACH(it, bucket, inp_list) {
		if (it->so_proto == so->so_proto &&
		    it->inp_laddr == so->inp_laddr &&
		    it->inp_lport == so->inp_lport &&
		    it->inp_faddr == so->inp_faddr &&
		    it->inp_fport == so->inp_fport) {
			return EADDRINUSE;
		}
	}
	so->so_state |= SS_ISATTACHED;
	htable_add(&in_htable, &so->inp_list, h);
	*ph = h;
	return 0;
}

int
in_pcbconnect(struct socket *so, const struct sockaddr_in *sin, uint32_t *ph)
{
	if (sin->sin_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	if (sin->sin_port == 0) {
		return -EADDRNOTAVAIL;
	}
	if (sin->sin_addr.s_addr == INADDR_ANY ||
	    sin->sin_addr.s_addr == INADDR_BROADCAST) {
		return -ENOTSUP;
	}
	if (so->inp_faddr != INADDR_ANY) {
		return -EISCONN;
	}
	if (so->so_state & SS_ISATTACHED) {
		return -EISCONN;
	}
	so->inp_faddr = sin->sin_addr.s_addr;
	so->inp_fport = sin->sin_port;
	if (so->inp_laddr != INADDR_ANY) {
		return 0;
	}
	if (in_nephipport == in_nephipport_max) {
		return -EADDRNOTAVAIL;
	}
	do {
		if (in_ephipcnt == NEPHEMERAL) {
			in_ephipcnt = 0;
			in_initephport();
			HTONL(in_ephip);
			in_ephip++;
			if (in_ephip > ip_laddr_max) {
				in_ephip = ip_laddr_min;
			}
			HTONL(in_ephip);
		}
		if (in_ephipport < EPHEMERAL_MIN) {
			in_ephipport = EPHEMERAL_MIN;
		}
		so->inp_laddr = in_ephip;
		so->inp_lport = htons(in_ephipport);
		in_ephipcnt++;
		in_ephipport++;
	} while (in_pcbattach(so, ph) != 0);
	in_nephipport++;
	return 0;
}

int
in_pcbdetach(struct socket *so)
{
	int lport;

	lport = ntohs(so->inp_lport);
	if (lport < EPHEMERAL_MIN) {
		if (in_binded[lport] == so) {
			in_binded[lport] = NULL;
		}
	}
	if (so->so_state & SS_ISATTACHED) {
		so->so_state &= ~SS_ISATTACHED;
		htable_del(&in_htable, &so->inp_list);
		if (lport >= EPHEMERAL_MIN) {
			assert(in_nephipport);
			in_nephipport--;
		}
	}
	sofree(so);
	return 0;
}

void
in_pcbdisconnect(struct socket *so)
{
	so->inp_faddr = INADDR_ANY;
	so->inp_fport = 0;
}

void
in_pcbnotify(int proto,
             be32_t laddr,
             be16_t lport,
             be32_t faddr,
             be16_t fport,
             int err,
             void (*notify)(struct socket *, int))
{
	struct socket *so;

	so = in_pcblookup(proto, laddr, lport, faddr, fport);
	if (so != NULL) {
		(*notify)(so, err);
	}
}

static void
in_pcbforeachfn(void *udata, void *e)
{
	void (*fn)(struct socket *);
	struct socket *so;

	fn = udata;
	so = container_of(e, struct socket, inp_list);
	(*fn)(so);
}

void
in_pcbforeach(void (*fn)(struct socket *))
{
	int i;

	for (i = 0; i < ARRAY_SIZE(in_binded); ++i) {
		if (in_binded[i]) {
			(*fn)(in_binded[i]);
		}
	}
	htable_foreach(&in_htable, fn, in_pcbforeachfn);
}

struct socket *
in_pcblookup(int proto, be32_t laddr, be16_t lport, be32_t faddr, be16_t fport)
{
	int i;
	uint32_t h;
	struct dlist *bucket;
	struct socket *so, tmp;

	tmp.inp_laddr = laddr;
	tmp.inp_lport = lport;
	tmp.inp_faddr = faddr;
	tmp.inp_fport = fport;
	h = in_pcbhash(&tmp.inp_list);
	bucket = htable_bucket_get(&in_htable, h);
	DLIST_FOREACH(so, bucket, inp_list) {	
		if (so->so_proto == proto &&
		    so->inp_laddr == laddr &&
		    so->inp_lport == lport &&
		    so->inp_faddr == faddr &&
		    so->inp_fport == fport) {
			return so;
		}
	}
	i = ntohs(lport);
	if (i < EPHEMERAL_MIN) {
		return in_binded[i];
	} else {
		return NULL;
	}
}
