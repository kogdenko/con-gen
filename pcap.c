#include "subr.h"
#include "global.h"
#include <pcap/pcap.h>

static void
pcap_init_if(struct thread *t)
{
	int i, rc, fd, *dlt_buf, snaplen;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;

	snaplen = 1500;
	pcap = pcap_create(t->t_ifname, errbuf);
	if (pcap == NULL) {
		panic(0, "pcap_create('%s') failed (%s)", t->t_ifname, errbuf);
	}
	rc = pcap_set_immediate_mode(pcap, 1);
	if (rc < 0) {
		panic(0, "pcap_set_immediate_mode('%s', 1) failed (%s)",
				t->t_ifname, pcap_geterr(pcap));
	}
	rc = pcap_set_promisc(pcap, 1);
	if (rc < 0) {
		panic(0, "pcap_set_promisc('%s', 1) failed (%s)",
				t->t_ifname, pcap_geterr(pcap));
	}
	rc = pcap_set_snaplen(pcap, snaplen);
	if (rc < 0) {
		panic(0, "pcap_set_snaplen('%s', %d) failed (%s)",
				t->t_ifname, snaplen, pcap_geterr(pcap));
	}
	rc = pcap_activate(pcap);
	if (rc != 0) {
		panic(0, "pcap_activate('%s') failed (%s)",
				t->t_ifname, pcap_geterr(pcap));
	}
	rc = pcap_list_datalinks(pcap, &dlt_buf);
	if (rc < 0) {
		panic(0, "pcap_list_datatlinks('%s') failed (%s)",
				t->t_ifname, pcap_geterr(pcap));
	}
	for (i = 0; i < rc; ++i) {
		if (dlt_buf[i] == DLT_EN10MB) {
			break;
		}
	}
	if (i == rc) {
		panic(0, "%s doesn't support DLT_EN10MB datalink type", t->t_ifname);
	}
	pcap_free_datalinks(dlt_buf);
	pcap_setdirection(pcap, PCAP_D_IN);
	rc = pcap_setnonblock(pcap, 1, errbuf);
	if (rc < 0) {
		panic(0, "pcap_setnonblock('%s') failed (%s)", t->t_ifname, errbuf);
	}
	fd = pcap_get_selectable_fd(pcap);
	if (fd < 0) {
		panic(0, "pcap_get_selectable_fd('%s') failed (%s)",
				t->t_ifname, pcap_geterr(pcap));
	}
	current->t_pcap = pcap;
	multiplexer_add(fd);
}

void
pcap_init_threads(struct thread *threads, int n_threads)
{
	int i;

	for (i = 0; i < n_threads; ++i) {
		pcap_init_if(threads + i);
	}
}

bool
pcap_is_tx_throttled(void)
{
	return multiplexer_get_events(0) & POLLOUT;
}

void
pcap_init_tx_packet(struct packet *pkt)
{
	pkt->pkt.buf = pkt->pkt_body;
	pkt->pkt.len = 0;
}

bool
pcap_tx_packet(struct packet *pkt)
{
	assert(pkt->pkt.len);
	if (pcap_inject(current->t_pcap, pkt->pkt.buf, pkt->pkt.len) <= 0) {
		add_pending_packet(pkt);
		multiplexer_pollout(0);
		return false;
	} else {
		return true;
	}
}

int
pcap_rx(int queue_id)
{
	int n, rc;
	const u_char *pkt_dat;
	struct pcap_pkthdr *pkt_hdr;

	n = 0;
	for (;;) {
		rc = pcap_next_ex(current->t_pcap, &pkt_hdr, &pkt_dat);
		if (rc == 1) {
			io_process((void *)pkt_dat, pkt_hdr->caplen);
			n++;
		} else {
			break;
		}
	}
	return n;
}

struct transport_ops pcap_io_ops = {
	.tr_io_init_op = pcap_init_threads,
	.tr_io_is_tx_throttled_op = pcap_is_tx_throttled,
	.tr_io_init_tx_packet_op = pcap_init_tx_packet,
	.tr_io_tx_packet_op = pcap_tx_packet,
	.tr_io_rx_op = pcap_rx,
};
