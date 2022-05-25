#include "subr.h"
#include "global.h"
#include <pcap/pcap.h>

void
cg_pcap_init(const char *ifname)
{
	int i, rc, fd, *dlt_buf, snaplen;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;

	snaplen = 1500;
	pcap = pcap_create(ifname, errbuf);
	if (pcap == NULL) {
		panic(0, "pcap_create('%s') failed (%s)", ifname, errbuf);
	}
	rc = pcap_set_immediate_mode(pcap, 1);
	if (rc < 0) {
		panic(0, "pcap_set_immediate_mode('%s', 1) failed (%s)",
			ifname, pcap_geterr(pcap));
	}
	rc = pcap_set_promisc(pcap, 1);
	if (rc < 0) {
		panic(0, "pcap_set_promisc('%s', 1) failed (%s)", ifname, pcap_geterr(pcap));
	}
	rc = pcap_set_snaplen(pcap, snaplen);
	if (rc < 0) {
		panic(0, "pcap_set_snaplen('%s', %d) failed (%s)",
			ifname, snaplen, pcap_geterr(pcap));
	}
	rc = pcap_activate(pcap);
	if (rc != 0) {
		panic(0, "pcap_activate('%s') failed (%s)", ifname, pcap_geterr(pcap));
	}
	rc = pcap_list_datalinks(pcap, &dlt_buf);
	if (rc < 0) {
		panic(0, "pcap_list_datatlinks('%s') failed (%s)", ifname, pcap_geterr(pcap));
	}
	for (i = 0; i < rc; ++i) {
		if (dlt_buf[i] == DLT_EN10MB) {
			break;
		}
	}
	if (i == rc) {
		panic(0, "%s doesn't support DLT_EN10MB datalink type", ifname);
	}
	pcap_free_datalinks(dlt_buf);
	pcap_setdirection(pcap, PCAP_D_IN);
	rc = pcap_setnonblock(pcap, 1, errbuf);
	if (rc < 0) {
		panic(0, "pcap_setnonblock('%s') failed (%s)", ifname, errbuf);
	}
	fd = pcap_get_selectable_fd(pcap);
	if (fd < 0) {
		panic(0, "pcap_get_selectable_fd('%s') failed (%s)", ifname, pcap_geterr(pcap));
	}
	current->t_pcap = pcap;
	strzcpy(current->t_ifname, ifname, sizeof(current->t_ifname));
	multiplexer_add(fd);
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

void
pcap_rx(int queue_id)
{
	int i, rc;
	const u_char *pkt_dat;
	struct pcap_pkthdr *pkt_hdr;

	for (i = 0; i < current->t_burst_size; ++i) {
		rc = pcap_next_ex(current->t_pcap, &pkt_hdr, &pkt_dat);
		if (rc == 1) {
			(*current->t_rx_op)((void *)pkt_dat, pkt_hdr->caplen);
		} else {
			break;
		}
	}
}

void
set_pcap_ops(struct thread *t)
{
	t->t_io_init_op = cg_pcap_init;
	t->t_io_is_tx_throttled_op = pcap_is_tx_throttled;
	t->t_io_init_tx_packet_op = pcap_init_tx_packet;
	t->t_io_tx_packet_op = pcap_tx_packet;
	t->t_io_rx_op = pcap_rx;
}
