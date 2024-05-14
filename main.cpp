#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <string>
#include <set>
#include <time.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

std::set<std::string> site_list;
u_int32_t verdict;

void usage() {
	fprintf(stderr, "syntax : 1m-block <site list file>\n");
	fprintf(stderr ,"sample : 1m-block top-1m.txt\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);

	if (ret >= 0){
        u_int32_t iphdr_len = (data[0] & 0xf) * 4;
        u_int32_t tcphdr_len = ((data[iphdr_len + 12] & 0xf0)>>4) * 4;
        u_int32_t http_len = ret - iphdr_len - tcphdr_len;

        unsigned char *http_data = data + iphdr_len + tcphdr_len;
        if (http_len > 0){
            char *host_ptr = strstr((char *)http_data, "Host: ");
            if (host_ptr){
                host_ptr = host_ptr + 6;
				char *hostname = strtok(host_ptr, "\r\n");
                if (site_list.find(hostname) != site_list.end()){
					printf("\n[ BLOCKED ] : %s\n", hostname);
					verdict = NF_DROP;
				}
				else {
					printf("\n[ ALLOWED ] : %s\n", hostname);
				}
            }
        }
        printf("payload_len=%d\n", ret);
    }

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
    int ret = nfq_set_verdict(qh, id, verdict, 0, NULL);
    verdict = NF_ACCEPT;
	return ret;
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
		usage();
		return -1;
	}

    FILE *fp = fopen(argv[1], "r");
	if (!fp){
		fprintf(stderr, "Error: cannot open file %s\n", argv[1]);
		exit(1);
	}

	char line[256];
	u_int32_t num;
	memset(line, 0, sizeof(line));

	time_t bef, aft;
	time(&bef);
	while(fscanf(fp, "%d,%s\n", &num, line) != EOF){
		std::string str(line);
		site_list.insert(line);
		memset(line, 0, sizeof(line));
	}
	time(&aft);
	printf("[ RF TIME ] : %lf\n", difftime(aft, bef));

	fclose(fp);


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	// memory free
	site_list.clear();
	exit(0);
}
