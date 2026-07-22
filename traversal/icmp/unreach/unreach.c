#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>

#include "../../traversal.h"
#include "../../checksum/checksum.h"
#include "unreach.h"

void deinit_icmp_unreach(struct icmp_unreach *icmpunreach) {
    if (!icmpunreach) return;
    free(icmpunreach->data);
}

static ssize_t build_icmp_unreach(uint8_t **buf, struct iphdr *iph, struct udphdr *udph, uint8_t *data, size_t len) {
    *buf = malloc(8+iph->ihl*4+sizeof(struct udphdr)+len);
    if (!*buf) return -1;

    struct icmphdr *icmph = (struct icmphdr *)*buf;
    memset(icmph, 0, sizeof(*icmph));
    icmph->type = ICMP_DEST_UNREACH;
    icmph->code = ICMP_NET_UNREACH;
    memcpy(*buf+8, iph, iph->ihl*4); // ip header
    memcpy(*buf+8+iph->ihl*4, udph, sizeof(struct udphdr));
    memcpy(*buf+8+iph->ihl*4+sizeof(struct udphdr), data, len);

    ((struct icmphdr *)(*buf))->checksum = htons(checksum(*buf, 8+iph->ihl*4+sizeof(struct udphdr)+len));

    return 8+iph->ihl*4+sizeof(struct udphdr)+len;
}

int send_icmp_unreach(struct nt_session *nts, struct nt_send_packet *pkt) {
    struct iphdr iph;
    struct udphdr udph;

    memset(&iph, 0, sizeof(iph));
    memset(&udph, 0, sizeof(udph));

    iph.version = 4; // ipv4
    iph.ihl = 5;
    iph.tos = 0;
    iph.tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+pkt->data_len);
    iph.id = 0;
    iph.frag_off = 0;
    iph.ttl = 64;
    iph.protocol = 17; // udp
    iph.check = 0;
    iph.saddr = htonl(pkt->daddr);
    iph.daddr = htonl(nts->stun_addr);
    iph.check = htons(checksum((uint8_t *)&iph, sizeof(iph)));

    udph.source = htons(pkt->dport);
    udph.dest   = htons(nts->stun_port);
    udph.len    = htons(sizeof(struct udphdr)+pkt->data_len);
    udph.check  = 0;

    uint8_t *buf = NULL;
    ssize_t size = build_icmp_unreach(&buf, &iph, &udph, pkt->data, pkt->data_len);
    if (size < 0) return size;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(pkt->daddr);

    int n = sendto(nts->icmp_ctx.socket, buf, size, 0, (struct sockaddr *)&sin, sizeof(sin));
    free(buf);
    if (n != size) {
        return -1;
    }

    return 0;
}

int read_icmp_unreach(struct nt_session *nts, struct nt_read_packet *pkt) {    
    uint8_t buf[MAX_DATA_BUFFER];
    int n = read(nts->icmp_ctx.socket, buf, MAX_DATA_BUFFER);
    if (n < 0) return -1;

    struct iphdr *iph = (struct iphdr *)buf;
    if (n < sizeof(struct iphdr) || ntohs(iph->tot_len) != n) {
        return -1;
    }

    if (iph->ihl < 5 || iph->ihl*4+sizeof(struct icmphdr) > n) {
        return -1;
    }

    struct icmphdr *icmph = (struct icmphdr*)(buf+(iph->ihl*4));
    if (icmph->type == ICMP_DEST_UNREACH) {
        struct iphdr *in_iph = (struct iphdr *)(buf+iph->ihl*4+sizeof(struct icmphdr));
        if (ntohl(in_iph->daddr) != nts->stun_addr) return -1;

        uint8_t *payload = (uint8_t *)icmph+sizeof(struct icmphdr)+28;
        int len = ntohs(iph->tot_len)-(sizeof(struct icmphdr)+iph->ihl*4+28);
        if (len <= 0) {
            return -1;
        }

        if (len > MAX_DATA_BUFFER) {
            len = MAX_DATA_BUFFER;
        }

        // allocate heap buffer for payload
        uint8_t *data = calloc(1, len);
        if (!data) {
            return -1;
        }

        // copy stack to heap
        memcpy(data, payload, len);

        // set results
        pkt->method = nts->method;
        pkt->icmptime.iph = *iph;
        pkt->icmptime.icmph = *icmph;

        pkt->icmptime.data = data;
        pkt->icmptime.data_len = len;

        return 0;
    }

    return -1;
} 
