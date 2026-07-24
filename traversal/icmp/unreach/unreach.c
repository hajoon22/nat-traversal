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

static ssize_t build_icmp_unreach(uint8_t **buf, uint8_t *inner_packet, size_t inner_len) {
    *buf = malloc(8+inner_len);
    if (!*buf) return -1;

    struct icmphdr *icmph = (struct icmphdr *)*buf;
    memset(icmph, 0, sizeof(*icmph));
    icmph->type = ICMP_DEST_UNREACH;
    icmph->code = ICMP_NET_UNREACH;
    memcpy(*buf+8, inner_packet, inner_len);

    ((struct icmphdr *)(*buf))->checksum = htons(checksum(*buf, 8+inner_len));
    return 8+inner_len;
}

static ssize_t build_inner_icmp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    struct iphdr iph = {0};
    struct icmphdr icmph = {0};

    iph.version = 4; // ipv4
    iph.ihl = 5;
    iph.tot_len = htons(sizeof(iph)+sizeof(icmph)+pkt->data_len);
    iph.ttl = 64;
    iph.protocol = 1; // icmp echo
    iph.saddr = htonl(pkt->daddr);
    iph.daddr = htonl(nts->icmp_ctx.addr);
    iph.check = htons(checksum((uint8_t *)&iph, sizeof(iph)));

    icmph.type = ICMP_ECHO;
    icmph.un.echo.id = htons(nts->icmp_ctx.id);
    icmph.un.echo.sequence = htons(nts->icmp_ctx.seq); 

    size_t inner_len = sizeof(iph)+sizeof(icmph)+pkt->data_len;
    *buf = malloc(inner_len);
    if (!*buf) return -1;

    memcpy(*buf, &iph, sizeof(iph));
    memcpy((*buf)+sizeof(iph), &icmph, sizeof(icmph));
    memcpy((*buf)+sizeof(iph)+sizeof(icmph), pkt->data, pkt->data_len);

    return inner_len;
}

static ssize_t build_inner_udp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    struct iphdr iph = {0};
    struct udphdr udph = {0};

    iph.version = 4; // ipv4
    iph.ihl = 5;
    iph.tot_len = htons(sizeof(iph)+sizeof(udph)+pkt->data_len);
    iph.ttl = 64;
    iph.protocol = 17; // udp
    iph.saddr = htonl(pkt->daddr);
    iph.daddr = htonl(nts->stun_addr);
    iph.check = htons(checksum((uint8_t *)&iph, sizeof(iph)));

    udph.source = htons(pkt->dport);
    udph.dest   = htons(nts->stun_port);
    udph.len    = htons(sizeof(udph)+pkt->data_len);

    size_t inner_len = sizeof(iph)+sizeof(udph)+pkt->data_len;
    *buf = malloc(inner_len);
    if (!*buf ) return -1;

    memcpy(*buf, &iph, sizeof(iph));
    memcpy((*buf)+sizeof(iph), &udph, sizeof(udph));
    memcpy((*buf)+sizeof(iph)+sizeof(udph), pkt->data, pkt->data_len);

    return inner_len;
}

int send_icmp_unreach(struct nt_session *nts, struct nt_send_packet *pkt) {
    uint8_t *inner_packet = NULL;
    size_t inner_len = 0;

    switch (nts->method) {
        case nt_method_icmp_unreach_udp: {
            ssize_t n = build_inner_udp(nts, pkt, &inner_packet);
            if (n < 0) return n;

            inner_len = (size_t)n;
            break;
        }

        case nt_method_icmp_unreach_icmp: {
            ssize_t n = build_inner_icmp(nts, pkt, &inner_packet);
            if (n < 0) return n;

            inner_len = (size_t)n;
            break;
        }
        
        default: return -1;
    }
    
    uint8_t *buf = NULL;
    ssize_t len = build_icmp_unreach(&buf, inner_packet, inner_len);
    if (len < 0) return len;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(pkt->daddr);

    int n = sendto(nts->icmp_ctx.socket, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
    free(buf);
    free(inner_packet);
    if (n != len) {
        return -1;
    }

    return 0;
}

static int parse_inner_udp(struct nt_session *nts, struct nt_read_packet *pkt, uint8_t *buf) {
    struct iphdr *iph = (struct iphdr *)buf;
    if (ntohl(iph->daddr) != nts->stun_addr) {
        return -1;
    }

    uint8_t *payload = (uint8_t *)buf+iph->ihl*4+sizeof(struct udphdr);
    ssize_t payload_len = ntohs(iph->tot_len)-sizeof(struct udphdr)-iph->ihl*4;
    if (payload_len < 0) return -1;
    if (payload_len > MAX_DATA_BUFFER) {
        payload_len = MAX_DATA_BUFFER;
    }

    uint8_t *data = malloc(payload_len);
    if (!data) return -1;

    memcpy(data, payload, payload_len);
    pkt->method = nts->method;
    pkt->icmpun.iph = *iph;
    pkt->icmpun.data = data;
    pkt->icmpun.data_len = payload_len;

    return 0;
}

static int parse_inner_icmp(struct nt_session *nts, struct nt_read_packet *pkt, uint8_t *buf) {
    struct iphdr *iph = (struct iphdr *)buf;
    if (ntohl(iph->daddr) != nts->icmp_ctx.addr) {
        return -1;
    }

    uint8_t *payload = (uint8_t *)buf+iph->ihl*4+sizeof(struct icmphdr);
    ssize_t payload_len = ntohs(iph->tot_len)-sizeof(struct icmphdr)-iph->ihl*4;
    if (payload_len < 0) return -1;
    if (payload_len > MAX_DATA_BUFFER) {
        payload_len = MAX_DATA_BUFFER;
    }

    uint8_t *data = malloc(payload_len);
    if (!data) return -1;

    memcpy(data, payload, payload_len);
    pkt->method = nts->method;
    pkt->icmpun.iph = *iph;
    pkt->icmpun.data = data;
    pkt->icmpun.data_len = payload_len;

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
        switch (nts->method) {
            case nt_method_icmp_unreach_udp: {
                return parse_inner_udp(nts, pkt, buf+iph->ihl*4+sizeof(struct icmphdr));
            }

            case nt_method_icmp_unreach_icmp: {
                return parse_inner_icmp(nts, pkt, buf+iph->ihl*4+sizeof(struct icmphdr));
            }
        }
    }

    return -1;
} 
