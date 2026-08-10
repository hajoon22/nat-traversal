#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>

#include "exceeded.h"
#include "../nt.h"

#include "../../traversal.h"
#include "../../checksum/checksum.h"

static ssize_t build_icmp_exceeded(uint8_t **buf, uint8_t *inner, size_t inner_len) {
    size_t total_len = sizeof(struct icmphdr)+inner_len;
    
    *buf = calloc(total_len, sizeof(uint8_t));
    if (!*buf) return -1;

    size_t offset = 0;

    struct icmphdr *icmph = (struct icmphdr *)*buf;
    offset += sizeof(struct icmphdr);

    icmph->type = ICMP_TIME_EXCEEDED;
    icmph->code = ICMP_EXC_TTL;
    
    memcpy(*buf+offset, inner, inner_len);
    
    icmph->checksum = htons(checksum(*buf, total_len));

    return (ssize_t)total_len;
}

static ssize_t build_inner_udp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    size_t total_len = sizeof(struct iphdr)+sizeof(struct udphdr)+pkt->data_len;
    
    *buf = calloc(total_len, sizeof(uint8_t));
    if (!*buf) return -1;

    size_t offset = 0;

    struct iphdr *iph = (struct iphdr *)(*buf);
    offset += sizeof(struct iphdr);

    iph->version = 4; // ipv4
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 17; // udp
    iph->check = 0;
    iph->saddr = htonl(pkt->daddr);
    iph->daddr = htonl(nts->stun_addr);
    iph->check = 0;

    struct udphdr *udph = (struct udphdr *)(*buf+offset);
    offset += sizeof(struct udphdr);

    udph->source = htons(pkt->dport);
    udph->dest   = htons(nts->stun_port);
    udph->len    = htons(sizeof(struct udphdr)+pkt->data_len);
    udph->check  = 0;

    memcpy(*buf+offset, pkt->data, pkt->data_len);

    return (ssize_t)total_len;
}

static ssize_t build_inner_icmp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    size_t total_len = sizeof(struct iphdr)+sizeof(struct icmphdr)+pkt->data_len;

    *buf = calloc(total_len, sizeof(uint8_t));
    if (!*buf) return -1;

    size_t offset = 0;

    struct iphdr *iph = (struct iphdr *)(*buf);
    offset += sizeof(struct iphdr);

    iph->version = 4; // ipv4
    iph->ihl = 5;
    iph->tot_len = htons(total_len);
    iph->ttl = 64;
    iph->protocol = 1; // icmp echo
    iph->saddr = htonl(pkt->daddr);
    iph->daddr = htonl(nts->istun_addr);
    iph->check = 0;

    struct icmphdr *icmph = (struct icmphdr *)(*buf+offset);
    offset += sizeof(struct icmphdr);

    icmph->type = ICMP_ECHO;
    icmph->un.echo.id = htons(pkt->did);
    icmph->un.echo.sequence = htons(2222); 

    memcpy(*buf+offset, pkt->data, pkt->data_len);

    return (ssize_t)total_len;
}

int send_icmp_exceeded(struct nt_session *nts, struct nt_send_packet *pkt) {
    uint8_t *inner_buf = NULL;
    size_t inner_len = 0;

    switch (nts->method) {
        case nt_method_icmp_exceeded_udp: {
            ssize_t ret = build_inner_udp(nts, pkt, &inner_buf);
            if (ret < 0) {
                return (int)ret;
            }

            inner_len = (size_t)ret;
            break;
        }

        case nt_method_icmp_exceeded_icmp: {
            ssize_t ret = build_inner_icmp(nts, pkt, &inner_buf);
            if (ret < 0) {
                return (int)ret;
            }

            inner_len = (size_t)ret;
            break;
        }

        default:
            return -1;
    }

    uint8_t *buf = NULL;
    ssize_t ret = build_icmp_exceeded(&buf, inner_buf, inner_len);
    free(inner_buf);
    if (ret < 0) {
        return (int)ret;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(pkt->daddr);

    ssize_t n = sendto(nts->icmp_ctx->send_socket, buf, ret, 0, (struct sockaddr *)&sin, sizeof(sin));
    free(buf);
    if (n != ret) {
        return -1;
    }

    return 0;
}

static int parse_inner_udp(struct nt_session *nts, struct nt_read_packet *pkt, uint8_t *buf) {
    struct iphdr *iph = (struct iphdr *)buf;
    if (ntohl(iph->daddr) != nts->stun_addr) {
        return -1;
    }

    uint8_t *data = (uint8_t *)buf+iph->ihl*4+sizeof(struct udphdr);
    ssize_t data_len = ntohs(iph->tot_len)-sizeof(struct udphdr)-iph->ihl*4;
    if (data_len < 0) return -1;
    if (data_len > MAX_DATA_BUFFER) {
        data_len = MAX_DATA_BUFFER;
    }
    pkt->data_len = (size_t)data_len;

    pkt->iph = calloc(1, sizeof(struct iphdr));
    if (!pkt->iph) {
        return -1;
    }

    pkt->data = calloc(pkt->data_len, sizeof(uint8_t));
    if (!pkt->data) {
        return -1;
    }

    memcpy(pkt->iph, iph, sizeof(struct iphdr));
    memcpy(pkt->data, data, pkt->data_len);
    
    return 0;
}

static int parse_inner_icmp(struct nt_session *nts, struct nt_read_packet *pkt, uint8_t *buf) {
    struct iphdr *iph = (struct iphdr *)buf;
    if (ntohl(iph->daddr) != nts->istun_addr) {
        return -1;
    }

    uint8_t *data = (uint8_t *)buf+iph->ihl*4+sizeof(struct icmphdr);
    ssize_t data_len = ntohs(iph->tot_len)-sizeof(struct icmphdr)-iph->ihl*4;
    if (data_len < 0) return -1;
    if (data_len > MAX_DATA_BUFFER) {
        data_len = MAX_DATA_BUFFER;
    }
    pkt->data_len = (size_t)data_len;

    pkt->iph = calloc(1, sizeof(struct iphdr));
    if (!pkt->iph) {
        return -1;
    }

    pkt->data = calloc(pkt->data_len, sizeof(uint8_t));
    if (!pkt->data) {
        return -1;
    }

    memcpy(pkt->iph, iph, sizeof(struct iphdr));
    memcpy(pkt->data, data, pkt->data_len);
    
    return 0;
}

int read_icmp_exceeded(struct nt_session *nts, struct nt_read_packet *pkt) {    
    uint8_t buf[MAX_DATA_BUFFER];
    int n = read(nts->icmp_ctx->read_socket, buf, MAX_DATA_BUFFER);
    if (n < 0) return -1;

    struct iphdr *iph = (struct iphdr *)buf;
    if (n < sizeof(struct iphdr) || ntohs(iph->tot_len) != n) {
        return -1;
    }

    if (iph->ihl < 5 || iph->ihl*4+sizeof(struct icmphdr) > n) {
        return -1;
    }

    struct icmphdr *icmph = (struct icmphdr*)(buf+(iph->ihl*4));
    if (icmph->type == ICMP_TIME_EXCEEDED) {
        switch (nts->method) {
            case nt_method_icmp_exceeded_udp: {
                return parse_inner_udp(nts, pkt, buf+iph->ihl*4+sizeof(struct icmphdr));
            }

            case nt_method_icmp_exceeded_icmp: {
                return parse_inner_icmp(nts, pkt, buf+iph->ihl*4+sizeof(struct icmphdr));
            }
        }
    }

    return -1;
}
