#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>

#include "unreach.h"
#include "../nt.h"

#include "../../traversal.h"
#include "../../checksum/checksum.h"


static ssize_t build_icmp_unreach(uint8_t **buf, uint8_t *inner_packet, size_t inner_len) {
    size_t total_len = sizeof(struct icmphdr)+inner_len;
    
    *buf = calloc(total_len, sizeof(uint8_t));
    if (!*buf) return -1;

    size_t offset = 0;

    struct icmphdr *icmph = (struct icmphdr *)*buf;
    offset += sizeof(struct icmphdr);

    icmph->type = ICMP_DEST_UNREACH;
    icmph->code = ICMP_NET_UNREACH;
    
    memcpy(*buf+offset, inner_packet, inner_len);

    icmph->checksum = htons(checksum(*buf, total_len));
    
    return (ssize_t)total_len;
}

static ssize_t build_inner_icmp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    size_t total_len = sizeof(struct iphdr)+sizeof(struct icmphdr)+pkt->data_len;

    *buf = calloc(total_len, sizeof(uint8_t));
    if (!*buf) {
        return -1;
    }

    size_t offset = 0;

    struct iphdr *iph = (struct iphdr *)(*buf);
    offset += sizeof(struct iphdr);

    iph->version = 4; // ipv4
    iph->ihl = 5;
    iph->tot_len = htons(total_len);
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = htonl(pkt->daddr);
    iph->daddr = htonl(nts->istun_addr);
    
    struct icmphdr *icmph = (struct icmphdr *)(*buf+offset);
    offset += sizeof(struct icmphdr);

    icmph->type = ICMP_ECHO;
    icmph->un.echo.id = htons(pkt->did);
    icmph->un.echo.sequence = htons(2222); 

    memcpy(*buf+offset, pkt->data, pkt->data_len);

    return (ssize_t)total_len;
}

static ssize_t build_inner_udp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    size_t total_len = sizeof(struct iphdr)+sizeof(struct udphdr)+pkt->data_len;
    
    *buf = calloc(total_len, sizeof(uint8_t));
    if (!*buf) {
        return -1;
    }

    size_t offset = 0;

    struct iphdr *iph = (struct iphdr *)(*buf);
    offset += sizeof(struct iphdr);

    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(total_len);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = htonl(pkt->daddr);
    iph->daddr = htonl(nts->stun_addr);
    
    struct udphdr *udph = (struct udphdr *)(*buf+offset);
    offset += sizeof(struct udphdr);

    udph->source = htons(pkt->dport);
    udph->dest = htons(nts->stun_port);
    udph->len = htons(sizeof(struct udphdr)+pkt->data_len);

    memcpy(*buf+offset, pkt->data, pkt->data_len);

    return (ssize_t)total_len;
}

int send_icmp_unreach(struct nt_session *nts, struct nt_send_packet *pkt) {
    uint8_t *inner_packet = NULL;
    size_t inner_len = 0;

    switch (nts->method) {
        case nt_method_icmp_unreach_udp: {
            ssize_t ret = build_inner_udp(nts, pkt, &inner_packet);
            if (ret < 0) {
                return (int)ret;
            }

            inner_len = (size_t)ret;
            break;
        }

        case nt_method_icmp_unreach_icmp: {
            ssize_t ret = build_inner_icmp(nts, pkt, &inner_packet);
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
    ssize_t len = build_icmp_unreach(&buf, inner_packet, inner_len);
    free(inner_packet);
    if (len < 0) {
        return (int)len;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(pkt->daddr);

    ssize_t ret = sendto(nts->icmp_ctx->send_socket, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
    free(buf);
    if (ret != len) {
        return (int)ret;
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

int read_icmp_unreach(struct nt_session *nts, struct nt_read_packet *pkt) {    
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
