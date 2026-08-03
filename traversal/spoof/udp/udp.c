#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "udp.h"
#include "../nt.h"

#include "../../ipip/ipip.h"
#include "../../traversal.h"
#include "../../checksum/checksum.h"

struct udp_pseudo {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t udp_len;
};

int read_spoof_udp(struct nt_session *nts, struct nt_read_packet *pkt) {
    uint8_t buf[MAX_DATA_BUFFER];
    ssize_t r = recv(nts->spoof_ctx->read_socket, buf, sizeof(buf), 0);
    if (r < 0) {
        return -1;
    }

    pkt->iph = NULL;
    pkt->data = malloc(r);
    if (!pkt->data) {
        return -1;
    }

    pkt->data_len = (size_t)r;
    memcpy(pkt->data, buf, pkt->data_len);

    return (int)r;
}

static ssize_t build_udp(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t **buf) {
    size_t total_len = sizeof(struct iphdr)+sizeof(struct udphdr)+pkt->data_len;

    *buf = calloc(total_len+sizeof(struct udp_pseudo), sizeof(uint8_t));
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
    iph->saddr = htonl(nts->stun_addr);
    iph->daddr = htonl(pkt->daddr);
    iph->check = htons(checksum(*buf, sizeof(struct iphdr)));
    
    // inner udp header
    struct udphdr *udph = (struct udphdr *)(*buf+offset);
    offset += sizeof(struct udphdr);

    udph->source = htons(nts->stun_port);
    udph->dest   = htons(pkt->dport);
    udph->len    = htons(sizeof(struct udphdr)+pkt->data_len);

    struct udp_pseudo *pseudo = (struct udp_pseudo *)(*buf+offset);
    pseudo->saddr = iph->saddr;
    pseudo->daddr = iph->daddr;
    pseudo->protocol = iph->protocol;
    pseudo->udp_len = udph->len;

    memcpy(*buf+offset+sizeof(struct udp_pseudo), pkt->data, pkt->data_len);
    udph->check = htons(checksum(*buf+sizeof(struct iphdr), total_len-sizeof(struct iphdr)+sizeof(struct udp_pseudo)));

    // overwrite pseudo with data
    memcpy(*buf+offset, pkt->data, pkt->data_len);

    return total_len;
}

int send_spoof_udp(struct nt_session *nts, struct nt_send_packet *pkt) {
    uint8_t *buf = NULL;
    ssize_t len = build_udp(nts, pkt, &buf);
    if (len < 0) {
        return (int)len;
    }

    int ret = send_ipip(
        nts->spoof_ctx->send_socket,
        nts->pub_addr,
        nts->spoof_ctx->relay_addr,
        buf,
        (size_t)len);
    
    free(buf);
    return ret;
}
