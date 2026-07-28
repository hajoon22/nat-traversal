#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "../../traversal.h"
#include "../../checksum/checksum.h"
#include "../../ipip/ipip.h"
#include "udp.h"

struct udp_pseudo {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t udp_len;
};

void deinit_spoof_udp(struct spoof_udp *spoofudp) {
    free(spoofudp->data);
}

int read_spoof_udp(struct nt_session *nts, struct nt_read_packet *pkt) {
    int n = poll(&nts->spoof_ctx.pfd, 1, 1000);
    if (n > 0) {
        uint8_t buf[MAX_DATA_BUFFER];
        ssize_t r = recv(nts->socket, buf, sizeof(buf), 0);
        if (r < 0) {
            return -1;
        }

        pkt->spoofudp.data = malloc(r);
        if (!pkt->spoofudp.data) {
            return -1;
        }

        pkt->method = nts->method;
        pkt->spoofudp.data_len = (size_t)r;
        memcpy(pkt->spoofudp.data, buf, r);
        return (int)r;
    }

    return -1;
}

int send_spoof_udp(struct nt_session *nts, struct nt_send_packet *pkt) {
    size_t inner_len = sizeof(struct iphdr)+sizeof(struct udphdr)+pkt->data_len;
    
    // inner packet buffer
    uint8_t *buf = calloc(inner_len+sizeof(struct udp_pseudo), sizeof(uint8_t));
    if (!buf) return -1;
    
    size_t offset = 0;

    // inner ip header
    struct iphdr *iph = (struct iphdr *)buf;
    offset += sizeof(struct iphdr);

    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(inner_len);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = htonl(nts->stun_addr);
    iph->daddr = htonl(pkt->daddr);
    iph->check = htons(checksum(buf, sizeof(struct iphdr)));
    
    // inner udp header
    struct udphdr *udph = (struct udphdr *)(buf+offset);
    offset += sizeof(struct udphdr);

    udph->source = htons(nts->stun_port);
    udph->dest   = htons(pkt->dport);
    udph->len    = htons(sizeof(struct udphdr)+pkt->data_len);

    struct udp_pseudo *pseudo = (struct udp_pseudo *)(buf+offset);
    pseudo->saddr = iph->saddr;
    pseudo->daddr = iph->daddr;
    pseudo->protocol = iph->protocol;
    pseudo->udp_len = udph->len;

    memcpy(buf+offset+sizeof(struct udp_pseudo), pkt->data, pkt->data_len);
    udph->check = htons(checksum(buf, inner_len));

    // overwrite pseudo with data
    memcpy(buf+offset, pkt->data, pkt->data_len);

    int send_ipip(int s, uint32_t src, uint32_t dst, uint8_t *inner, size_t inner_len);

    int ret = send_ipip(
        nts->spoof_ctx.socket,
        nts->spoof_ctx.pub_addr,
        nts->spoof_ctx.relay_addr,
        buf,
        inner_len);
    
    free(buf);
    return ret;
}
