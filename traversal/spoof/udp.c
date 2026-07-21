#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "../traversal.h"
#include "../checksum/checksum.h"
#include "udp.h"
#include "ipip/ipip.h"

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
        uint8_t buf[1500];
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
    struct iphdr inner_iph = {0};
    inner_iph.version = 4;
    inner_iph.ihl = 5;
    inner_iph.tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+pkt->data_len);
    inner_iph.ttl = 64;
    inner_iph.protocol = IPPROTO_UDP;
    inner_iph.saddr = htonl(nts->stun_addr);
    inner_iph.daddr = htonl(pkt->daddr);
    inner_iph.check = htons(checksum((uint8_t *)&inner_iph, sizeof(inner_iph)));

    struct udphdr inner_udph = {0};
    inner_udph.source = htons(nts->stun_port);
    inner_udph.dest   = htons(pkt->dport);
    inner_udph.len    = htons(sizeof(struct udphdr)+pkt->data_len);

    struct udp_pseudo pseudo = {0};
    pseudo.saddr = inner_iph.saddr;
    pseudo.daddr = inner_iph.daddr;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.udp_len = inner_udph.len;

    uint8_t *udp = malloc(sizeof(struct udphdr)+sizeof(struct udp_pseudo)+pkt->data_len);
    if (!udp) return -1;

    memcpy(udp, &pseudo, sizeof(struct udp_pseudo));
    memcpy(udp+sizeof(struct udp_pseudo), &inner_udph, sizeof(struct udphdr));
    memcpy(udp+sizeof(struct udphdr)+sizeof(struct udp_pseudo), pkt->data, pkt->data_len);

    inner_udph.check = htons(checksum(udp, sizeof(struct udphdr)+sizeof(struct udp_pseudo)+pkt->data_len));
    free(udp);

    return send_ipip(
        nts->spoof_ctx.socket,
        nts->spoof_ctx.pub_addr, 
        nts->spoof_ctx.relay_addr, 
        &inner_iph, 
        &inner_udph, 
        pkt->data, 
        pkt->data_len);
}
