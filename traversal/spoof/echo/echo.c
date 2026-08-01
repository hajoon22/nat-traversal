#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "echo.h"
#include "../nt.h"

#include "../../ipip/ipip.h"
#include "../../traversal.h"
#include "../../checksum/checksum.h"

static ssize_t build_echo_request(uint8_t **buf, struct nt_session *nts, struct nt_send_packet *pkt) {
    size_t total_len = sizeof(struct iphdr)+sizeof(struct icmphdr)+pkt->data_len;

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
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = htonl(pkt->daddr);
    iph->daddr = htonl(nts->spoof_ctx->addr);
    iph->check = htons(checksum(*buf, sizeof(struct iphdr)));

    struct icmphdr *icmph = (struct icmphdr *)(*buf+offset);
    offset += sizeof(struct icmphdr);

    icmph->type = ICMP_ECHO;
    icmph->un.echo.id = htons(nts->spoof_ctx->id);
    icmph->un.echo.sequence = htons(nts->spoof_ctx->seq);

    memcpy(*buf+offset, pkt->data, pkt->data_len);

    icmph->checksum = htons(checksum(*buf+sizeof(struct iphdr), total_len-sizeof(struct iphdr)));

    return total_len;
}

static int send_spoof_echo_reflection(struct nt_session *nts, struct nt_send_packet *pkt) {
    uint8_t *buf = NULL;
    ssize_t len = build_echo_request(&buf, nts, pkt);    
    if (len < 0) {
        return -1;
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

int send_spoof_echo(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_spoof_echo_reflection:
            return send_spoof_echo_reflection(nts, pkt);
    }

    return -1;
}

static int parse_icmp_echo(struct nt_session *nts, struct nt_read_packet *pkt, uint8_t *buf, size_t len) {
    if (len < sizeof(struct iphdr)+sizeof(struct icmphdr)) {
        return -1;
    }

    size_t offset = 0;

    struct iphdr *iph = (struct iphdr *)buf;
    offset += sizeof(struct iphdr);

    if (ntohs(iph->tot_len) != len) {
        return -1;
    }

    struct icmphdr *icmph = (struct icmphdr *)(buf+offset);
    offset += sizeof(struct icmphdr);

    if (ntohs(icmph->un.echo.id) != nts->spoof_ctx->id) {
        return -1;
    }

    uint8_t *data = buf+offset;
    pkt->data_len = len-sizeof(struct iphdr)-sizeof(struct icmphdr);

    pkt->data = calloc(pkt->data_len, sizeof(uint8_t));
    if (!pkt->data) {
        return -1;
    }

    pkt->iph = calloc(1, sizeof(struct iphdr));
    if (!pkt->iph) {
        return -1;
    }

    memcpy(pkt->data, data, pkt->data_len);
    memcpy(pkt->iph, iph, sizeof(struct iphdr));

    return (int)pkt->data_len;
}

int read_spoof_echo(struct nt_session *nts, struct nt_read_packet *pkt) {
    uint8_t buf[MAX_DATA_BUFFER];
    ssize_t ret = recv(nts->spoof_ctx->read_socket, buf, sizeof(buf), 0);
    if (ret < 0) {
        return (int)ret;
    }

    return parse_icmp_echo(nts, pkt, buf, (size_t)ret);
}
