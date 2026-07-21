#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "../../checksum/checksum.h"

static ssize_t build_ipip(uint8_t **buf, uint32_t src, uint32_t dst, struct iphdr *iph, struct udphdr *udph, uint8_t *data, size_t data_len) {
    *buf = malloc(sizeof(struct iphdr)*2+sizeof(struct udphdr)+data_len);
    if (!*buf) return -1;

    struct iphdr outer = {0};
    outer.version = 4;
    outer.ihl = 5;
    outer.tot_len = htons(sizeof(struct iphdr)*2+sizeof(struct udphdr)+data_len);
    outer.ttl = 64;
    outer.protocol = IPPROTO_IPIP;
    outer.saddr = htonl(src);
    outer.daddr = htonl(dst);
    outer.check = htons(checksum((uint8_t *)&outer, sizeof(outer)));

    memcpy(*buf, &outer, sizeof(struct iphdr));
    memcpy(*buf+sizeof(struct iphdr), iph, sizeof(struct iphdr));
    memcpy(*buf+sizeof(struct iphdr)*2, udph, sizeof(struct udphdr));
    memcpy(*buf+sizeof(struct iphdr)*2+sizeof(struct udphdr), data, data_len);

    return sizeof(struct iphdr)*2+sizeof(struct udphdr)+data_len;
}

int send_ipip(int s, uint32_t src, uint32_t dst, struct iphdr *iph, struct udphdr *udph, uint8_t *data, size_t data_len) {
    uint8_t *buf = NULL;
    ssize_t n = build_ipip(&buf, src, dst, iph, udph, data, data_len);
    if (n < 0) {
        return -1;
    }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(dst);

    ssize_t sn = sendto(s, buf, n, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (sn < 0 || sn != n) {
        free(buf);

        return -1;
    }
    free(buf);

    return 0;
}
