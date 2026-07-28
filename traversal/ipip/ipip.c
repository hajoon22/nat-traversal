#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "../checksum/checksum.h"

static ssize_t build_ipip(uint8_t **buf, uint32_t src, uint32_t dst, uint8_t *inner, size_t inner_len) {
    size_t total_len = sizeof(struct iphdr)+inner_len;
    
    *buf = malloc(total_len);
    if (!*buf) return -1;

    struct iphdr iph = {0};
    iph.version = 4;
    iph.ihl = 5;
    iph.tot_len = htons(total_len);
    iph.ttl = 64;
    iph.protocol = IPPROTO_IPIP;
    iph.saddr = htonl(src);
    iph.daddr = htonl(dst);
    iph.check = htons(checksum((uint8_t *)&iph, sizeof(iph)));

    memcpy(*buf, &iph, sizeof(iph));
    memcpy(*buf+sizeof(iph), inner, inner_len);

    return total_len;
}

int send_ipip(int s, uint32_t src, uint32_t dst, uint8_t *inner, size_t inner_len) {
    uint8_t *buf = NULL;
    ssize_t ret = build_ipip(&buf, src, dst, inner, inner_len);
    if (ret < 0) return ret;
    
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(dst);

    ssize_t n = sendto(s, buf, ret, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (n != ret) {
        free(buf);

        return -1;
    }
    free(buf);
    
    return 0;
}
