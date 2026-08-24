// ICMP STUN Server (reflects the rewritten ICMP echo id)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "istun.h"

#include "../common/common.h"
#include "../common/checksum.h"

static void build_istun_reply(uint8_t buf[REPLY_SIZE], uint16_t id) {
        struct icmphdr *icmph = (struct icmphdr *)buf;
        icmph->type = ICMP_ECHOREPLY;
        icmph->un.echo.id = id;
        icmph->un.echo.sequence = htons(ISTUN_REPLY);
        memcpy(buf+sizeof(struct icmphdr), &id, 2);
        icmph->checksum = htons(checksum(buf, REPLY_SIZE));
}

static int listen_istun(int s) {
    uint8_t reply[REPLY_SIZE];
    uint8_t buf[MAX_DATA_BUFFER];
    while (1) {
        ssize_t len = read(s, buf, MAX_DATA_BUFFER);
        if (len < 0) break;
        if (len < sizeof(struct iphdr)+sizeof(struct icmphdr)) continue;

        size_t offset = 0;

        struct iphdr *iph = (struct iphdr *)buf;
        offset += sizeof(struct iphdr);

        struct icmphdr *icmph = (struct icmphdr *)(buf+offset);
        if (icmph->type != ICMP_ECHO || ntohs(icmph->un.echo.sequence) != ISTUN_REQUEST) continue;

        memset(reply, 0, REPLY_SIZE);
        build_istun_reply(reply, icmph->un.echo.id);

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = iph->saddr;

        printf("sent istun reply to %s (id = %d)\n", inet_ntoa(sin.sin_addr), ntohs(icmph->un.echo.id));
        sendto(s, reply, REPLY_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(s);
}

int init_istun() {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        return -1;
    }

    return listen_istun(s);
}

static int parse_istun_reply(uint32_t istun_addr, uint8_t *buf, size_t len) {
    if (len < sizeof(struct iphdr)+sizeof(struct icmphdr)+sizeof(uint16_t)) {
        return -1;
    }

    size_t offset = 0;
    struct iphdr *iph = (struct iphdr *)buf;
    offset += sizeof(struct iphdr);

    if (ntohl(iph->saddr) != istun_addr) {
        return -1;
    }

    struct icmphdr *icmph = (struct icmphdr *)(buf+offset);
    offset += sizeof(struct icmphdr);

    if (icmph->type != ICMP_ECHOREPLY || ntohs(icmph->un.echo.sequence) != ISTUN_REPLY) {
        return -1;
    }

    uint16_t mapped_id;
    memcpy(&mapped_id, buf+offset, sizeof(mapped_id));

    mapped_id = ntohs(mapped_id);

    return (int)mapped_id;
}

int send_istun_request(uint32_t istun_addr, uint16_t sid) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        return s;
    }

    struct icmphdr icmph = {0};
    icmph.type = ICMP_ECHO;
    icmph.un.echo.id = htons(sid);
    icmph.un.echo.sequence = htons(ISTUN_REQUEST);    
    icmph.checksum = htons(checksum((uint8_t *)&icmph, sizeof(icmph)));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(istun_addr);

    sendto(s, &icmph, sizeof(icmph), 0, (struct sockaddr *)&sin, sizeof(sin));

    struct pollfd pfd = {
        .fd = s,
        .events = POLLIN
    };

    // timeout: 10 sec
    for (int i = 0; i < 5; i++) {
        int r = poll(&pfd, 1, 10000);
        if (r > 0) {
            uint8_t buf[MAX_DATA_BUFFER];
            ssize_t n = read(s, buf, MAX_DATA_BUFFER);
            if (n < 0) continue;
            
            int ret = parse_istun_reply(istun_addr, buf, (size_t)n);
            if (ret < 0) continue;

            close(s);
            return ret;
        }
    }

    close(s);
    return -1; // timeout
}
