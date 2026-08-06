// ICMP STUN Server (reflects the rewritten ICMP echo id)
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "istun.h"

static void build_istun_reply(uint8_t buf[REPLY_SIZE], uint16_t id) {
        struct icmphdr *icmph = (struct icmphdr *)buf;
        icmph->type = ICMP_ECHOREPLY;
        icmph->un.echo.id = id;
        icmph->un.echo.sequence = htons(22);
        memcpy(buf+sizeof(struct icmphdr), &id, 2);
        icmph->checksum = htons(checksum(buf, REPLY_SIZE));
}

static int listen_istun(int s) {
    int pid = fork();
    if (pid == 0) {
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

            memset(reply, 0, REPLY_SIZE);
            build_istun_reply(reply, icmph->un.echo.id);

            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = iph->saddr;

            sendto(s, reply, REPLY_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin));
        }

        close(s);
    }
    
    return pid;
}

int init_istun() {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        return -1;
    }

    return listen_istun(s);
}
