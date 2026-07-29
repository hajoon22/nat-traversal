#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "../stun/stun.h"
#include "../traversal.h"
#include "../checksum/checksum.h"

#include "nt.h"
#include "unreach/unreach.h"
#include "exceeded/exceeded.h"

static int init_keepalive_udp(int s) {
    int pid = fork();
    if (pid == 0) {
        while (1) {
            send(s, "hello", 5, 0); // keepalive
            sleep(10);
        }
    }

    return pid;
}

static int init_keepalive_icmp(int s) {
    int pid = fork();
    if (pid == 0) {
        struct icmphdr icmph = {0};
        icmph.type = ICMP_ECHO;
        icmph.un.echo.id = htons(ECHO_ID);
        icmph.un.echo.sequence = htons(ECHO_SEQ);    
        icmph.checksum = htons(checksum((uint8_t *)&icmph, sizeof(icmph)));

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(ECHO_ADDR);

        while (1) {
            sendto(s, &icmph, sizeof(icmph), 0, (struct sockaddr *)&sin, sizeof(sin));
            sleep(5);
        }
    }

    return pid;
}

void deinit_nt_icmp_context(struct nt_icmp_context *ctx) {
    if (ctx->socket >= 0) {
        close(ctx->socket);
    }
}

static int init_nt_icmp_udp(struct nt_session *nts) {
    nts->socket = init_stun(
        nts->stun_addr, nts->stun_port, 
        &nts->icmp_ctx.pub_addr, 
        &nts->icmp_ctx.mapped_port);

    if (nts->socket < 0) {
        return nts->socket;
    }
    
    nts->keepalive_pid = init_keepalive_udp(nts->socket);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    return 0;
}

static int init_nt_icmp_icmp(struct nt_session *nts) {
    nts->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nts->socket < 0) return nts->socket;

    nts->keepalive_pid = init_keepalive_icmp(nts->socket);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    return 0;
}

int init_nt_icmp(struct nt_session *nts) {
    switch (nts->method) {
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp: {
            if (init_nt_icmp_udp(nts) < 0) {
                return -1;
            }

            break;
        }

        case nt_method_icmp_exceeded_icmp:
        case nt_method_icmp_unreach_icmp: {
            nts->icmp_ctx.id = ECHO_ID;
            nts->icmp_ctx.seq = ECHO_SEQ;
            nts->icmp_ctx.addr = ntohl(inet_addr(ECHO_ADDR));

            if (init_nt_icmp_icmp(nts) < 0) {
                return -1;
            }

            break;
        }

        default: 
            return -1;
    }

    nts->icmp_ctx.socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nts->icmp_ctx.socket < 0) {
        deinit_nt_session(nts);
        return nts->icmp_ctx.socket;
    }

    nts->icmp_ctx.pfd = (struct pollfd){
        .fd = nts->icmp_ctx.socket,
        .events = POLLIN,
    };

    return 0;
}

int nt_read_icmp(struct nt_session *nts, struct nt_read_packet *pkt) {
    int n = poll(&nts->icmp_ctx.pfd, 1, 1000);
    if (n > 0) {
        switch (nts->method) {
            case nt_method_icmp_unreach_icmp:
            case nt_method_icmp_unreach_udp:
                return read_icmp_unreach(nts, pkt);

            case nt_method_icmp_exceeded_icmp:
            case nt_method_icmp_exceeded_udp:
                return read_icmp_exceeded(nts, pkt);
        }
    }

    return -1;
}

int nt_send_icmp(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_unreach_udp:
            return send_icmp_unreach(nts, pkt);

        case nt_method_icmp_exceeded_icmp:
        case nt_method_icmp_exceeded_udp:
            return send_icmp_exceeded(nts, pkt);      
    }

    return -1;
}
