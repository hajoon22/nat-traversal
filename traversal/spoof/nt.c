#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "nt.h"
#include "udp/udp.h"
#include "echo/echo.h"

#include "../traversal.h"
#include "../stun/stun.h"
#include "../checksum/checksum.h"

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

void deinit_nt_spoof_context(struct nt_spoof_context *ctx) {
    if (ctx->read_socket >= 0 && ctx->send_socket >= 0) {
        close(ctx->read_socket);
        close(ctx->send_socket);
    }

    free(ctx);
}

static int init_nt_spoof_echo(struct nt_session *nts) {
    nts->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nts->socket < 0) {
        return nts->socket;
    }

    nts->keepalive_pid = init_keepalive_icmp(nts->socket);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    nts->spoof_ctx->read_socket = nts->socket;

    return 0;
}

int init_nt_spoof(struct nt_session *nts) {
    nts->socket = init_stun(
        nts->stun_addr, nts->stun_port, 
        &nts->pub_addr, 
        &nts->mapped_port);

    if (nts->socket < 0) {
        return nts->socket;
    }

    nts->spoof_ctx->send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (nts->spoof_ctx->send_socket < 0) {
        deinit_nt_session(nts);
        return nts->spoof_ctx->send_socket;
    }

    switch (nts->method) {
        case nt_method_spoof_udp_direct: {
            nts->keepalive_pid = init_keepalive_udp(nts->socket);
            if (nts->keepalive_pid < 0) {
                deinit_nt_session(nts);
                return nts->keepalive_pid;
            }

            nts->spoof_ctx->read_socket = nts->socket;

            break;
        }

        case nt_method_spoof_echo_reflection: {
            close(nts->socket);
            
            nts->spoof_ctx->id = ECHO_ID;
            nts->spoof_ctx->seq = ECHO_SEQ;
            nts->spoof_ctx->addr = ntohl(inet_addr(ECHO_ADDR));

            if (init_nt_spoof_echo(nts) < 0) {
                return -1;
            }

            break;
        } 
    }

    
    nts->spoof_ctx->pfd = (struct pollfd){
        .fd = nts->spoof_ctx->read_socket,
        .events = POLLIN,
    };
    

    return 0;
}

int nt_read_spoof(struct nt_session *nts, struct nt_read_packet *pkt) {
    int n = poll(&nts->spoof_ctx->pfd, 1, 1000);
    if (n > 0) {
        switch (nts->method) {
            case nt_method_spoof_udp_direct: {
                return read_spoof_udp(nts, pkt);
            }
            
            case nt_method_spoof_echo_reflection: {
                return read_spoof_echo(nts, pkt);
            }
        }
    }

    return -1;
}

int nt_send_spoof(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_spoof_udp_direct: {
           return send_spoof_udp(nts, pkt);
        }

        case nt_method_spoof_echo_reflection: {
            return send_spoof_echo(nts, pkt);
        }
    }

    return -1;
}
