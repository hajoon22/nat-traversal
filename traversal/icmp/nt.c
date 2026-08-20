#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "nt.h"
#include "icmp.h"

#include "../traversal.h"
#include "../stun/stun.h"
#include "../istun/istun.h"
#include "../common/common.h"
#include "../common/checksum.h"
#include "../common/keepalive.h"

void deinit_nt_icmp_context(struct nt_icmp_context *ctx) {
    close(ctx->read_socket);
    if (ctx->read_socket != ctx->send_socket) {
        close(ctx->send_socket);
    }

    if (ctx->keepalive_socket != ctx->send_socket && ctx->keepalive_socket != ctx->read_socket) {
        close(ctx->keepalive_socket);
    }

    free(ctx);
}

static int init_nt_icmp_udp(struct nt_session *nts) {
    nts->icmp_ctx->keepalive_socket = init_stun(
        nts->stun_addr, nts->stun_port, 
        &nts->pub_addr, 
        &nts->mapped_port);

    if (nts->icmp_ctx->keepalive_socket < 0) {
        return nts->icmp_ctx->keepalive_socket;
    }
    
    nts->keepalive_pid = init_keepalive_udp(nts->icmp_ctx->keepalive_socket);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    nts->icmp_ctx->read_socket = nts->icmp_ctx->send_socket;

    return 0;
}

static int init_nt_icmp_icmp(struct nt_session *nts) {
    int ret = send_istun_request(nts->istun_addr, ECHO_ID);
    if (ret < 0) return ret;
    
    nts->mapped_id = ECHO_ID;
    if (ret != ECHO_ID) {
        nts->mapped_id = (uint16_t)ret;
    }

    nts->icmp_ctx->keepalive_socket = nts->icmp_ctx->send_socket;
    nts->keepalive_pid = init_keepalive_icmp(nts->icmp_ctx->keepalive_socket, nts->istun_addr);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    nts->icmp_ctx->read_socket = nts->icmp_ctx->send_socket;

    return 0;
}

int init_nt_icmp(struct nt_session *nts) {
    nts->icmp_ctx->send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nts->icmp_ctx->send_socket < 0) {
        deinit_nt_session(nts);
        return nts->icmp_ctx->send_socket;
    }

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
            if (init_nt_icmp_icmp(nts) < 0) {
                return -1;
            }

            break;
        }

        default: 
            return -1;
    }

    nts->icmp_ctx->pfd = (struct pollfd){
        .fd = nts->icmp_ctx->read_socket,
        .events = POLLIN,
    };

    return 0;
}

int nt_read_icmp(struct nt_session *nts, struct nt_read_packet *pkt) {
    int n = poll(&nts->icmp_ctx->pfd, 1, 1000);
    if (n > 0) {
        switch (nts->method) {
            case nt_method_icmp_unreach_icmp:
            case nt_method_icmp_unreach_udp:
                return read_icmp_error(nts, pkt, ICMP_DEST_UNREACH);

            case nt_method_icmp_exceeded_icmp:
            case nt_method_icmp_exceeded_udp:
                return read_icmp_error(nts, pkt, ICMP_TIME_EXCEEDED);
        }
    }

    return -1;
}

int nt_send_icmp(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_unreach_udp:
            return send_icmp_error(nts, pkt, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);

        case nt_method_icmp_exceeded_icmp:
        case nt_method_icmp_exceeded_udp:
            return send_icmp_error(nts, pkt, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);      
    }

    return -1;
}
