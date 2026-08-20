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
#include "../istun/istun.h"
#include "../common/common.h"
#include "../common/checksum.h"
#include "../common/keepalive.h"

void deinit_nt_spoof_context(struct nt_spoof_context *ctx) {
    close(ctx->read_socket);
    if (ctx->read_socket != ctx->send_socket) {
        close(ctx->send_socket);
    }

    if (ctx->keepalive_socket != ctx->send_socket && ctx->keepalive_socket != ctx->read_socket) {
        close(ctx->keepalive_socket);
    }

    free(ctx);
}

static int init_nt_spoof_echo(struct nt_session *nts) {
    int ret = send_istun_request(nts->istun_addr, ECHO_ID);
    if (ret < 0) return ret;
    
    nts->mapped_id = ECHO_ID;
    if (ret != ECHO_ID) {
        nts->mapped_id = (uint16_t)ret;
    }
    
    nts->spoof_ctx->keepalive_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nts->spoof_ctx->keepalive_socket < 0) {
        return nts->spoof_ctx->keepalive_socket;
    }

    nts->keepalive_pid = init_keepalive_icmp(nts->spoof_ctx->keepalive_socket, nts->istun_addr);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    nts->spoof_ctx->read_socket = nts->spoof_ctx->keepalive_socket;

    return 0;
}

int init_nt_spoof(struct nt_session *nts) {
    nts->spoof_ctx->keepalive_socket = init_stun(
        nts->stun_addr, nts->stun_port, 
        &nts->pub_addr, 
        &nts->mapped_port);

    if (nts->spoof_ctx->keepalive_socket < 0) {
        return nts->spoof_ctx->keepalive_socket;
    }

    nts->spoof_ctx->send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (nts->spoof_ctx->send_socket < 0) {
        deinit_nt_session(nts);
        return nts->spoof_ctx->send_socket;
    }

    switch (nts->method) {
        case nt_method_spoof_udp_local:
        case nt_method_spoof_udp_direct: {
            nts->keepalive_pid = init_keepalive_udp(nts->spoof_ctx->keepalive_socket);
            if (nts->keepalive_pid < 0) {
                deinit_nt_session(nts);
                return nts->keepalive_pid;
            }

            nts->spoof_ctx->read_socket = nts->spoof_ctx->keepalive_socket;

            break;
        }

        case nt_method_spoof_echo_reflection: {
            close(nts->spoof_ctx->keepalive_socket);
        
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
            case nt_method_spoof_udp_local:
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

        case nt_method_spoof_udp_local: {
            return send_spoof_udp_local(nts, pkt);
        }
    }

    return -1;
}
