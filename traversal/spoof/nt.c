#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "../traversal.h"
#include "../stun/stun.h"
#include "udp/udp.h"
#include "nt.h"

static int init_keepalive(int s) {
    int pid = fork();
    if (pid == 0) {
        while (1) {
            send(s, "hello", 5, 0); // keepalive
            sleep(10);
        }
    }

    return pid;
}

void deinit_nt_spoof_context(struct nt_spoof_context *ctx) {
    if (ctx->socket >= 0) {
        close(ctx->socket);
    }
}

int init_nt_spoof(struct nt_session *nts) {
    nts->socket = init_stun(
        nts->stun_addr, nts->stun_port, 
        &nts->spoof_ctx.pub_addr, 
        &nts->spoof_ctx.mapped_port);

    if (nts->socket < 0) {
        return nts->socket;
    }
    
    nts->keepalive_pid = init_keepalive(nts->socket);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    nts->spoof_ctx.socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (nts->spoof_ctx.socket < 0) {
        deinit_nt_session(nts);
        return nts->spoof_ctx.socket;
    }

    nts->spoof_ctx.pfd = (struct pollfd){
        .fd = nts->spoof_ctx.socket,
        .events = POLLIN,
    };

    return 0;
}

int nt_read_spoof(struct nt_session *nts, struct nt_read_packet *pkt) {
    switch (nts->method) {
        case nt_method_spoof_udp: {
            return read_spoof_udp(nts, pkt);
        }
    }

    return -1;
}

int nt_send_spoof(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_spoof_udp: {
           return send_spoof_udp(nts, pkt);
        }
    }

    return -1;
}
