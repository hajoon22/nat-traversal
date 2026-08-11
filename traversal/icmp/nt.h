#ifndef ICMP_NT_H
#define ICMP_NT_H

#include <stdint.h>
#include <poll.h>

#include "../traversal.h"

struct nt_icmp_context {
    int send_socket;
    int read_socket;
    int keepalive_socket;

    struct pollfd pfd;
};

int init_nt_icmp(struct nt_session *nts);
void deinit_nt_icmp_context(struct nt_icmp_context *ctx);

int nt_read_icmp(struct nt_session *nts, struct nt_read_packet *pkt);
int nt_send_icmp(struct nt_session *nts, struct nt_send_packet *pkt);

#endif
