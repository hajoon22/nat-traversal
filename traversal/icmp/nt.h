#ifndef ICMP_NT_H
#define ICMP_NT_H

#include <stdint.h>
#include <poll.h>

#include "../traversal.h"

#define ECHO_ID 1111
#define ECHO_SEQ 2222
#define ECHO_ADDR "1.1.1.1"

struct nt_icmp_context {
    int socket; // icmp socket
    struct pollfd pfd;

    // icmp echo
    uint16_t id;
    uint16_t seq;
    uint32_t addr;
};

int init_nt_icmp(struct nt_session *nts);
void deinit_nt_icmp_context(struct nt_icmp_context *ctx);

int nt_read_icmp(struct nt_session *nts, struct nt_read_packet *pkt);
int nt_send_icmp(struct nt_session *nts, struct nt_send_packet *pkt);

#endif
