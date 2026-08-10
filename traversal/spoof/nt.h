#ifndef NT_SPOOF_H
#define NT_SPOOF_H

#include <stdint.h>
#include <poll.h>

#include "../traversal.h"

#define ECHO_ID 1111
#define ECHO_SEQ 2222

struct nt_spoof_context {
    int send_socket;
    int read_socket;
    int keepalive_socket;

    struct pollfd pfd;

    uint32_t relay_addr;

    uint32_t addr;
};

int init_nt_spoof(struct nt_session *nts);
void deinit_nt_spoof_context(struct nt_spoof_context *ctx);

int nt_read_spoof(struct nt_session *nts, struct nt_read_packet *pkt);
int nt_send_spoof(struct nt_session *nts, struct nt_send_packet *pkt);

#endif
