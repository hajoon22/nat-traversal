#ifndef NT_SPOOF_H
#define NT_SPOOF_H

#include <stdint.h>
#include <poll.h>

struct nt_session;
struct nt_read_packet;
struct nt_send_packet;

struct nt_spoof_context {
    int socket;
    struct pollfd pfd;

    uint32_t pub_addr;
    uint16_t mapped_port;

    uint32_t relay_addr;
};

int init_nt_spoof(struct nt_session *nts);
void deinit_nt_spoof_context(struct nt_spoof_context *ctx);

int nt_read_spoof(struct nt_session *nts, struct nt_read_packet *pkt);
int nt_send_spoof(struct nt_session *nts, struct nt_send_packet *pkt);

#endif
