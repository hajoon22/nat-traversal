#ifndef ICMP_NT_H
#define ICMP_NT_H

#include <stdint.h>
#include <poll.h>

struct nt_session;
struct nt_read_packet;
struct nt_send_packet;

struct nt_icmp_context {
    int socket; // icmp socket
    struct pollfd pfd;

    uint32_t pub_addr;
    uint16_t mapped_port;
};

int init_nt_icmp(struct nt_session *nts);
void deinit_nt_icmp_context(struct nt_icmp_context *ctx);

int nt_read_icmp(struct nt_session *nts, struct nt_read_packet *pkt);
int nt_send_icmp(struct nt_session *nts, struct nt_send_packet *pkt);

#endif
