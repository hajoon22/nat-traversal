#ifndef TRAVERSAL_H
#define TRAVERSAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "istun/istun.h"

struct nt_spoof_context;
struct nt_icmp_context;

// nat traversal method
enum nt_method {
    nt_method_icmp_unreach_udp, 
    nt_method_icmp_unreach_icmp,
    nt_method_icmp_exceeded_udp,
    nt_method_icmp_exceeded_icmp,

    nt_method_spoof_udp_direct,
    nt_method_spoof_echo_reflection,

    nt_method_spoof_udp_local,
};

struct nt_session {
    int keepalive_pid;
    
    uint32_t stun_addr;
    uint16_t stun_port;
    uint16_t mapped_port;

    uint32_t istun_addr;
    uint16_t mapped_id;

    uint32_t pub_addr;
    uint32_t local_addr;
 
    enum nt_method method;
    union {
        struct nt_spoof_context *spoof_ctx;
        struct nt_icmp_context *icmp_ctx;
    };
};

struct nt_read_packet {
    struct iphdr *iph;
    
    uint8_t *data;
    size_t data_len;
};

struct nt_send_packet {
    uint32_t daddr; // dst public address
    uint32_t dlocal; // dst local address
    uint16_t dport; // dst port

    uint16_t did; // dst icmp id

    uint8_t *data;
    size_t data_len;
};

int init_nt_session(struct nt_session *nts, ...);
void deinit_nt_session(struct nt_session *nts);

int nt_read(struct nt_session *nts, struct nt_read_packet *rpkt);
int nt_send(struct nt_session *nts, struct nt_send_packet *spkt);

void deinit_nt_read_packet(struct nt_read_packet *rpkt);

#endif
