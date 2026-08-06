#ifndef TRAVERSAL_H
#define TRAVERSAL_H

#include <stddef.h>
#include <stdint.h>

#include "istun/istun.h"

struct nt_spoof_context;
struct nt_icmp_context;

struct icmp_unreach;
struct icmp_exceeded;
struct spoof_udp;
struct spoof_echo;

// nat traversal method
enum nt_method {
    nt_method_icmp_unreach_udp, 
    nt_method_icmp_unreach_icmp,
    nt_method_icmp_exceeded_udp,
    nt_method_icmp_exceeded_icmp,

    nt_method_spoof_udp_direct,
    nt_method_spoof_echo_reflection,
};

struct nt_session {
    int socket;
    int keepalive_pid;
    
    uint32_t stun_addr;
    uint16_t stun_port;

    uint32_t pub_addr;
    uint16_t mapped_port;

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
    uint32_t daddr;
    uint16_t dport;

    uint8_t *data;
    size_t data_len;
};

int init_nt_session(struct nt_session *nts, ...);
void deinit_nt_session(struct nt_session *nts);

int nt_read(struct nt_session *nts, struct nt_read_packet *rpkt);
int nt_send(struct nt_session *nts, struct nt_send_packet *spkt);

void deinit_nt_read_packet(struct nt_read_packet *rpkt);

#endif
