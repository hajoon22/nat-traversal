#ifndef TRAVERSAL_H
#define TRAVERSAL_H

#include <stddef.h>
#include <stdint.h>

#include "icmp/nt.h"
#include "icmp/unreach.h"
#include "icmp/exceeded.h"

// nat traversal method
enum nt_method {
    nt_method_icmp_unreach, 
    nt_method_icmp_exceeded,
};

struct nt_session {
    int socket;
    int keepalive_pid;
    
    uint32_t stun_addr;
    uint16_t stun_port;

    enum nt_method method;
    union {
        struct nt_icmp_context icmp_ctx;
    };
};

struct nt_read_packet {
    enum nt_method method;
    union {
        struct icmp_unreach icmpun;
        struct icmp_exceeded icmptime;
    };
};

struct nt_send_packet {
    uint32_t daddr;
    uint16_t dport;

    uint8_t *data;
    size_t data_len;
};

int init_nt_session(struct nt_session *nts);
void deinit_nt_session(struct nt_session *nts);

int nt_read(struct nt_session *nts, struct nt_read_packet *rpkt);
int nt_send(struct nt_session *nts, struct nt_send_packet *spkt);

void deinit_nt_read_packet(struct nt_read_packet *rpkt);

#endif
