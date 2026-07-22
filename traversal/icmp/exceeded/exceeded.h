#ifndef ICMP_EXCEEDED_H
#define ICMP_EXCEEDED_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MAX_DATA_BUFFER 1500

struct nt_session;
struct nt_read_packet;
struct nt_send_packet;

struct icmp_exceeded {
    struct iphdr iph;
    struct icmphdr icmph;

    uint8_t *data;
    size_t data_len;
};

void deinit_icmp_exceeded(struct icmp_exceeded *icmptime);

int send_icmp_exceeded(struct nt_session *nts, struct nt_send_packet *pkt);
int read_icmp_exceeded(struct nt_session *nts, struct nt_read_packet *pkt);

#endif
