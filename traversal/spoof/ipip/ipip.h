#ifndef IPIP_H
#define IPIP_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

int send_ipip(int s, uint32_t src, uint32_t dst, struct iphdr *iph, struct udphdr *udph, uint8_t *data, size_t data_len);

#endif
