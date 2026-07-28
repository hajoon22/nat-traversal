#ifndef IPIP_H
#define IPIP_H

#include <stdint.h>
#include <netinet/ip.h>

int send_ipip(int s, uint32_t src, uint32_t dst, uint8_t *inner, size_t inner_len);

#endif
