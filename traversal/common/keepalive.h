#ifndef KEEPALIVE_H
#define KEEPALIVE_H

#include <stdint.h>

int init_keepalive_udp(int s);
int init_keepalive_icmp(int s, uint32_t istun_addr);

#endif
