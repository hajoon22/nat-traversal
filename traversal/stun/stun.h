#ifndef STUN_H
#define STUN_H

#include <stdint.h>

int init_stun(uint32_t stun_addr, uint16_t stun_port, uint32_t *addr, uint16_t *port);

#endif
