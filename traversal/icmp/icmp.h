#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include "../traversal.h"

int read_icmp_error(struct nt_session *nts, struct nt_read_packet *pkt, uint8_t type);
int send_icmp_error(struct nt_session *nts, struct nt_send_packet *pkt, uint8_t type, uint8_t code);

#endif
