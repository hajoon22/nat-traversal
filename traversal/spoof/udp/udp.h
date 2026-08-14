#ifndef SPOOF_UDP_H
#define SPOOF_UDP_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>

#include "../../traversal.h"

int read_spoof_udp(struct nt_session *nts, struct nt_read_packet *pkt);

int send_spoof_udp(struct nt_session *nts, struct nt_send_packet *pkt);
int send_spoof_udp_local(struct nt_session *nts, struct nt_send_packet *pkt);

#endif
