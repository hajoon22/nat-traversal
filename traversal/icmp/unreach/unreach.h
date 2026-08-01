#ifndef ICMP_UNREACH_H
#define ICMP_UNREACH_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "../../traversal.h"

#define MAX_DATA_BUFFER 1500

int send_icmp_unreach(struct nt_session *nts, struct nt_send_packet *pkt);
int read_icmp_unreach(struct nt_session *nts, struct nt_read_packet *pkt);

#endif
