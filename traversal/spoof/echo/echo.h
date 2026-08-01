#ifndef SPOOF_ECHO_H
#define SPOOF_ECHO_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>

#include "../../traversal.h"

#define MAX_DATA_BUFFER 1500

int send_spoof_echo(struct nt_session *nts, struct nt_send_packet *pkt);
int read_spoof_echo(struct nt_session *nts, struct nt_read_packet *pkt);

#endif
