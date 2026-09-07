#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "../traversal.h"

#define SAFE_COUNT 5
#define CHUNK_SIZE 1000
#define MAX_SESSIONS 256

ssize_t nt_proto_read_safe(struct nt_session *nts, uint8_t **buf);
int nt_proto_send_safe(struct nt_session *nts, struct nt_send_packet *spkt);

#endif
