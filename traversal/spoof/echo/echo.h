#ifndef SPOOF_ECHO_H
#define SPOOF_ECHO_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>

#define MAX_DATA_BUFFER 1500

struct nt_session;
struct nt_read_packet;
struct nt_send_packet;

struct spoof_echo {
    uint8_t *data;
    size_t data_len;
};

void deinit_spoof_echo(struct spoof_echo *spoofecho);

int send_spoof_echo(struct nt_session *nts, struct nt_send_packet *pkt);
int read_spoof_echo(struct nt_session *nts, struct nt_read_packet *pkt);

#endif
