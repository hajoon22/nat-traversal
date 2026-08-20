/*
SPOOF ICMP ECHO NAT Traversal 
Server Example

Verified Environments
GAPD-7500R (FW 1.03.10, 2026-02-13) Cone NAT (Endpoint-Independent Mapping)
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.istun_addr = ntohl(inet_addr("1.1.1.1"));
    nts.stun_addr = ntohl(inet_addr("74.125.250.129"));
    nts.relay_addr = ntohl(inet_addr("127.0.0.1"));
    nts.stun_port = 19302;
    nts.method = nt_method_spoof_echo_reflection;

    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct in_addr a;
    a.s_addr = htonl(nts.pub_addr);
    printf("public ip = %s, mapped id = %d\n", inet_ntoa(a), nts.mapped_id);

    struct nt_read_packet rpkt;
    while (1) {
        if (nt_read(&nts, &rpkt) < 0) {
            continue;
        }

        printf("received data: %.*s\n", (int)rpkt.data_len, (char *)rpkt.data);
        deinit_nt_read_packet(&rpkt);

        break;
    }

    deinit_nt_session(&nts);

    return 0;
}
