/*
SPOOF ICMP ECHO NAT Traversal 
Client Example

Verified Environments
GAPD-7500R (FW 1.03.10, 2026-02-13) Cone NAT
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.istun_addr = ntohl(inet_addr(""));
    nts.stun_addr = ntohl(inet_addr("74.125.250.129"));
    nts.stun_port = 19302;
    nts.method = nt_method_spoof_echo_reflection;

    uint32_t relay_addr = ntohl(inet_addr(""));

    if (init_nt_session(&nts, relay_addr) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct nt_send_packet spkt;
    spkt.did = 1111; // dst icmp id
    spkt.daddr = ntohl(inet_addr("")); // dst
    spkt.data = "apple";
    spkt.data_len = 5;

    if (nt_send(&nts, &spkt) < 0) {
        printf("nt send error\n");
        return -1;
    }
    printf("sent\n");

    deinit_nt_session(&nts);

    return 0;
}
