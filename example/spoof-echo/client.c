/*
SPOOF UDP NAT Traversal 
Client Example
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.stun_addr = ntohl(inet_addr("74.125.250.129"));
    nts.stun_port = 19302;
    nts.method = nt_method_spoof_echo_reflection;

    uint32_t relay_addr = ntohl(inet_addr("127.0.0.1"));

    if (init_nt_session(&nts, relay_addr) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct nt_send_packet spkt;
    spkt.daddr = ntohl(inet_addr("1.1.1.1")); // dst
    spkt.data = "hello!";
    spkt.data_len = 6;

    if (nt_send(&nts, &spkt) < 0) {
        printf("nt send error\n");
        return -1;
    }
    printf("sent\n");

    deinit_nt_session(&nts);

    return 0;
}
