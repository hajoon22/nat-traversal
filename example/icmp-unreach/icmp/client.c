/*
ICMP Destination Unreachable (ICMP) NAT Traversal 
Client Example
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.method = nt_method_icmp_unreach_icmp;

    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct nt_send_packet spkt;
    spkt.daddr = ntohl(inet_addr("0.0.0.0")); // dst
    spkt.data = "hello";
    spkt.data_len = 5;

    if (nt_send(&nts, &spkt) < 0) {
        printf("nt send error\n");
        return -1;
    }
    printf("sent\n");

    deinit_nt_session(&nts);

    return 0;
}
