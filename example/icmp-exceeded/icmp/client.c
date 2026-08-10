/*
ICMP Time Exceeded (ICMP) NAT Traversal 
Client Example
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.method = nt_method_icmp_exceeded_icmp;
    nts.istun_addr = ntohl(inet_addr(""));

    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct nt_send_packet spkt;
    spkt.did = 1111; // dst icmp id
    spkt.daddr = ntohl(inet_addr("")); // dst
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
