/*
ICMP Destination Unreachable (UDP) NAT Traversal 
Server Example
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.stun_addr = ntohl(inet_addr("74.125.250.129"));
    nts.stun_port = 19302;
    nts.method = nt_method_icmp_unreach_udp;

    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }
    
    struct in_addr a;
    a.s_addr = htonl(nts.pub_addr);
    printf("mapped: %s:%d (udp)\n", inet_ntoa(a), nts.mapped_port);

    struct nt_read_packet rpkt;
    while (1) {
        if (nt_read(&nts, &rpkt) < 0) {
            continue;
        }

        printf("recived data: %.*s\n", (int)rpkt.data_len, (char *)rpkt.data);
        deinit_nt_read_packet(&rpkt);

        break;
    }

    deinit_nt_session(&nts);

    return 0;
}
