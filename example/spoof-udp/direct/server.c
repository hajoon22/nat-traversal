/*
SPOOF UDP Direct NAT Traversal 
Server Example

Verified Environments
Ubuntu (kernel 6.8.0-71-generic, x86_64) Full Cone NAT
Ubuntu (kernel 6.8.0-71-generic, x86_64) Restricted Cone NAT
Ubuntu (kernel 6.8.0-71-generic, x86_64) Port-Restricted Cone NAT
Ubuntu (kernel 6.8.0-71-generic, x86_64) Symmetric NAT (MASQUERADE --random-fully)
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.stun_addr = ntohl(inet_addr("74.125.250.129"));
    nts.relay_addr = ntohl(inet_addr("127.0.0.1"));
    nts.stun_port = 19302;
    nts.method = nt_method_spoof_udp_direct;

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

        printf("received data: %.*s\n", (int)rpkt.data_len, (char *)rpkt.data);
        deinit_nt_read_packet(&rpkt);

        break;
    }

    deinit_nt_session(&nts);

    return 0;
}
