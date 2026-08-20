/*
ICMP Destination Unreachable (ICMP) NAT Traversal 
Server Example

Ubuntu (kernel 6.8.0-71-generic, x86_64) Symmetric NAT (MASQUERADE --random-fully)
*/
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../../traversal/traversal.h"

int main(void) {
    struct nt_session nts;
    nts.method = nt_method_icmp_unreach_icmp;
    nts.istun_addr = ntohl(inet_addr(""));
    
    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }
    
    printf("mapped id = %d\n", nts.mapped_id);

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
