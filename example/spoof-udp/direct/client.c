/*
SPOOF UDP Direct NAT Traversal 
Client Example

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
    nts.relay_addr = ntohl(inet_addr("1.1.1.1"));
    nts.stun_port = 19302;
    nts.method = nt_method_spoof_udp_direct;
    
    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct nt_send_packet spkt;
    spkt.daddr = ntohl(inet_addr("0.0.0.0")); // dst
    spkt.dport = 16797;
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
