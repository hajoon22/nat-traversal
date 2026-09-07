#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../traversal/traversal.h"
#include "../../traversal/safe_proto/protocol.h"

int main(void) {
    struct nt_session nts;
    nts.stun_addr = ntohl(inet_addr("74.125.250.129"));
    nts.stun_port = 19302;
    nts.method = nt_method_icmp_unreach_udp;

    if (init_nt_session(&nts) < 0) {
        printf("init nt session error\n");
        return -1;
    }

    struct nt_send_packet spkt;
    spkt.daddr = ntohl(inet_addr("")); // dst
    spkt.dport = 2222;
    spkt.data = "hello";
    spkt.data_len = 5;

    int ret = nt_proto_send_safe(&nts, &spkt);
    if (ret < 0) {
        deinit_nt_session(&nts);
        return -1;
    }

    printf("sent\n");
    deinit_nt_session(&nts);

    return 0;
}
