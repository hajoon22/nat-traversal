#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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

    struct in_addr a;
    a.s_addr = htonl(nts.pub_addr);
    printf("mapped: %s:%d (udp)\n", inet_ntoa(a), nts.mapped_port);

    uint8_t *buf = NULL;
    while (1) {
        ssize_t ret = nt_proto_read_safe(&nts, &buf);
        if (ret < 0) {
            continue;
        }

        printf("received data: %.*s\n", (int)ret, (char *)buf);
        free(buf);

        break;
    }

    deinit_nt_session(&nts);

    return 0;
}
