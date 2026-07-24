#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "traversal.h"

#include "icmp/nt.h"
#include "icmp/unreach/unreach.h"
#include "icmp/exceeded/exceeded.h"

#include "spoof/nt.h"
#include "spoof/udp/udp.h"

int init_nt_session(struct nt_session *nts) {
    switch (nts->method) {
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_unreach_icmp:
            return init_nt_icmp(nts);
        case nt_method_spoof_udp:
            return init_nt_spoof(nts);
    }

    return -1;
}

void deinit_nt_session(struct nt_session *nts) {
    if (nts->keepalive_pid >= 0) {
        kill(nts->keepalive_pid, SIGTERM);
        waitpid(nts->keepalive_pid, NULL, 0);
    }
    
    if (nts->socket >= 0) {
        close(nts->socket);
    } 

    switch (nts->method) {
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_icmp:
            return deinit_nt_icmp_context(&nts->icmp_ctx);
        case nt_method_spoof_udp:
            return deinit_nt_spoof_context(&nts->spoof_ctx);
    }
}

int nt_read(struct nt_session *nts, struct nt_read_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_unreach_icmp:
            return nt_read_icmp(nts, pkt);
        case nt_method_spoof_udp:
            return nt_read_spoof(nts, pkt);
    }

    return -1;
}

int nt_send(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_unreach_icmp:
            return nt_send_icmp(nts, pkt);
        case nt_method_spoof_udp:
            return nt_send_spoof(nts, pkt);
    }

    return -1;
}

void deinit_nt_read_packet(struct nt_read_packet *pkt) {
    switch (pkt->method) {
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_unreach_udp:
            return deinit_icmp_unreach(&pkt->icmpun);
        case nt_method_icmp_exceeded_udp:
            return deinit_icmp_exceeded(&pkt->icmptime);
        case nt_method_spoof_udp:
            return deinit_spoof_udp(&pkt->spoofudp);
    }
}
