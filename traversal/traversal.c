#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "traversal.h"

#include "icmp/nt.h"
#include "icmp/unreach.h"
#include "icmp/exceeded.h"

#include "spoof/nt.h"
#include "spoof/udp.h"

int init_nt_session(struct nt_session *nts) {
    switch (nts->method) {
        case nt_method_icmp_exceeded:
        case nt_method_icmp_unreach:
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
        case nt_method_icmp_unreach:
        case nt_method_icmp_exceeded:
            return deinit_nt_icmp_context(&nts->icmp_ctx);
        case nt_method_spoof_udp:
            return deinit_nt_spoof_context(&nts->spoof_ctx);
    }
}

int nt_read(struct nt_session *nts, struct nt_read_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_exceeded:
        case nt_method_icmp_unreach:
            return nt_read_icmp(nts, pkt);
        case nt_method_spoof_udp:
            return nt_read_spoof(nts, pkt);
    }

    return -1;
}

int nt_send(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_exceeded:
        case nt_method_icmp_unreach:
            return nt_send_icmp(nts, pkt);
        case nt_method_spoof_udp:
            return nt_send_spoof(nts, pkt);
    }

    return -1;
}

void deinit_nt_read_packet(struct nt_read_packet *pkt) {
    switch (pkt->method) {
        case nt_method_icmp_unreach:
            return deinit_icmp_unreach(&pkt->icmpun);
        case nt_method_icmp_exceeded:
            return deinit_icmp_exceeded(&pkt->icmptime);
        case nt_method_spoof_udp:
            return deinit_spoof_udp(&pkt->spoofudp);
    }
}
