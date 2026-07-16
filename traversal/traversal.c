#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "traversal.h"
#include "icmp/nt.h"
#include "icmp/unreach.h"

int init_nt_session(struct nt_session *nts) {
    switch (nts->method) {
    case nt_method_icmp_unreach:
        return init_nt_icmp_unreach(nts);
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
        return deinit_nt_icmp_unreach(&nts->icmp_unreach);
    }
}

int nt_read(struct nt_session *nts, struct nt_read_packet *rpkt) {
    switch (nts->method) {
    case nt_method_icmp_unreach:
        return nt_read_icmp_unreach(nts, rpkt);
    }

    return -1;
}

int nt_send(struct nt_session *nts, struct nt_send_packet *spkt) {
    switch (nts->method) {
    case nt_method_icmp_unreach:
        return nt_send_icmp_unreach(nts, spkt);
    }

    return -1;
}

void deinit_nt_read_packet(struct nt_read_packet *rpkt) {
    switch (rpkt->method) {
    case nt_method_icmp_unreach:
        return deinit_icmp_unreach(&rpkt->icmpun);
    }
}
