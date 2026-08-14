#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdarg.h>

#include "traversal.h"

#include "icmp/nt.h"
#include "icmp/icmp.h"

#include "spoof/nt.h"
#include "spoof/udp/udp.h"
#include "spoof/echo/echo.h"

#include "common/local.h"

int init_nt_session(struct nt_session *nts, ...) {
    va_list ap;
    va_start(ap, nts);

    if (get_local_addr(&nts->local_addr) < 0) {
        return -1;
    }

    nts->keepalive_pid = -1;
    switch (nts->method) {
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_exceeded_icmp: {
            nts->icmp_ctx = calloc(1, sizeof(struct nt_icmp_context));
            if (!nts->icmp_ctx) {
                return -1;
            }

            return init_nt_icmp(nts);
        }

        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp: {
            nts->icmp_ctx = calloc(1, sizeof(struct nt_icmp_context));
            if (!nts->icmp_ctx) {
                return -1;
            }

            return init_nt_icmp(nts);
        }

        case nt_method_spoof_udp_local:        
        case nt_method_spoof_udp_direct:
        case nt_method_spoof_echo_reflection: {
            nts->spoof_ctx = calloc(1, sizeof(struct nt_spoof_context));
            if (!nts->spoof_ctx) {
                return -1;
            }

            if (nts->method != nt_method_spoof_udp_local) {
                nts->spoof_ctx->relay_addr = va_arg(ap, uint32_t);
            }
            
            return init_nt_spoof(nts);
        }
    }

    return -1;
}

void deinit_nt_session(struct nt_session *nts) {
    if (nts->keepalive_pid >= 0) {
        kill(nts->keepalive_pid, SIGTERM);
        waitpid(nts->keepalive_pid, NULL, 0);
    }

    switch (nts->method) {
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_exceeded_icmp:
            return deinit_nt_icmp_context(nts->icmp_ctx);

        case nt_method_spoof_udp_local:
        case nt_method_spoof_udp_direct:
        case nt_method_spoof_echo_reflection:
            return deinit_nt_spoof_context(nts->spoof_ctx);
    }
}

int nt_read(struct nt_session *nts, struct nt_read_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_exceeded_icmp:
            return nt_read_icmp(nts, pkt);

        case nt_method_spoof_udp_local:
        case nt_method_spoof_udp_direct:
        case nt_method_spoof_echo_reflection:
            return nt_read_spoof(nts, pkt);
    }

    return -1;
}

int nt_send(struct nt_session *nts, struct nt_send_packet *pkt) {
    switch (nts->method) {
        case nt_method_icmp_exceeded_udp:
        case nt_method_icmp_unreach_udp:
        case nt_method_icmp_unreach_icmp:
        case nt_method_icmp_exceeded_icmp:
            return nt_send_icmp(nts, pkt);
 
        case nt_method_spoof_udp_local:
        case nt_method_spoof_udp_direct:
        case nt_method_spoof_echo_reflection:
            return nt_send_spoof(nts, pkt);
    }

    return -1;
}

void deinit_nt_read_packet(struct nt_read_packet *pkt) {
    free(pkt->iph);
    free(pkt->data);
}
