#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "../traversal.h"
#include "nt.h"

#include "unreach.h"
#include "../stun/stun.h"

void deinit_nt_icmp_unreach(struct nt_icmp_unreach_context *icmp_unreach) {
    if (icmp_unreach->socket >= 0) {
        close(icmp_unreach->socket);
    }
}

int init_nt_icmp_unreach(struct nt_session *nts) {
    nts->socket = init_stun(
        nts->stun_addr, nts->stun_port, 
        &nts->icmp_unreach.pub_addr, 
        &nts->icmp_unreach.mapped_port);

    if (nts->socket < 0) {
        return nts->socket;
    }
    
    nts->keepalive_pid = init_keepalive(nts->socket);
    if (nts->keepalive_pid < 0) {
        deinit_nt_session(nts);
        return nts->keepalive_pid;
    }

    nts->icmp_unreach.socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nts->icmp_unreach.socket < 0) {
        deinit_nt_session(nts);
        return nts->icmp_unreach.socket;
    }

    nts->icmp_unreach.pfd = (struct pollfd){
        .fd = nts->icmp_unreach.socket,
        .events = POLLIN,
    };

    return 0;
}

int nt_read_icmp_unreach(struct nt_session *nts, struct nt_read_packet *rpkt) {
    int n = poll(&nts->icmp_unreach.pfd, 1, 1000);
    if (n > 0) {
        int n = read_icmp_unreach(nts->icmp_unreach.socket, nts->stun_addr, &rpkt->icmpun);
        if (n < 0) {
            return n;
        }
        rpkt->method = nts->method;
        
        return 0;
    }

    return -1;
}

int nt_send_icmp_unreach(struct nt_session *nts, struct nt_send_packet *spkt) {
    return send_icmp_unreach(
        nts->icmp_unreach.socket, 
        spkt->daddr, spkt->dport, 
        nts->stun_addr, nts->stun_port, 
        spkt->data, spkt->data_len);
}
