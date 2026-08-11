#include <stdint.h> 
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "common.h"
#include "checksum.h"

int init_keepalive_udp(int s) {
    int pid = fork();
    if (pid == 0) {
        while (1) {
            send(s, "hello", 5, 0); // keepalive
            sleep(10);
        }
    }

    return pid;
}

int init_keepalive_icmp(int s, uint32_t istun_addr) {
    int pid = fork();
    if (pid == 0) {
        struct icmphdr icmph = {0};
        icmph.type = ICMP_ECHO;
        icmph.un.echo.id = htons(ECHO_ID);
        icmph.un.echo.sequence = htons(ECHO_SEQ);    
        icmph.checksum = htons(checksum((uint8_t *)&icmph, sizeof(icmph)));

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(istun_addr);

        while (1) {
            sendto(s, &icmph, sizeof(icmph), 0, (struct sockaddr *)&sin, sizeof(sin));
            sleep(5);
        }
    }

    return pid;
}
