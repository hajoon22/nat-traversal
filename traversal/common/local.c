#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int get_local_addr(uint32_t *addr) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return s;

    struct sockaddr_in dsin = {0};
    dsin.sin_family = AF_INET;
    dsin.sin_port = htons(53);
    dsin.sin_addr.s_addr = inet_addr("8.8.8.8");
        
    connect(s, (struct sockaddr *)&dsin, sizeof(dsin));

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr *)&local, &len);

    *addr = ntohl(local.sin_addr.s_addr);
    close(s);

    return 0;
}
