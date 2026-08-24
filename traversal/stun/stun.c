#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h> 
#include <poll.h>

#include "../common/common.h"

static void build_binding_request(uint8_t buf[20]) {
    uint16_t type = htons(0x0001);
    uint32_t magic = htonl(0x2112A442); 

    memcpy(buf, &type, 2); // message type
    memset(buf+2, 0, 2); // message length
    memcpy(buf+4, &magic, 4); // magic cookie
    memset(buf+8, 0, 12); // transaction id (0)
}

static int parse_binding_reply(uint8_t *buf, size_t len, uint32_t *addr, uint16_t *port) {
    if (len < 20) return -1; // invalid header length
    
    uint16_t message_type;
    memcpy(&message_type, buf, 2);
    message_type = ntohs(message_type);
    if (message_type != 0x0101) return -1; // is not binding success reply

    uint16_t message_length;
    memcpy(&message_length, buf+2, 2);
    message_length = ntohs(message_length);
    if (message_length < 12) return -1;
    if (message_length+20 > len) return -1;

    int offset = 20;
    while (offset < message_length+20) {
        if (offset+4 > message_length+20) return -1; // invalid attribute length

        uint16_t attribute_type, attribute_length;
        memcpy(&attribute_type, buf+offset, 2);
        memcpy(&attribute_length, buf+offset+2, 2);
        attribute_type = ntohs(attribute_type);
        attribute_length = ntohs(attribute_length);

        int padding_length = (4-(attribute_length%4))%4;
        if (offset+4+attribute_length+padding_length > message_length+20) return -1;

        // X-MAPPED-ADDRESS
        if (attribute_type == 0x0020) {
            if (attribute_length == 8 && buf[offset+5] == 0x01) {
                 // x-port
                memcpy(port, buf+offset+6, 2);
                *port ^= htons(0x2112);
                *port = ntohs(*port);

                // x-address
                memcpy(addr, buf+offset+8, 4);
                *addr ^= htonl(0x2112A442);
                *addr = ntohl(*addr);

                return 0;
            }

            return -1; // invalid X-MAPPED-ADDRESS
        }

        offset = offset+4+attribute_length+padding_length;
    }

    return -1;
}

int init_stun(uint32_t stun_addr, uint16_t stun_port, uint32_t *addr, uint16_t *port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return s;

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(STUN_SRC_PORT);

    if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) {
        goto error;
    }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(stun_port);
    sin.sin_addr.s_addr = htonl(stun_addr);

    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        goto error;
    }

    uint8_t buf[20] = {0};
    build_binding_request(buf);
    if (send(s, buf, 20, 0) < 0) {
        goto error;   
    }

    struct pollfd pfd = {
        .fd = s,
        .events = POLLIN
    };

    // timeout: 10 sec
    int r = poll(&pfd, 1, 10000);
    if (r > 0) {
        uint8_t buf[MAX_DATA_BUFFER] = {0};
        ssize_t n = recv(s, buf, MAX_DATA_BUFFER, 0);
        if (n < 0) {
            goto error;
        }

        if (parse_binding_reply(buf, n, addr, port) < 0) {
            goto error;
        }

        return s;
    }

    goto error; // timeout
    error:
    close(s);
    return -1;
}
