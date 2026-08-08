#ifndef ISTUN_H
#define ISTUN_H

#define MAX_DATA_BUFFER 1500
#define REPLY_SIZE sizeof(struct icmphdr)+sizeof(uint16_t)

int init_istun();
int send_istun_request(uint32_t istun_addr, uint16_t sid);

#endif
