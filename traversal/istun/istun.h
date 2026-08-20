#ifndef ISTUN_H
#define ISTUN_H

#define REPLY_SIZE (sizeof(struct icmphdr)+sizeof(uint16_t))

#define ISTUN_REQUEST 2010
#define ISTUN_REPLY 2222

int init_istun();
int send_istun_request(uint32_t istun_addr, uint16_t sid);

#endif
