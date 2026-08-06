#ifndef ISTUN_H
#define ISTUN_H

#define MAX_DATA_BUFFER 1500
#define REPLY_SIZE sizeof(struct icmphdr)+sizeof(uint16_t)

int init_istun();

#endif
