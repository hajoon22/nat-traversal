#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "../traversal.h"

struct read_session {
    uint32_t id;
    
    uint8_t *buffer;
    size_t data_length;

    uint16_t next_offset;
};

struct read_session sessions[MAX_SESSIONS];

static void clean_read_session(int i) {
    sessions[i].id = 0;
    if (sessions[i].buffer != NULL) {
        free(sessions[i].buffer);
        sessions[i].buffer = NULL;
    }
    sessions[i].data_length = 0;
    sessions[i].next_offset = 0;
}

static int find_free_index() {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].id == 0) {
            return i;
        }
    }

    return -1;
}

static int find_session(uint32_t id) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].id == id) {
            return i;
        }
    }

    return -1;
}

static void build_handshake_request(uint32_t id, uint8_t buf[7], uint16_t length) {
    buf[0] = 1;

    id = htonl(id);
    memcpy(buf+1, &id, sizeof(id));

    length = htons(length);
    memcpy(buf+5, &length, sizeof(length));
}

static void parse_handshake_request(uint8_t *buf, size_t length) {
    if (length != 7 || buf[0] != 1) return;

    uint32_t id = 0;
    memcpy(&id, buf+1, sizeof(id));
    id = ntohl(id);

    if (find_session(id) >= 0) return;

    int i = find_free_index();
    if (i < 0) return;

    clean_read_session(i);

    uint16_t data_size = 0;
    memcpy(&data_size, buf+5, sizeof(data_size));
    data_size = ntohs(data_size);

    sessions[i].data_length = data_size;
    sessions[i].buffer = calloc(data_size, sizeof(uint8_t));
    if (!sessions[i].buffer) {
        return;
    }

    sessions[i].id = id;
}

static ssize_t build_data_pakcet(uint32_t id, uint8_t **buf, uint8_t *data, uint16_t length, uint16_t offset) {
    size_t total_length = 9+length;
    *buf = calloc(total_length, sizeof(uint8_t));
    if (!*buf) return -1;

    size_t off = 0;

    (*buf)[off] = 2;
    off += sizeof(uint8_t);

    id = htonl(id);
    memcpy(*buf+off, &id, sizeof(id));
    off += sizeof(id);

    offset = htons(offset);
    memcpy(*buf+off, &offset, sizeof(offset));
    off += sizeof(offset);

    length = htons(length);
    memcpy(*buf+off, &length, sizeof(length));
    off += sizeof(length);

    memcpy(*buf+off, data, ntohs(length));

    return total_length;
}

static int parse_data_packet(uint8_t *buf, size_t length) {
    if (length < 9 || buf[0] != 2) return -1;

    uint32_t id = 0;
    memcpy(&id, buf+1, sizeof(id));
    id = ntohl(id);

    int i = find_session(id);
    if (i < 0) return -1;

    uint16_t offset = 0;
    memcpy(&offset, buf+5, sizeof(offset));
    offset = ntohs(offset);
    if (offset != sessions[i].next_offset) {
        return -1;
    }

    uint16_t data_size = 0;
    memcpy(&data_size, buf+7, sizeof(data_size));
    data_size = ntohs(data_size);
    if ((size_t)data_size > length-9) return -1;
    if ((size_t)offset+data_size > sessions[i].data_length) return -1;
    

    sessions[i].next_offset = offset+data_size;
    memcpy(sessions[i].buffer+offset, buf+9, data_size);

    if (sessions[i].next_offset == sessions[i].data_length) {
        return i;
    }

    return -1;
}

static int nt_send_safe(struct nt_session *nts, struct nt_send_packet *pkt) {
    for (int i = 0; i < SAFE_COUNT; i++) {
        if (nt_send(nts, pkt) < 0) {
            return -1;
        }
    }

    return 0;
}

int nt_proto_send_safe(struct nt_session *nts, struct nt_send_packet *spkt) {
    if (spkt == NULL || spkt->data == NULL || 
        nts == NULL || spkt->data_len == 0) {
        return -1;
    }

    uint32_t id = arc4random();

    uint8_t hs_req[7] = {0};
    build_handshake_request(id, hs_req, spkt->data_len);

    struct nt_send_packet pkt = {0};
    memcpy(&pkt, spkt, sizeof(struct nt_send_packet));
    pkt.data = hs_req;
    pkt.data_len = sizeof(hs_req);

    if (nt_send_safe(nts, &pkt) < 0) {
        return -1;
    }

    uint8_t *buf = NULL;
    ssize_t ret = 0, offset = 0, length = 0;
    while (offset != spkt->data_len) {
        length = spkt->data_len - offset;
        if (length > CHUNK_SIZE) {
            length = CHUNK_SIZE;
        }

        ret = build_data_pakcet(id, &buf, spkt->data+offset, length, offset);
        if (ret < 0) return -1;

        pkt.data = buf;
        pkt.data_len = ret;

        offset += length;

        ret = nt_send_safe(nts, &pkt);
        free(buf);
        buf = NULL;
        if (ret < 0) return -1;
    }

    return 0;
}

ssize_t nt_proto_read_safe(struct nt_session *nts, uint8_t **buf) {
    int i = 0;
    struct nt_read_packet pkt = {0};
    while (1) {
        if (nt_read(nts, &pkt) < 0) {
            return -1;
        }

        parse_handshake_request(pkt.data, pkt.data_len);
        int ret = parse_data_packet(pkt.data, pkt.data_len);
        deinit_nt_read_packet(&pkt);
        if (ret >= 0) {
            i = ret;
            break;
        }
    }

    size_t length = (size_t)sessions[i].data_length;
    *buf = calloc(length, sizeof(uint8_t));
    if (!*buf) {
        clean_read_session(i);
        return -1;
    }

    memcpy(*buf, sessions[i].buffer, length);

    clean_read_session(i);
    return length;
}
