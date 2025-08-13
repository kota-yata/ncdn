#ifndef QUIC_H
#define QUIC_H

#include <stdint.h>

// QUIC packet types for long header
#define QUIC_PACKET_TYPE_INITIAL    0x00
#define QUIC_PACKET_TYPE_0_RTT      0x01
#define QUIC_PACKET_TYPE_HANDSHAKE  0x02
#define QUIC_PACKET_TYPE_RETRY      0x03

struct quic_long_header {
    uint8_t flags;
    uint32_t version;
    uint8_t dcid_len;
} __attribute__((packed));

struct quic_short_header {
    uint8_t flags;
} __attribute__((packed));

#define QUIC_IS_LONG_HEADER(flags) ((flags) & 0x80)
#define QUIC_GET_PACKET_TYPE(flags) (((flags) >> 4) & 0x03)
#define QUIC_GET_PKT_NUM_LEN(flags) (((flags) & 0x03) + 1)

#endif
