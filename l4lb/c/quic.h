#pragma once
#include <stdint.h>

#include "stat_counters.h"

#if DEBUG_LB_MAIN
#define debugk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debugk(fmt, ...) \
  do {                   \
  } while (0)
#endif

#define QUIC_PACKET_TYPE_INITIAL    0x00
#define QUIC_PACKET_TYPE_0_RTT      0x01
#define QUIC_PACKET_TYPE_HANDSHAKE  0x02
#define QUIC_PACKET_TYPE_RETRY      0x03

#define QUIC_CID_DEFAULT_LEN 17

struct quic_lb_cid {
  uint8_t config;
  uint8_t server_id;
  uint32_t nonce;
};

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

static __always_inline bool is_valid_quic_packet(void* quic_data, void* data_end, struct stat_counters* c) {
  uint8_t* quic_bytes = (uint8_t*)quic_data;
  
  if (quic_bytes >= (uint8_t*)data_end) {
    return false;
  }
  
  uint8_t first_byte = *quic_bytes;
  
  // Check fixed bit (must be 1 for valid QUIC packets)
  if ((first_byte & 0x40) == 0) {
    ++c->invalid_quic_packet_total;
    return false;
  }
  
  // Additional validation for long header packets
  if (QUIC_IS_LONG_HEADER(first_byte)) {
    // Need at least 5 bytes for basic long header (flags + version)
    if (quic_bytes + 5 > (uint8_t*)data_end) {
      ++c->invalid_quic_packet_total;
      return false;
    }
    
    // Check version (should not be 0 for valid packets, except version negotiation)
    uint32_t version = *(uint32_t*)(quic_bytes + 1);
    if (version == 0) {
      // This might be a version negotiation packet, still valid
      debugk("QUIC version negotiation packet detected");
    }
  }
  
  return true;
}
