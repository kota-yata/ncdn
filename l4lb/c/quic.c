#include "quic.h"

static inline bool is_valid_quic_packet(uint8_t* quic_data, void* data_end, struct stat_counters* c) {
  if (quic_data >= (uint8_t*)data_end) {
    return false;
  }
  
  uint8_t first_byte = *quic_data;
  
  // Check fixed bit (must be 1 for valid QUIC packets)
  if ((first_byte & 0x40) == 0) {
    ++c->invalid_quic_packet_total;
    return false;
  }
  
  // Additional validation for long header packets
  if (QUIC_IS_LONG_HEADER(first_byte)) {
    // Need at least 5 bytes for basic long header (flags + version)
    if (quic_data + 5 > (uint8_t*)data_end) {
      ++c->invalid_quic_packet_total;
      return false;
    }
    
    // Check version (should not be 0 for valid packets, except version negotiation)
    uint32_t version = *(uint32_t*)(quic_data + 1);
    if (version == 0) {
      // This might be a version negotiation packet, still valid
      debugk("QUIC version negotiation packet detected");
    }
  }
  
  return true;
}
