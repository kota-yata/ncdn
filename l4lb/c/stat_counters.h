#pragma once
#include <stdint.h>

struct stat_counters { /* go:Add,String */
  uint64_t rx_packet_total; // HELP Number of packets received against known VIPs.
  uint64_t rx_total_size; // HELP Total size of packets received against known VIPs.

  uint64_t too_short_packet_total; // HELP Number of packets dropped due to being too short.
  uint64_t non_ipv4_packet_total; // HELP Number of packets dropped due to their IP protocol version not v4.
  uint64_t ip_option_packet_total; // HELP Number of packets dropped due to their IP header having options. (currently not supported)
  uint64_t non_supported_proto_packet_total; // HELP Number of packets dropped due to their protocol not being TCP.
  uint64_t no_vip_match_total; // HELP Number of packets dropped due to their dest IP address not matching any known VIP.
  uint64_t failed_adjust_head_total; // HELP Number of xdp_adjust_head failures.
  uint64_t failed_adjust_tail_total; // HELP Number of xdp_adjust_tail failures.
  
  uint64_t quic_packet_total; // HELP Number of QUIC packets detected.
  uint64_t quic_long_header_total; // HELP Number of QUIC long header packets detected.
  uint64_t quic_short_header_total; // HELP Number of QUIC short header packets detected.
  uint64_t invalid_quic_packet_total; // HELP Number of invalid QUIC packets detected.
} ALIGN8;
