#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "quic.h"

typedef enum { L4_UNKNOWN=0, L4_TCP=6, L4_UDP=17 } l4_kind_t;
typedef enum { APP_UNKNOWN=0, APP_QUIC=1 } app_kind_t;
typedef enum { QUIC_HDR_UNKNOWN=0, QUIC_HDR_LONG, QUIC_HDR_SHORT } quic_header_form_t;

typedef struct {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
} lb_tuple4_t;

typedef struct {
  quic_header_form_t hdr_form;
  const uint8_t *dcid;
  size_t dcid_len;
  uint8_t dcid_first_octet;
} lb_quic_t;

typedef struct {
  lb_tuple4_t t4;
  l4_kind_t l4;
  app_kind_t app;
  lb_quic_t quic;
  uint16_t backend_id;   // -1 if not assigned
} pkt_t;

static inline void lb_init(pkt_t *m) {
  memset(m, 0, sizeof(*m));
  m->backend_id = -1;
  m->l4 = L4_UNKNOWN;
  m->app = APP_UNKNOWN;
  m->quic.hdr_form = QUIC_HDR_UNKNOWN;
}

static inline void lb_set_tuple4(
  pkt_t *m,
  uint32_t src_ip,
  uint32_t dst_ip,
  uint16_t sport,
  uint16_t dport
) {
  m->t4.src_ip = src_ip;
  m->t4.dst_ip = dst_ip;
  m->t4.src_port = sport;
  m->t4.dst_port = dport;
}

static inline void lb_mark_udp(pkt_t *m) { m->l4 = L4_UDP; }
static inline void lb_mark_tcp(pkt_t *m) { m->l4 = L4_TCP; }

static inline bool lb_quic_fill_long_from_udp_payload(pkt_t *m, const uint8_t *p, size_t len) {
  if (!p) return false;
  m->app = APP_QUIC;

  if (!QUIC_IS_LONG_HEADER(p[0])) return false;

  uint8_t dcid_len = p[5];
  size_t need = 6u + 1u + (size_t)dcid_len;  // flags(1)+version(4)+dcil(1)+dcid(dcid_len)
  if (need > len) return false;

  m->quic.hdr_form = QUIC_HDR_LONG;
  m->quic.dcid = &p[6];
  m->quic.dcid_len = dcid_len;
  m->quic.dcid_first_octet = (dcid_len >= 1) ? p[6] : 0;
  m->backend_id = m->quic.dcid[1];
  return true;
}

static inline bool lb_quic_fill_short_from_udp_payload(pkt_t *m, const uint8_t *p, size_t len, size_t known_short_dcid_len) {
  if (!p || len < 1) return false;
  m->app = APP_QUIC;

  if (QUIC_IS_LONG_HEADER(p[0])) return false;

  m->quic.hdr_form = QUIC_HDR_SHORT;

  // DCID comes right after the flags byte.
  const uint8_t *dcid = &p[1];

  if (known_short_dcid_len > 0) {
    if (len < 1 + known_short_dcid_len) return false;
    m->quic.dcid = dcid;
    m->quic.dcid_len = known_short_dcid_len;
    m->quic.dcid_first_octet = dcid[0];
  } else {
    // TODO: Handle case where DCID length is not known.
    m->quic.dcid = dcid;
    m->quic.dcid_len = 0;
    m->quic.dcid_first_octet = 0;
  }
  m->backend_id = m->quic.dcid[1];
  return true;
}

// static inline uint32_t lb_quic_get_dcid(const pkt_t *m) {
//   if (m->quic.dcid && m->quic.dcid_len > 0) {
//     uint32_t dcid = 0;
//     debugk("QUIC DCID: len=%zu, first_octet=0x%02x", m->quic.dcid_len, m->quic.dcid_first_octet);
//     for (size_t i = 0; i < m->quic.dcid_len; ++i) {
//       dcid = (dcid << 8) | m->quic.dcid[i];
//     }
//     return dcid;
//   }
//   return 0;
// }
