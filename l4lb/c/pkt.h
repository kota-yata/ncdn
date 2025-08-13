#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

typedef enum { L4_UNKNOWN=0, L4_TCP=6, L4_UDP=17 } l4_kind_t;
typedef enum { APP_UNKNOWN=0, APP_QUIC=1 } app_kind_t;
typedef enum { QUIC_HDR_UNKNOWN=0, QUIC_HDR_LONG, QUIC_HDR_SHORT } quic_header_form_t;

typedef struct {
  uint32_t src_ip_be;
  uint32_t dst_ip_be;
  uint16_t src_port_be;
  uint16_t dst_port_be;
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
  int backend_id;   // -1 if not assigned
} pkt_t;

static inline void lb_init(pkt_t *m);
static inline void lb_set_tuple4(
  pkt_t *m,
  uint32_t src_ip,
  uint32_t dst_ip,
  uint16_t sport,
  uint16_t dport
);
static inline void lb_mark_udp(pkt_t *m);
static inline void lb_mark_tcp(pkt_t *m);

bool lb_quic_fill_long_from_udp_payload(pkt_t *m, const uint8_t *p, size_t len);
bool lb_quic_fill_short_from_udp_payload(pkt_t *m, const uint8_t *p, size_t len, size_t known_short_dcid_len);
