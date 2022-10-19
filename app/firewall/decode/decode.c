#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_gre.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_mbuf_ptype.h>
#include <rte_mpls.h>
#include <rte_net.h>
#include <rte_sctp.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../packet.h"

#include "decode.h"

MODULE_DECLARE(decode) = {.name = "decode",
                           .id = MOD_ID_DECODER,
                           .enabled = true,
                           .log = true,
                           .init = decoder_init,
                           .proc = decoder_proc,
                           .conf = NULL,
                           .free = NULL,
                           .priv = NULL};

/* get l3 packet type from ip6 next protocol */
static uint32_t ptype_l3_ip6(uint8_t ip6_proto) {
  static const uint32_t ip6_ext_proto_map[256] = {
      [IPPROTO_HOPOPTS] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
      [IPPROTO_ROUTING] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
      [IPPROTO_FRAGMENT] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
      [IPPROTO_ESP] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
      [IPPROTO_AH] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
      [IPPROTO_DSTOPTS] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
  };

  return RTE_PTYPE_L3_IPV6 + ip6_ext_proto_map[ip6_proto];
}

/* get l3 packet type from ip version and header length */
static uint32_t ptype_l3_ip(uint8_t ipv_ihl) {
  static const uint32_t ptype_l3_ip_proto_map[256] = {
      [0x45] = RTE_PTYPE_L3_IPV4,     [0x46] = RTE_PTYPE_L3_IPV4_EXT,
      [0x47] = RTE_PTYPE_L3_IPV4_EXT, [0x48] = RTE_PTYPE_L3_IPV4_EXT,
      [0x49] = RTE_PTYPE_L3_IPV4_EXT, [0x4A] = RTE_PTYPE_L3_IPV4_EXT,
      [0x4B] = RTE_PTYPE_L3_IPV4_EXT, [0x4C] = RTE_PTYPE_L3_IPV4_EXT,
      [0x4D] = RTE_PTYPE_L3_IPV4_EXT, [0x4E] = RTE_PTYPE_L3_IPV4_EXT,
      [0x4F] = RTE_PTYPE_L3_IPV4_EXT,
  };

  return ptype_l3_ip_proto_map[ipv_ihl];
}

/* get l4 packet type from proto */
static uint32_t ptype_l4(uint8_t proto) {
  static const uint32_t ptype_l4_proto[256] = {
      [IPPROTO_UDP] = RTE_PTYPE_L4_UDP,
      [IPPROTO_TCP] = RTE_PTYPE_L4_TCP,
      [IPPROTO_SCTP] = RTE_PTYPE_L4_SCTP,
      [IPPROTO_ICMP] = RTE_PTYPE_L4_ICMP,
  };

  return ptype_l4_proto[proto];
}

/* get inner l3 packet type from ip6 next protocol */
static uint32_t ptype_inner_l3_ip6(uint8_t ip6_proto) {
  static const uint32_t ptype_inner_ip6_ext_proto_map[256] = {
      [IPPROTO_HOPOPTS] = RTE_PTYPE_INNER_L3_IPV6_EXT - RTE_PTYPE_INNER_L3_IPV6,
      [IPPROTO_ROUTING] = RTE_PTYPE_INNER_L3_IPV6_EXT - RTE_PTYPE_INNER_L3_IPV6,
      [IPPROTO_FRAGMENT] =
          RTE_PTYPE_INNER_L3_IPV6_EXT - RTE_PTYPE_INNER_L3_IPV6,
      [IPPROTO_ESP] = RTE_PTYPE_INNER_L3_IPV6_EXT - RTE_PTYPE_INNER_L3_IPV6,
      [IPPROTO_AH] = RTE_PTYPE_INNER_L3_IPV6_EXT - RTE_PTYPE_INNER_L3_IPV6,
      [IPPROTO_DSTOPTS] = RTE_PTYPE_INNER_L3_IPV6_EXT - RTE_PTYPE_INNER_L3_IPV6,
  };

  return RTE_PTYPE_INNER_L3_IPV6 + ptype_inner_ip6_ext_proto_map[ip6_proto];
}

/* get inner l3 packet type from ip version and header length */
static uint32_t ptype_inner_l3_ip(uint8_t ipv_ihl) {
  static const uint32_t ptype_inner_l3_ip_proto_map[256] = {
      [0x45] = RTE_PTYPE_INNER_L3_IPV4,
      [0x46] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x47] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x48] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x49] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x4A] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x4B] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x4C] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x4D] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x4E] = RTE_PTYPE_INNER_L3_IPV4_EXT,
      [0x4F] = RTE_PTYPE_INNER_L3_IPV4_EXT,
  };

  return ptype_inner_l3_ip_proto_map[ipv_ihl];
}

/* get inner l4 packet type from proto */
static uint32_t ptype_inner_l4(uint8_t proto) {
  static const uint32_t ptype_inner_l4_proto[256] = {
      [IPPROTO_UDP] = RTE_PTYPE_INNER_L4_UDP,
      [IPPROTO_TCP] = RTE_PTYPE_INNER_L4_TCP,
      [IPPROTO_SCTP] = RTE_PTYPE_INNER_L4_SCTP,
  };

  return ptype_inner_l4_proto[proto];
}

/* get the tunnel packet type if any, update proto and off. */
static uint32_t ptype_tunnel(uint16_t *proto, const struct rte_mbuf *mbuf,
                             uint32_t *off) {
  switch (*proto) {
  case IPPROTO_GRE: {
    static const uint8_t opt_len[16] = {
        [0x0] = 4,  [0x1] = 8,  [0x2] = 8,  [0x8] = 8,
        [0x3] = 12, [0x9] = 12, [0xa] = 12, [0xb] = 16,
    };
    const struct rte_gre_hdr *gh;
    struct rte_gre_hdr gh_copy;
    uint16_t flags;

    gh = rte_pktmbuf_read(mbuf, *off, sizeof(*gh), &gh_copy);
    if (unlikely(gh == NULL))
      return 0;

    flags = rte_be_to_cpu_16(*(const uint16_t *)gh);
    flags >>= 12;
    if (opt_len[flags] == 0)
      return 0;

    *off += opt_len[flags];
    *proto = gh->proto;
    if (*proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_TEB))
      return RTE_PTYPE_TUNNEL_NVGRE;
    else
      return RTE_PTYPE_TUNNEL_GRE;
  }
  case IPPROTO_IPIP:
    *proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    return RTE_PTYPE_TUNNEL_IP;
  case IPPROTO_IPV6:
    *proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    return RTE_PTYPE_TUNNEL_IP; /* IP is also valid for IPv6 */
  default:
    return 0;
  }
}

int decoder_init(__rte_unused void *config) { return 0; }

static mod_ret_t decoder_proc_ingress(struct rte_mbuf *mbuf) {
  packet_t *p;
  const struct rte_ether_hdr *eh;
  uint32_t pkt_type = RTE_PTYPE_L2_ETHER;
  uint32_t offset = 0;
  uint16_t proto;
  int ret;

  p = rte_mbuf_to_priv(mbuf);
  if (!p) {
    M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
          "rte mbuf to priv failed\n");
    goto error;
  }

  // L2:
  if (unlikely(rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_ether_hdr))) {
    M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
          "pkt data len check failed\n");
    goto error;
  }

  eh = rte_pktmbuf_mtod_offset(mbuf, struct rte_ether_hdr *, offset);
  if (unlikely(eh == NULL)) {
    M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
          "ether header check failed\n");
    goto error;
  }

  rte_ether_addr_copy(&eh->dst_addr, (struct rte_ether_addr *)p->dmac);
  rte_ether_addr_copy(&eh->src_addr, (struct rte_ether_addr *)p->smac);

  proto = eh->ether_type;
  offset = sizeof(*eh);

  if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
    goto L3;

  if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
    const struct rte_vlan_hdr *vh;

    pkt_type = RTE_PTYPE_L2_ETHER_VLAN;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset <
                 sizeof(struct rte_vlan_hdr))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    vh = rte_pktmbuf_mtod_offset(mbuf, struct rte_vlan_hdr *, offset);
    if (unlikely(vh == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "vlan header check failed\n");
      goto error;
    }

    offset += sizeof(*vh);
    proto = vh->eth_proto;
  } else if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
    const struct rte_vlan_hdr *vh;

    pkt_type = RTE_PTYPE_L2_ETHER_QINQ;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset <
                 sizeof(struct rte_vlan_hdr) * 2)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    vh = rte_pktmbuf_mtod_offset(mbuf, struct rte_vlan_hdr *,
                                 offset + sizeof(*vh));
    if (unlikely(vh == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "vlan header check failed\n");
      goto error;
    }

    offset += 2 * sizeof(*vh);
    proto = vh->eth_proto;
  } else if ((proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLS)) ||
             (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLSM))) {
    unsigned int i;
    const struct rte_mpls_hdr *mh;

#define MAX_MPLS_HDR 5
    for (i = 0; i < MAX_MPLS_HDR; i++) {
      if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < i * sizeof(*mh))) {
        M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
              "pkt data len check failed\n");
        goto error;
      }

      mh = rte_pktmbuf_mtod_offset(mbuf, struct rte_mpls_hdr *,
                                   offset + (i * sizeof(*mh)));
      if (unlikely(mh == NULL)) {
        M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
              "mpls header check failed\n");
        goto error;
      }
    }
    if (i == MAX_MPLS_HDR) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "over max mpls header limit\n");
      goto error;
    }

    pkt_type = RTE_PTYPE_L2_ETHER_MPLS;
    goto done;
  }

L3:
  if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    const struct rte_ipv4_hdr *ip4h;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*ip4h))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    ip4h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, offset);
    if (unlikely(ip4h == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "ipv4 header check failed\n");
      goto error;
    }

    p->tuple.v4.proto = ip4h->next_proto_id;
    p->tuple.v4.sip = ip4h->src_addr;
    p->tuple.v4.dip = ip4h->dst_addr;
    p->is_v4 = true;

    pkt_type |= ptype_l3_ip(ip4h->version_ihl);
    offset += rte_ipv4_hdr_len(ip4h);

    if (ip4h->fragment_offset &
        rte_cpu_to_be_16(RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG)) {
      pkt_type |= RTE_PTYPE_L4_FRAG;
      goto done;
    }
    proto = ip4h->next_proto_id;
    pkt_type |= ptype_l4(proto);
  } else if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
    const struct rte_ipv6_hdr *ip6h;
    int frag = 0;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*ip6h))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    ip6h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, offset);
    if (unlikely(ip6h == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "ipv6 header check failed\n");
      goto error;
    }

    p->tuple.v6.proto = ip6h->proto;
    memcpy(p->tuple.v6.sip, ip6h->src_addr, 16);
    memcpy(p->tuple.v6.dip, ip6h->dst_addr, 16);
    p->is_v4 = false;

    proto = ip6h->proto;
    offset += sizeof(*ip6h);
    pkt_type |= ptype_l3_ip6(proto);

    if ((pkt_type & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV6_EXT) {
      ret = rte_net_skip_ip6_ext(proto, mbuf, &offset, &frag);
      if (ret < 0) {
        M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
              "skip ipv6 extensions failed\n");
        goto error;
      }
      proto = ret;
    }

    if (proto == 0) {
      goto done;
    }

    if (frag) {
      pkt_type |= RTE_PTYPE_L4_FRAG;
      goto done;
    }
    pkt_type |= ptype_l4(proto);
  }

  // L4:
  if ((pkt_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP) {
    const struct rte_udp_hdr *uh;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*uh))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, offset);
    if (unlikely(uh == NULL)) {
      pkt_type = pkt_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
      goto done;
    }

    if (p->is_v4) {
      p->tuple.v4.sp = uh->src_port;
      p->tuple.v4.dp = uh->dst_port;
    } else {
      p->tuple.v6.sp = uh->src_port;
      p->tuple.v6.dp = uh->dst_port;
    }

    goto done;
  } else if ((pkt_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {
    const struct rte_tcp_hdr *th;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*th))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, offset);
    if (unlikely(th == NULL)) {
      pkt_type = pkt_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
      goto done;
    }

    if (p->is_v4) {
      p->tuple.v4.sp = th->src_port;
      p->tuple.v4.dp = th->dst_port;
    } else {
      p->tuple.v6.sp = th->src_port;
      p->tuple.v6.dp = th->dst_port;
    }

    goto done;
  } else if ((pkt_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_SCTP) {
    const struct rte_sctp_hdr *sh;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*sh))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    sh = rte_pktmbuf_mtod_offset(mbuf, struct rte_sctp_hdr *, offset);
    if (unlikely(sh == NULL)) {
      pkt_type = pkt_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
      goto done;
    }

    if (p->is_v4) {
      p->tuple.v4.sp = sh->src_port;
      p->tuple.v4.dp = sh->dst_port;
    } else {
      p->tuple.v6.sp = sh->src_port;
      p->tuple.v6.dp = sh->dst_port;
    }

    goto done;
  } else if ((pkt_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_ICMP) {
    if (p->is_v4) {
      p->tuple.v4.sp = 0;
      p->tuple.v4.dp = 0;
    } else {
      p->tuple.v6.sp = 0;
      p->tuple.v6.dp = 0;
    }

    goto done;
  } else {
    pkt_type |= ptype_tunnel(&proto, mbuf, &offset);
  }

  // INNER_L2:
  if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_TEB)) {
    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*eh))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    eh = rte_pktmbuf_mtod_offset(mbuf, struct rte_ether_hdr *, offset);
    if (unlikely(eh == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "ether header check failed\n");
      goto error;
    }

    rte_ether_addr_copy(&eh->dst_addr, (struct rte_ether_addr *)p->dmac);
    rte_ether_addr_copy(&eh->src_addr, (struct rte_ether_addr *)p->smac);

    pkt_type |= RTE_PTYPE_INNER_L2_ETHER;
    proto = eh->ether_type;
    offset += sizeof(*eh);
  }

  if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
    const struct rte_vlan_hdr *vh;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*vh))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    pkt_type &= ~RTE_PTYPE_INNER_L2_MASK;
    pkt_type |= RTE_PTYPE_INNER_L2_ETHER_VLAN;

    vh = rte_pktmbuf_mtod_offset(mbuf, struct rte_vlan_hdr *, offset);
    if (unlikely(vh == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "vlan header check failed\n");
      goto error;
    }

    offset += sizeof(*vh);
    proto = vh->eth_proto;
  } else if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
    const struct rte_vlan_hdr *vh;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*vh) * 2)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    pkt_type &= ~RTE_PTYPE_INNER_L2_MASK;
    pkt_type |= RTE_PTYPE_INNER_L2_ETHER_QINQ;

    vh = rte_pktmbuf_mtod_offset(mbuf, struct rte_vlan_hdr *,
                                 offset + sizeof(*vh));
    if (unlikely(vh == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "vlan header check failed\n");
      return pkt_type;
    }

    offset += 2 * sizeof(*vh);
    proto = vh->eth_proto;
  }

  // INNER_L3:
  if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    const struct rte_ipv4_hdr *ip4h;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*ip4h))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    ip4h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, offset);
    if (unlikely(ip4h == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "ipv4 header check failed\n");
      goto error;
    }

    p->tuple.v4.proto = ip4h->next_proto_id;
    p->tuple.v4.sip = ip4h->src_addr;
    p->tuple.v4.dip = ip4h->dst_addr;
    p->is_v4 = true;

    pkt_type |= ptype_inner_l3_ip(ip4h->version_ihl);
    offset += rte_ipv4_hdr_len(ip4h);

    if (ip4h->fragment_offset &
        rte_cpu_to_be_16(RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG)) {
      pkt_type |= RTE_PTYPE_INNER_L4_FRAG;
      goto done;
    }
    proto = ip4h->next_proto_id;
    pkt_type |= ptype_inner_l4(proto);
  } else if (proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
    const struct rte_ipv6_hdr *ip6h;
    int frag = 0;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*ip6h))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    ip6h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, offset);
    if (unlikely(ip6h == NULL)) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "ipv6 header check failed\n");
      goto error;
    }

    p->tuple.v6.proto = ip6h->proto;
    memcpy(p->tuple.v6.sip, ip6h->src_addr, 16);
    memcpy(p->tuple.v6.dip, ip6h->dst_addr, 16);
    p->is_v4 = false;

    proto = ip6h->proto;
    offset += sizeof(*ip6h);
    pkt_type |= ptype_inner_l3_ip6(proto);

    if ((pkt_type & RTE_PTYPE_INNER_L3_MASK) == RTE_PTYPE_INNER_L3_IPV6_EXT) {
      ret = rte_net_skip_ip6_ext(proto, mbuf, &offset, &frag);
      if (ret < 0) {
        M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
              "skip ipv6 extensions failed\n");
        goto error;
      }
      proto = ret;
    }

    if (proto == 0) {
      goto done;
    }

    if (frag) {
      pkt_type |= RTE_PTYPE_INNER_L4_FRAG;
      goto done;
    }
    pkt_type |= ptype_inner_l4(proto);
  }

  // INNER_L4:
  if ((pkt_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_UDP) {
    const struct rte_udp_hdr *uh;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*uh))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, offset);
    if (unlikely(uh == NULL)) {
      pkt_type = pkt_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
      goto done;
    }

    if (p->is_v4) {
      p->tuple.v4.sp = uh->src_port;
      p->tuple.v4.dp = uh->dst_port;
    } else {
      p->tuple.v6.sp = uh->src_port;
      p->tuple.v6.dp = uh->dst_port;
    }

    goto done;
  } else if ((pkt_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_TCP) {
    const struct rte_tcp_hdr *th;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*th))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, offset);
    if (unlikely(th == NULL)) {
      pkt_type = pkt_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
      goto done;
    }

    if (p->is_v4) {
      p->tuple.v4.sp = th->src_port;
      p->tuple.v4.dp = th->dst_port;
    } else {
      p->tuple.v6.sp = th->src_port;
      p->tuple.v6.dp = th->dst_port;
    }

    goto done;
  } else if ((pkt_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_SCTP) {
    const struct rte_sctp_hdr *sh;

    if (unlikely(rte_pktmbuf_data_len(mbuf) - offset < sizeof(*sh))) {
      M_LOG(decode.log, RTE_LOG_ERR, MOD_ID_DECODER,
            "pkt data len check failed\n");
      goto error;
    }

    sh = rte_pktmbuf_mtod_offset(mbuf, struct rte_sctp_hdr *, offset);
    if (unlikely(sh == NULL)) {
      pkt_type = pkt_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
      goto done;
    }

    if (p->is_v4) {
      p->tuple.v4.sp = sh->src_port;
      p->tuple.v4.dp = sh->dst_port;
    } else {
      p->tuple.v6.sp = sh->src_port;
      p->tuple.v6.dp = sh->dst_port;
    }

    goto done;
  } else if ((pkt_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_ICMP) {
    if (p->is_v4) {
      p->tuple.v4.sp = 0;
      p->tuple.v4.dp = 0;
    } else {
      p->tuple.v6.sp = 0;
      p->tuple.v6.dp = 0;
    }

    goto done;
  } else {
    pkt_type |= ptype_tunnel(&proto, mbuf, &offset);
  }

done:
  p->ptype = pkt_type;
  return MOD_RET_ACCEPT;

error:
  rte_pktmbuf_free(mbuf);
  return MOD_RET_STOLEN;
}

mod_ret_t decoder_proc(__rte_unused void *config, struct rte_mbuf *mbuf,
                       mod_hook_t hook) {
  if (hook == MOD_HOOK_INGRESS) {
    return decoder_proc_ingress(mbuf);
  }

  return MOD_RET_ACCEPT;
}

// file format utf-8
// ident using space