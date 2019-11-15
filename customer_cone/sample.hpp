#pragma once

#include <map>

#include "Packet.h"
#include "ProtocolType.h"

#include "caf/variant.hpp"

#include "customer_cone/classification_type.hpp"
#include "customer_cone/ipv4_address.hpp"
#include "stats.hpp"

namespace customer_cone {

struct sample {
  uint32_t forwarding_asn = 0;

  classification_type label;

  pcpp::ProtocolType trans_proto;

  pcpp::ProtocolType proto;

  ipv4_address src_addr;

  ipv4_address dst_addr;

  uint16_t src_port = 0;

  uint16_t vlan_in = 0;

  uint16_t vlan_out = 0;

  uint16_t dst_port = 0;

  uint8_t ttl = 0;

  uint32_t sampled_packet_size = 0;

  item checks;

  pcpp::Packet packet;

  uint32_t sample_rate;

  sample(pcpp::Packet& packet, uint32_t sample_rate);

  ~sample();

  std::string line_rep();

  static std::string line_fields();
};
} // namespace customer_cone