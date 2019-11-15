#pragma once

#include <map>

#include "Packet.h"
#include "ProtocolType.h"

#include "caf/variant.hpp"

#include "customer_cone/classification_type.hpp"
#include "customer_cone/ipv4_address.hpp"

namespace customer_cone {

struct item {
  std::map<std::string, uint64_t> str_checks;

  std::map<uint16_t, uint64_t> ports;
};

struct stats {
  uint64_t pkt_count = 0;

  std::map<pcpp::ProtocolType, std::map<pcpp::ProtocolType, uint64_t>>
    proto_pkt_count;

  std::map<pcpp::ProtocolType, uint64_t> trans_proto_pkt_count;

  std::map<pcpp::ProtocolType, std::map<pcpp::ProtocolType, item>> items;
};

} // namespace customer_cone