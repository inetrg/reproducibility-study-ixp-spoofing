#pragma once

#include "byte_addr.hpp"
#include <array>
#include <bitset>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "caf/all.hpp"

namespace customer_cone {

struct ipv4_address : public byte_addr {
  explicit ipv4_address(const std::string& a) : byte_addr(a) {
    // nop
  }
  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, ipv4_address& x) {
    return f(caf::meta::type_name("ipv4_address"), x.bytes,
             customer_cone::ipv4_address::num_bytes);
  }
};
} // namespace customer_cone
