#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "caf/all.hpp"

#include "byte_addr.hpp"

namespace customer_cone {

struct ipv4_subnet_mask : public byte_addr {
  /// Creates subnet from short representation
  ///
  /// \param subnet mask as short representation like 24 for 255.255.255.0
  /// \return subnet mask
  static ipv4_subnet_mask make(size_t s);

  explicit ipv4_subnet_mask(std::array<uint8_t, ipv4_subnet_mask::num_bytes> a)
    : byte_addr(a) {
    // nop
  }

  /// Gives the short representation of a subnet mask
  ///
  /// \return for 255.255.255.0 the method returns 24
  int to_short_rep() const;

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, ipv4_subnet_mask& x) {
    return f(caf::meta::type_name("ipv4_subnet_mask"), x.bytes,
             customer_cone::ipv4_subnet_mask::num_bytes);
  }
};
} // namespace customer_cone