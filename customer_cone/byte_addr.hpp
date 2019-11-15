#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "caf/all.hpp"

namespace customer_cone {

struct byte_addr {
  static constexpr size_t num_bytes = 4;

  explicit byte_addr(std::array<uint8_t, num_bytes> a);

  explicit byte_addr(const std::string& a);

  std::array<uint8_t, num_bytes> bytes{};

  inline bool operator<=(const byte_addr& rhs) {
    for (size_t i = 0; i < num_bytes; i++)
      if (this->bytes[i] > rhs.bytes[i])
        return false;
    return true;
  }

  inline bool operator>=(const byte_addr& rhs) {
    for (size_t i = 0; i < num_bytes; i++)
      if (this->bytes[i] < rhs.bytes[i])
        return false;
    return true;
  }

  inline bool operator==(const byte_addr& rhs) {
    for (size_t i = 0; i < num_bytes; i++)
      if (this->bytes[i] != rhs.bytes[i])
        return false;
    return true;
  }
  uint32_t to_number_rep();

  byte_addr();

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, byte_addr& x) {
    return f(caf::meta::type_name("byte_addr"), x.bytes,
             customer_cone::byte_addr::num_bytes);
  }
};
} // namespace customer_cone