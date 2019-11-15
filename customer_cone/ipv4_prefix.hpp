#pragma once

#include <cmath>
#include <memory>
#include <string>

#include "caf/all.hpp"

#include "as.hpp"
#include "ipv4_address.hpp"
#include "ipv4_subnet_mask.hpp"

namespace customer_cone {

class as;

struct ipv4_prefix {
  unsigned long upper;

  unsigned long lower;

  ipv4_address addr;

  ipv4_subnet_mask subn_mask;

  std::map<uint32_t, std::shared_ptr<as>> origins;

  explicit ipv4_prefix(const ipv4_address& a, const ipv4_subnet_mask& s);

  ipv4_prefix(const ipv4_address& a, const ipv4_subnet_mask& s,
              std::map<uint32_t, std::shared_ptr<as>> origins);

  static ipv4_prefix make(const std::string& prefix,
                          const std::shared_ptr<as>& o_as);

  static ipv4_prefix make(const std::string& prefix);

  bool contains(const std::string& a) const;

  std::string to_string() const;

  bool contains(const std::shared_ptr<ipv4_prefix>& a) const;

  bool contains(const ipv4_prefix& a) const;

  inline bool operator<=(const byte_addr& b) const {
    auto r = generate_bounds(b);
    return r.first <= r.second;
  }

  inline bool operator>=(const byte_addr& b) const {
    auto r = generate_bounds(b);
    return r.first >= r.second;
  }

  inline bool operator>(const byte_addr& b) const {
    auto r = generate_bounds(b);
    return r.first > r.second;
  }

  inline bool operator<(const byte_addr& b) const {
    auto r = generate_bounds(b);
    return r.first < r.second;
  }

  inline std::pair<uint32_t, uint32_t>
  generate_bounds(const byte_addr& b) const {
    uint32_t ar = 0;
    uint32_t br = 0;
    for (size_t i = 0; i < byte_addr::num_bytes; i++) {
      ar += (addr.bytes[i] > 0 ? addr.bytes[i] : 255)
            * static_cast<uint32_t>(std::pow(
              subn_mask.bytes[i] > 0 ? subn_mask.bytes[i] : 256, (3 - i)));
      br += (b.bytes[i] > 0 ? b.bytes[i] : 255)
            * static_cast<uint32_t>(std::pow(
              subn_mask.bytes[i] > 0 ? subn_mask.bytes[i] : 256, (3 - i)));
    }
    return {ar, br};
  }

  inline bool operator>=(const ipv4_prefix& b) const {
    return upper >= b.upper && lower >= b.lower;
  }

  inline bool operator>(const ipv4_prefix& b) const {
    return upper > b.upper && lower > b.lower;
  }

  inline bool operator==(const ipv4_prefix& b) const {
    return upper == b.upper && lower == b.lower;
  }

  inline bool operator!=(const ipv4_prefix& b) const {
    return upper != b.upper || lower != b.lower;
  }

  inline bool operator<(const ipv4_prefix& b) const {
    return upper < b.upper && lower < b.lower;
  }

  inline bool operator<=(const ipv4_prefix& b) const {
    return upper <= b.upper && lower <= b.lower;
  }

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, ipv4_prefix& x) {
    return f(caf::meta::type_name("ipv4_prefix"), x.upper, x.lower, x.origins,
             x.addr, x.subn_mask);
  }
};
} // namespace customer_cone