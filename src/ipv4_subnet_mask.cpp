#include <cstring>
#include <utility>

#include "customer_cone/ipv4_subnet_mask.hpp"

using namespace std;

namespace customer_cone {

namespace {
constexpr uint8_t netmask_tbl[]
  = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE};
}

ipv4_subnet_mask ipv4_subnet_mask::make(size_t a) {
  size_t pl = std::min(a, num_bytes * 8);
  array<uint8_t, num_bytes> r{};
  auto p = pl / 8;
  auto remainder = pl % 8;
  size_t i = 0;
  for (; i < p; i++)
    r[i] = 0xff;
  if (remainder != 0)
    r[i] = netmask_tbl[remainder];

  return ipv4_subnet_mask{r};
}

int ipv4_subnet_mask::to_short_rep() const {
  int s = 0;
  for (size_t i = 0; i < byte_addr::num_bytes; i++) {
    auto c = bitset<8>(bytes[i]);
    for (size_t j = 0; j < c.size(); j++)
      s += c[j];
  }
  return s;
}
} // namespace customer_cone