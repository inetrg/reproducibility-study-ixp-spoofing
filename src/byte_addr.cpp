#include <utility>

#include <cmath>
#include <iterator>

#include "customer_cone/byte_addr.hpp"
#include "customer_cone/utils/string.hpp"

using namespace std;
namespace customer_cone {
using namespace utils::str;
byte_addr::byte_addr(array<uint8_t, num_bytes> a) : bytes(a) {
  // nop
}

byte_addr::byte_addr(const std::string& a) {
  char* end;
  std::vector<std::string> r = split(a, '.');
  for (size_t i = 0; i < num_bytes; i++)
    bytes[i] = static_cast<uint8_t>(std::strtol(r[i].c_str(), &end, 10));
}

uint32_t byte_addr::to_number_rep() {
  uint32_t r = 0;
  for (size_t i = 0; i < byte_addr::num_bytes; i++) {
    r += bytes[i] * (uint32_t)pow(256, (3 - i));
  }
  return r;
}

byte_addr::byte_addr() = default;
} // namespace customer_cone