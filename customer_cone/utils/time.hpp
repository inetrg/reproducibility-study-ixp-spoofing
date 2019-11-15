#pragma once

#include <chrono>
#include <ctime>
#include <string>
#include <vector>

namespace customer_cone {
namespace utils {
namespace time {

inline std::chrono::time_point<std::chrono::system_clock> get_time() {
  return std::chrono::system_clock::now();
}

inline int64_t elapsed_microseconds(
  const std::chrono::time_point<std::chrono::system_clock>& s,
  const std::chrono::time_point<std::chrono::system_clock>& e) {
  return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count();
}

} // namespace time
} // namespace utils
} // namespace customer_cone