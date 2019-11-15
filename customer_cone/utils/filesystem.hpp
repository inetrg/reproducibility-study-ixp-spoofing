#pragma once

#include <chrono>
#include <ctime>
#include <set>
#include <string>
#include <vector>

namespace customer_cone {
namespace utils {
namespace filesystem {

std::vector<std::string> get_files(const std::string& path_str,
                                   const std::string& pattern);

} // namespace filesystem
} // namespace utils
} // namespace customer_cone