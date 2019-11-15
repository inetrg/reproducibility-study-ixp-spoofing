#pragma once

#include <chrono>
#include <ctime>
#include <string>
#include <vector>

#include <IcmpLayer.h>

#include "customer_cone/byte_addr.hpp"
#include "customer_cone/classification_type.hpp"
#include "customer_cone/sample.hpp"

namespace {
inline void add_string(std::vector<std::string>& v, const std::string& str) {
  if (!str.empty())
    v.push_back(str);
}
template <typename T>
inline void add_string(std::vector<std::string>& v, const T str) {
  auto tmp = std::to_string(str);
  if (!tmp.empty())
    v.push_back(tmp);
}
} // namespace

namespace customer_cone {
namespace utils {
namespace str {
std::vector<std::string> split(const std::string& s, char delimiter);

inline std::string to_string(bool i) {
  return i ? "true" : "false";
}

std::string rm_file_ending(const std::string& file);

std::string extract_filename(const std::string& file);

std::string to_string(const uint8_t mac[6]);

std::string to_string(const classification_type& type);

std::string to_string(const std::map<std::string, std::string>& m);

std::string to_string(const byte_addr& addr);

std::string to_string(const pcpp::IcmpMessageType& type);

std::string to_string(const pcpp::ProtocolType& type);

std::string to_string(const item& it);

static inline std::string to_lower(std::string& data) {
  std::transform(data.begin(), data.end(), data.begin(), ::tolower);
}

static inline void ltrim(std::string& s) {
  s.erase(s.begin(),
          std::find_if(s.begin(), s.end(),
                       std::not1(std::ptr_fun<int, int>(std::isspace))));
}

static inline void rtrim(std::string& s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       std::not1(std::ptr_fun<int, int>(std::isspace)))
            .base(),
          s.end());
}

static inline void trim(std::string& s) {
  ltrim(s);
  rtrim(s);
}

static inline std::string ltrim_copy(std::string s) {
  ltrim(s);
  return s;
}

static inline std::string rtrim_copy(std::string s) {
  rtrim(s);
  return s;
}
template <typename T1, typename T2>
static inline std::string to_string(const std::map<T1, T2>& m) {
  std::vector<std::string> v{m.size()};
  for (const auto& i : m) {
    add_string(v, i.first);
  }
  auto r = std::string("");
  if (!v.empty())
    r = caf::join(v, ";");
  return r;
}

} // namespace str
} // namespace utils
} // namespace customer_cone