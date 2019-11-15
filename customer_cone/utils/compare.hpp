#pragma once

#include <chrono>
#include <ctime>
#include <string>
#include <vector>

namespace customer_cone {
namespace utils {
namespace compare {

struct o_greater {
  template <typename T>
  inline bool operator()(const std::shared_ptr<T>& a,
                         const std::shared_ptr<T>& b) const {
    return *a.get() > *b.get();
  }
};

struct o_smaller {
  template <typename T>
  inline bool operator()(const std::shared_ptr<T>& a,
                         const std::shared_ptr<T>& b) const {
    return *a.get() < *b.get();
  }
};

struct object_equal {
  template <typename T>
  bool operator()(std::shared_ptr<T> const& a,
                  std::shared_ptr<T> const& b) const {
    return *a == *b;
  }
};
} // namespace compare
} // namespace utils
} // namespace customer_cone