#pragma once

#include "Packet.h"
#include <fstream>
#include <zlib.h>

#include "caf/all.hpp"
#include "caf/io/all.hpp"

#include "customer_cone/sample.hpp"

namespace customer_cone {
namespace client {
struct writer {
  gzFile file;

  writer(const std::string& path, const std::string& f_name);

  ~writer();

  void sample_to_disk(const std::shared_ptr<sample>& sample);
};
} // namespace client
} // namespace customer_cone