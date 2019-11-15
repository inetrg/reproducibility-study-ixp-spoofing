#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

#include "customer_cone/sample.hpp"
#include "customer_cone/sflow/encoder.hpp"

namespace customer_cone {
namespace sflow {
struct reader {
  encoder enc;
  explicit reader(const std::string& file);

  std::vector<std::shared_ptr<sample>> read_sample();
};

static std::shared_ptr<std::vector<std::shared_ptr<sample>>>
read_file(const std::string& file);
} // namespace sflow
} // namespace customer_cone
