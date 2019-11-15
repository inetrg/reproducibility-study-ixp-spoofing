#include <TcpLayer.h>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <sys/time.h>

#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

#include "customer_cone/sample.hpp"
#include "customer_cone/sflow/encoder.hpp"
#include "customer_cone/sflow/reader.hpp"

using namespace std;

namespace customer_cone {
namespace sflow {

reader::reader(const std::string& file) {
  enc = encoder{};
  enc.sfConfig = SFConfig{};
  enc.sfCLF = SFCommonLogFormat{};
  enc.sfConfig.readPcapFileName = const_cast<char*>(file.c_str());
  enc.sfConfig.outputFormat = SFLFMT_LINE;
  enc.sfConfig.readPcapFile = fopen(enc.sfConfig.readPcapFileName, "rb");
  enc.readPcapHeader();
}

vector<shared_ptr<sample>> reader::read_sample() {
  auto sfl_samples = enc.readPcapPacket(enc.sfConfig.readPcapFile);
  if (sfl_samples) {
    if (!sfl_samples.value().empty())
      return sfl_samples.value();
    else
      return read_sample();
  }

  return vector<shared_ptr<sample>>();
}
} // namespace sflow
} // namespace customer_cone