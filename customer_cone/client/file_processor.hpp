#pragma once

#include "Packet.h"
#include <customer_cone/sflow/reader.hpp>
#include <customer_cone/utils/string.hpp>
#include <string>

#include "caf/all.hpp"
#include "caf/io/all.hpp"

#include "customer_cone/client/checker.hpp"
#include "customer_cone/client/writer.hpp"
#include "customer_cone/sample.hpp"
#include "customer_cone/sflow/reader.hpp"

namespace customer_cone {
namespace client {

struct file_processor_state {
  static const char* name;
  std::string output_path;
  std::shared_ptr<std::unordered_map<std::string, uint32_t>> asn_mac_mapping;
  std::string file;
  std::string file_name;
  std::unordered_map<uint64_t, std::shared_ptr<sample>> samples_map;
  uint64_t counter;
  std::unique_ptr<sflow::reader> reader_ptr;
  std::unique_ptr<writer> writer_ptr;
};

using parse_sflow_atom = caf::atom_constant<caf::atom("p_sflow")>;
using check_samples_atom = caf::atom_constant<caf::atom("check_samp")>;
using write_results_atom = caf::atom_constant<caf::atom("write_res")>;
using classification_result_atom = caf::atom_constant<caf::atom("classi_res")>;

caf::behavior file_processor_behav(
  caf::stateful_actor<file_processor_state>* self, const caf::actor& server,
  const caf::actor& stats_processor, const std::string& file,
  const std::string& output_path,
  const std::shared_ptr<std::unordered_map<std::string, uint32_t>>&
    asn_mac_mapping);

} // namespace client
} // namespace customer_cone