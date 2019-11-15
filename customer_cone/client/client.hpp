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

struct client_state {
  static const char* name;
  std::string output_path;
  std::string input_path;
  std::string pattern;
  uint8_t active_actors;
  uint64_t finished_file_processors;
  uint64_t file_index;
  std::shared_ptr<std::unordered_map<std::string, uint32_t>> asn_mac_mapping;
  std::vector<std::string> files;
  caf::actor stats_processor_ptr;
};

using collect_sflow_files_atom = caf::atom_constant<caf::atom("coll_sflow")>;
using parse_sflow_atom = caf::atom_constant<caf::atom("p_sflow")>;
using check_samples_atom = caf::atom_constant<caf::atom("check_samp")>;
using write_results_atom = caf::atom_constant<caf::atom("write_res")>;
using classification_result_atom = caf::atom_constant<caf::atom("classi_res")>;

caf::behavior client_behav(caf::stateful_actor<client_state>* self,
                           const caf::actor& server,
                           const std::string& input_path,
                           const std::string& output_path,
                           const std::string& pattern,
                           const std::string& asn_mac_mapping_file,
                           const uint32_t& num_worker);

} // namespace client
} // namespace customer_cone