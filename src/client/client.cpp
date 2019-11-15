#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include "customer_cone/client/checker.hpp"
#include "customer_cone/client/client.hpp"
#include "customer_cone/client/file_processor.hpp"
#include "customer_cone/client/stats_processor.hpp"
#include "customer_cone/client/writer.hpp"
#include "customer_cone/sample.hpp"
#include "customer_cone/server/server.hpp"
#include "customer_cone/sflow/reader.hpp"
#include "customer_cone/utils/filesystem.hpp"
#include "customer_cone/utils/string.hpp"

using namespace std;
using namespace caf;
using namespace caf::io;

using namespace customer_cone::utils::str;
using namespace customer_cone::utils::filesystem;

CAF_ALLOW_UNSAFE_MESSAGE_TYPE(pcpp::Packet)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(pcpp::Layer)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(vector<pcpp::Packet>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(customer_cone::sample)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(vector<customer_cone::sample>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(shared_ptr<vector<customer_cone::sample>>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(
  shared_ptr<vector<shared_ptr<customer_cone::sample>>>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(shared_ptr<customer_cone::sample>)

namespace {
std::unordered_map<string, uint32_t> build_asn_mac_mapping(const string& file) {
  std::unordered_map<string, uint32_t> mapping;
  std::ifstream infile(file);
  string line;
  vector<string> lv;
  uint32_t asn;
  while (getline(infile, line)) {
    lv = split(line, ';');
    if (lv.size() < 2)
      continue;
    trim(lv[0]);
    asn = stoll(lv[0]);
    lv = split(lv[1], ',');
    if (lv.empty())
      continue;
    for (auto mx : lv) {
      trim(mx);
      mapping[mx] = asn;
    }
  }
  return mapping;
}
} // namespace
namespace customer_cone {
namespace client {

const char* client_state::name = "cc_client";

behavior client_behav(stateful_actor<client_state>* self,
                      const caf::actor& server, const string& input_path,
                      const string& output_path, const string& pattern,
                      const string& asn_mac_mapping_file,
                      const uint32_t& num_worker) {
  self->state.input_path = input_path;
  self->state.output_path = output_path;
  self->state.pattern = pattern;
  self->state.active_actors = 0;
  self->state.file_index = 0;
  self->state.asn_mac_mapping
    = make_shared<unordered_map<std::string, uint32_t>>(
      build_asn_mac_mapping(asn_mac_mapping_file));

  if (!self->state.stats_processor_ptr) {
    self->state.stats_processor_ptr
      = self->spawn<detached>(stats_processor_behav, self->state.output_path);
    self->monitor(self->state.stats_processor_ptr);
  }

  self->set_down_handler([=](down_msg& m) {
    if (self->state.stats_processor_ptr
        && m.source.id() != self->state.stats_processor_ptr.id()) {
      self->state.active_actors--;
      self->state.finished_file_processors++;
      aout(self) << "active:" << self->state.active_actors
                 << " finish:" << self->state.finished_file_processors << endl;
    }

    self->send(self, collect_sflow_files_atom::value);
  });

  return {[=](collect_sflow_files_atom) {
    if (self->state.files.empty()) {
      self->state.files
        = get_files(self->state.input_path, self->state.pattern);
    }
    if (self->state.active_actors < num_worker
        && self->state.file_index < self->state.files.size()) {
      auto f_processor = self->spawn<detached>(
        file_processor_behav, server, self->state.stats_processor_ptr,
        self->state.files[self->state.file_index], self->state.output_path,
        self->state.asn_mac_mapping);
      self->monitor(f_processor);
      self->send(f_processor, parse_sflow_atom::value);
      self->state.active_actors++;
      self->state.file_index++;
      self->send(self, collect_sflow_files_atom::value);
    } else if (self->state.active_actors == 0
               && self->state.finished_file_processors
                    == self->state.files.size()) {
      aout(self) << "start write stats" << endl;
      self
        ->request(self->state.stats_processor_ptr, infinite,
                  write_check_result_atom::value)
        .await(
          [&](bool r) {
            if (!r) {
              aout(self) << "stats have not been written" << endl;
            } else {
              aout(self) << "Stats have been written" << endl;
            }
          },
          [&](error& err) {
            aout(self) << self->system().render(err) << endl;
          });
      self->quit();
    }
    // if (self->state.finished_file_processors < self->state.files.size()) {
    self->delayed_send(self, std::chrono::microseconds(1),
                       collect_sflow_files_atom::value);
    //}
  }};
}
} // namespace client
} // namespace customer_cone