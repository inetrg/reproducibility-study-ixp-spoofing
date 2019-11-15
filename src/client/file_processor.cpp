#include <Logger.h>
#include <caf/atom.hpp>
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
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(customer_cone::sample*)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(vector<customer_cone::sample>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(shared_ptr<vector<customer_cone::sample>>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(
  shared_ptr<vector<shared_ptr<customer_cone::sample>>>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(shared_ptr<customer_cone::sample>)
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(unique_ptr<customer_cone::sample>)

namespace customer_cone {
namespace client {

const char* file_processor_state::name = "cc_file_processor";

behavior file_processor_behav(
  stateful_actor<file_processor_state>* self, const caf::actor& server,
  const caf::actor& stats_processor, const std::string& file,
  const std::string& output_path,
  const std::shared_ptr<std::unordered_map<std::string, uint32_t>>&
    asn_mac_mapping) {
  self->state.output_path = output_path;
  self->state.file = file;
  self->state.file_name = rm_file_ending(extract_filename(file));
  self->state.reader_ptr = make_unique<sflow::reader>(self->state.file);
  self->state.writer_ptr
    = make_unique<writer>(self->state.output_path, self->state.file_name);
  self->state.asn_mac_mapping = asn_mac_mapping;
  pcpp::LoggerPP::getInstance().supressErrors();

  return {
    [=](parse_sflow_atom) {
      if (self->state.samples_map.size() < 1000 && self->state.reader_ptr) {
        auto samples = self->state.reader_ptr->read_sample();
        // clear reader_ptr when all samples have been read from file
        if (samples.empty() && self->state.reader_ptr) {
          self->state.reader_ptr.reset();
        }

        for (auto& s : samples) {
          // skip IPv6 and ARP Packets
          if (s->packet.isPacketOfType(pcpp::IPv6)
              || !s->packet.isPacketOfType(pcpp::Ethernet)
              || s->packet.isPacketOfType(pcpp::ARP)) {
            s.reset();
            continue;
          }

          // check sample and add it
          checker::check_sample(s, self->state.asn_mac_mapping);
          self->state.counter++;
          self->state.samples_map[self->state.counter] = s;

          // classifies sample
          if (s->forwarding_asn != 0) {
            self->send(server, server::ip_in_cone_atom::value,
                       to_string(s->src_addr), s->forwarding_asn,
                       self->state.counter);
          } else {
            // handle unmapped macs
            self->send(self, classification_result_atom::value,
                       classification_type::unknown, self->state.counter);
          }
        }
      }
      if (self->state.reader_ptr)
        self->send(self, parse_sflow_atom::value);
    },
    [=](classification_result_atom, const classification_type& t,
        const uint64_t& n) {
      if (self->state.samples_map.count(n) > 0) {
        auto sx = self->state.samples_map[n];
        self->state.samples_map[n]->label = t;
        self->send(self, write_results_atom::value, n);
      }
    },
    [=](write_results_atom, uint64_t n) {
      if (self->state.writer_ptr && self->state.samples_map.count(n) > 0) {
        self->state.writer_ptr->sample_to_disk(self->state.samples_map[n]);
        self->send(stats_processor, add_check_result_atom::value,
                   std::move(*self->state.samples_map[n]));
        self->state.samples_map[n].reset();
        self->state.samples_map.erase(n);
      }

      if (self->state.samples_map.empty() && !self->state.reader_ptr) {
        if (self->state.writer_ptr)
          self->state.writer_ptr.reset();

        aout(self) << "finish writing " << self->state.output_path;

        if (self->state.output_path[self->state.output_path.size() - 1]
            != '/') {
          aout(self) << "/" << self->state.file_name << ".gz" << endl;
        } else {
          aout(self) << self->state.file_name << ".gz" << endl;
        }

        self->quit();
      } else if (self->state.reader_ptr)
        self->send(self, parse_sflow_atom::value);
    }};
}
} // namespace client
} // namespace customer_cone