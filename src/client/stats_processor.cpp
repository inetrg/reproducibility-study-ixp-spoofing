#include <iostream>
#include <utility>
#include <vector>

#include "IPv4Layer.h"
#include "Packet.h"
#include <DnsLayer.h>
#include <EthLayer.h>
#include <IcmpLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <backward/strstream>
#include <netinet/in.h>

#include "customer_cone/client/checker.hpp"
#include "customer_cone/client/client.hpp"
#include "customer_cone/ipv4_address.hpp"
#include "customer_cone/server/server.hpp"
#include "customer_cone/utils/string.hpp"
#include <customer_cone/client/file_processor.hpp>
#include <customer_cone/client/stats_processor.hpp>

using namespace std;
using namespace pcpp;
using namespace customer_cone::utils::str;

namespace {
string print_it_stats(uint64_t item_count, uint64_t class_count,
                      uint64_t all_count) {
  auto item_d = static_cast<long double>(item_count);
  std::stringstream ss;
  ss << "{\"pkts\":" << item_count << ",\"fraction_class\":" << std::fixed
     << std::setprecision(8) << item_d / class_count
     << ",\"fraction_all\":" << item_d / all_count << "}";
  return ss.str();
}
string print_class_stats(uint64_t class_count, uint64_t all_count) {
  auto class_d = static_cast<long double>(class_count);
  std::stringstream ss;
  ss << "{\"pkts\":" << class_count << ",\"fraction_all\":" << std::fixed
     << std::setprecision(8) << class_d / all_count << "}";
  return ss.str();
}
string print_entry(const string& name, const string& value) {
  stringstream ss;
  ss << "\"" << name << "\":\"" << value << "\"";
  return ss.str();
}
} // namespace

namespace customer_cone {
namespace client {

const char* stats_state::name = "cc_stats_processor";
caf::behavior stats_processor_behav(caf::stateful_actor<stats_state>* self,
                                    const std::string& path) {
  return {
    [=](add_check_result_atom, const sample& s) {
      if (self->state.pkt_stats.count(s.label) == 0)
        self->state.pkt_stats[s.label] = stats{};

      // Count pkts
      self->state.pkt_count += s.sample_rate;
      self->state.pkt_stats[s.label].pkt_count += s.sample_rate;

      // get item for current transport protocol
      if (self->state.pkt_stats[s.label].items.count(s.trans_proto) == 0) {
        self->state.pkt_stats[s.label].items[s.trans_proto][s.proto] = item{};
        self->state.pkt_stats[s.label].proto_pkt_count[s.trans_proto][s.proto]
          = 0;
        self->state.pkt_stats[s.label].trans_proto_pkt_count[s.trans_proto] = 0;
      }

      // Count protocol usage
      self->state.pkt_stats[s.label].proto_pkt_count[s.trans_proto][s.proto]
        += s.sample_rate;
      self->state.pkt_stats[s.label].trans_proto_pkt_count[s.trans_proto]
        += s.sample_rate;

      // Sum ports
      for (const auto& x : s.checks.ports) {
        if (self->state.pkt_stats[s.label]
              .items[s.trans_proto][s.proto]
              .ports.count(x.first)
            == 0)
          self->state.pkt_stats[s.label]
            .items[s.trans_proto][s.proto]
            .ports[x.first]
            = 0;
        self->state.pkt_stats[s.label]
          .items[s.trans_proto][s.proto]
          .ports[x.first]
          += x.second * s.sample_rate;
      }

      // Sum checks
      for (const auto& x : s.checks.str_checks) {
        if (self->state.pkt_stats[s.label]
              .items[s.trans_proto][s.proto]
              .str_checks.count(x.first)
            == 0)
          self->state.pkt_stats[s.label]
            .items[s.trans_proto][s.proto]
            .str_checks[x.first]
            = 0;
        self->state.pkt_stats[s.label]
          .items[s.trans_proto][s.proto]
          .str_checks[x.first]
          += x.second * s.sample_rate;
      }
    },
    [=](write_check_result_atom) {
      gzFile file = gzopen((path + "/stats.json.gz").c_str(), "wb");
      gzprintf(file, "{\"traffic-classes\":{");
      stringstream st;
      size_t num_proto = 0;
      size_t num_enc_proto = 0;
      size_t num_classification_types = 0;

      for_each(
        self->state.pkt_stats.begin(), self->state.pkt_stats.end(),
        [&](const pair<classification_type, stats>& p) {
          st << "\"" << to_string(p.first) << "\":{"
             << "\"stats\":"
             << print_class_stats(p.second.pkt_count, self->state.pkt_count)
             << ",\"protocols\":{";
          gzprintf(file, st.str().c_str());
          st.str("");
          for_each(
            p.second.items.begin(), p.second.items.end(),
            [&](const pair<pcpp::ProtocolType,
                           std::map<pcpp::ProtocolType, item>>& c) {
              st << "\"" << to_string(c.first) << R"(": {"stats":)"
                 << print_it_stats(p.second.trans_proto_pkt_count.at(c.first),
                                   p.second.pkt_count, self->state.pkt_count)
                 << ",\"encapsulated-protocols\":{";
              gzprintf(file, st.str().c_str());
              st.str("");
              for_each(
                c.second.begin(), c.second.end(),
                [&](const pair<pcpp::ProtocolType, item>& d) {
                  st << "\"" << to_string(d.first) << R"(": {"stats":)"
                     << print_it_stats(
                          p.second.proto_pkt_count.at(c.first).at(d.first),
                          p.second.pkt_count, self->state.pkt_count);
                  gzprintf(file, st.str().c_str());
                  st.str("");
                  gzprintf(file, ",\"dst-ports\":{");
                  for_each(d.second.ports.begin(), d.second.ports.end(),
                           [&](const pair<uint16_t, uint64_t>& e) {
                             st << "\"" << to_string(e.first) << "\":"
                                << print_it_stats(e.second, p.second.pkt_count,
                                                  self->state.pkt_count)
                                << ",";
                           });
                  auto p_str = st.str();
                  if (!p_str.empty()) {
                    p_str.pop_back();
                  }
                  gzprintf(file, p_str.c_str());
                  st.str("");
                  gzprintf(file, "},\"checks\":{");
                  for_each(d.second.str_checks.begin(),
                           d.second.str_checks.end(),
                           [&](const pair<string, uint64_t>& e) {
                             st << "\"" << e.first << "\":"
                                << print_it_stats(e.second, p.second.pkt_count,
                                                  self->state.pkt_count)
                                << ",";
                           });
                  auto c_str = st.str();
                  if (!c_str.empty()) {
                    c_str.pop_back();
                    c_str.push_back('}');
                  } else {
                    c_str = "}";
                  }
                  gzprintf(file, c_str.c_str());
                  st.str("");
                  num_enc_proto++;
                  if (c.second.size() > 1 && num_enc_proto < c.second.size())
                    gzprintf(file, "},");
                  else
                    gzprintf(file, "}}");
                });
              num_enc_proto = 0;
              num_proto++;
              if (p.second.items.size() > 1
                  && num_proto < p.second.items.size())
                gzprintf(file, "},");
              else
                gzprintf(file, "}}");
            });
          num_proto = 0;
          num_classification_types++;
          if (self->state.pkt_stats.size() > 1
              && num_classification_types < self->state.pkt_stats.size())
            gzprintf(file, "},");
          else
            gzprintf(file, "}}");
        });
      gzprintf(file, "}");
      gzclose(file);
      return caf::make_message(true);
    },
  };
}
} // namespace client
} // namespace customer_cone
