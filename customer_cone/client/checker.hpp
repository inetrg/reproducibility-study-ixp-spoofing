#pragma once

#include "Packet.h"

#include "caf/all.hpp"
#include "caf/io/all.hpp"

#include "customer_cone/client/client.hpp"
#include "customer_cone/sample.hpp"
#include "customer_cone/server/server.hpp"

namespace customer_cone {

namespace client {
constexpr uint_fast32_t dyn_port_lower_bound = 49152;

using check_sample_atom = caf::atom_constant<caf::atom("check_samp")>;
struct checker_state {
  std::unordered_map<std::string, uint32_t> asn_mac_mapping;
  caf::actor server;
  caf::actor client;
};
caf::behavior
check_behav(caf::stateful_actor<checker_state>* self, const caf::actor& server,
            const caf::actor& client,
            std::unordered_map<std::string, uint32_t> asn_mac_mapping);

struct checker {
  static void
  check_sample(const std::shared_ptr<sample>& s,
               const std::shared_ptr<std::unordered_map<std::string, uint32_t>>&
                 asn_mac_mapping);
};

} // namespace client
} // namespace customer_cone