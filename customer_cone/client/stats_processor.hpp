#pragma once

#include "Packet.h"

#include "caf/all.hpp"
#include "caf/io/all.hpp"

#include "customer_cone/client/client.hpp"
#include "customer_cone/sample.hpp"
#include "customer_cone/server/server.hpp"

namespace customer_cone {

namespace client {

using add_check_result_atom = caf::atom_constant<caf::atom("add_res")>;
using write_check_result_atom = caf::atom_constant<caf::atom("write_res")>;

struct stats_state {
  static const char* name;
  uint64_t pkt_count;
  std::map<classification_type, stats> pkt_stats;
};

caf::behavior stats_processor_behav(caf::stateful_actor<stats_state>* self,
                                    const std::string& path);

} // namespace client
} // namespace customer_cone