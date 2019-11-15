#pragma once

#include "caf/all.hpp"
#include "caf/io/all.hpp"

#include "customer_cone/cone.hpp"

namespace customer_cone {
namespace server {
using call_atom = caf::atom_constant<caf::atom("dispatch")>;

using answer_atom = caf::atom_constant<caf::atom("answer")>;

using add_p2p_atom = caf::atom_constant<caf::atom("add_p2p")>;

using add_c2p_atom = caf::atom_constant<caf::atom("add_c2p")>;

using add_as_atom = caf::atom_constant<caf::atom("add_as")>;

using add_prefix_atom = caf::atom_constant<caf::atom("add_prefix")>;

using ip_in_cone_atom = caf::atom_constant<caf::atom("ip_in_cone")>;

using get_as_atom = caf::atom_constant<caf::atom("get_as")>;

using get_cone_atom = caf::atom_constant<caf::atom("get_cone")>;

using get_prefixes_atom = caf::atom_constant<caf::atom("get_pref")>;

struct customer_cone_state {
  static const char* name;
  std::shared_ptr<cone> g;
};

caf::behavior server_behav(caf::stateful_actor<customer_cone_state>* self);
} // namespace server
} // namespace customer_cone