#include "customer_cone/server/server.hpp"
#include "customer_cone/client/client.hpp"

using namespace std;
using namespace caf;
using namespace caf::io;

namespace customer_cone {
namespace server {
const char* customer_cone_state::name = "cc";

behavior server_behav(stateful_actor<customer_cone_state>* self) {
  if (!self->state.g)
    self->state.g = std::make_shared<cone>(
      get_or(self->config(), "allow_transitive_p2p", false));
  return {
    [=](call_atom, const std::string& msg, actor s, connection_handle& hdl) {
      auto r = self->state.g->dispatch(msg);
      cout << r << endl;
      self->send(s, answer_atom::value, move(r), hdl);
    },
    [=](add_p2p_atom, const uint32_t& a, const uint32_t& b) {
      return self->state.g->add_p2p(a, b);
    },
    [=](add_c2p_atom, const uint32_t& a, const uint32_t& b) {
      return self->state.g->add_c2p(a, b);
    },
    [=](add_as_atom, const uint32_t& asn) {
      return self->state.g->add_as(asn);
    },
    [=](add_prefix_atom, const string& prefix, const uint32_t& asn) {
      return self->state.g->add_prefix(prefix, asn);
    },
    [=](ip_in_cone_atom, const string& prefix, const uint32_t& asn) {
      auto r = self->state.g->is_ip_in_cone(prefix, asn);
      return r;
    },
    [=](ip_in_cone_atom, const string& prefix, const uint32_t& asn,
        const uint64_t& sample_number) {
      auto r = self->state.g->is_ip_in_cone(prefix, asn);
      return caf::make_message(client::classification_result_atom::value, r,
                               sample_number);
    },
    [=](get_as_atom, const uint32_t& asn) {
      return self->state.g->dispatch("get_as " + to_string(asn));
    },
    [=](get_cone_atom, const uint32_t& asn) {
      return self->state.g->dispatch("get_cone " + to_string(asn));
    },
    [=](get_cone_atom) { // return self->state.g->cones;
    },
    [=](get_prefixes_atom, const uint32_t& asn) {
      return self->state.g->dispatch("get_prefixes " + to_string(asn));
    },
    [=](get_prefixes_atom) { return self->state.g->dispatch("get_prefixes"); },
  };
}
} // namespace server
} // namespace customer_cone