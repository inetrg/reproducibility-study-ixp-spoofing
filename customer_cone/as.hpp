#pragma once

#include <iostream>
#include <memory>
#include <set>
#include <map>
#include <vector>

#include "caf/all.hpp"

#include "customer_cone/utils/compare.hpp"
#include "ipv4_prefix.hpp"

namespace customer_cone {
using namespace utils::compare;

struct ipv4_prefix;

class as;

using as_ptr = std::shared_ptr<as>;
using ipv4_prefix_ptr = std::shared_ptr<ipv4_prefix>;
using as_map = std::map<long, as_ptr>;

class as : public std::enable_shared_from_this<as> {
public:
  uint32_t asn;

  std::map<std::string, ipv4_prefix_ptr> prefixes;

  /// Holds provider to customer relations of the AS
  std::map<long, as_ptr> p2c_relations;

  /// Holds provider to provider relations of the AS
  std::map<long, as_ptr> p2p_relations;

  explicit as(long asn);

  inline as_ptr ptr() {
    return shared_from_this();
  }

  bool add_prefix(const ipv4_prefix_ptr& p);

  bool rm_prefix(const ipv4_prefix_ptr& p);

  bool add_p2p(const as_ptr& p);

  bool rm_p2p(const as_ptr& p);

  bool add_c2p(const as_ptr& p);

  bool rm_c2p(const as_ptr& p);

  std::shared_ptr<as_map> cone(bool allow_transitive_p2p = false);

  bool is_in_cone(const ipv4_prefix& prefix);

  bool is_in_cone(const std::string& ip);

  bool is_in_cone(long as);

  std::string to_string();

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, as& x) {
    return f(caf::meta::type_name("as"), x.asn, x.prefixes, x.p2p_relations,
             x.p2c_relations, x.cone_cached_, x.prefixes_cached_);
  }

private:
  std::shared_ptr<as_map> cone(const std::shared_ptr<as_map>& cone, long mp_asn,
                               bool allow_p2p = false,
                               bool allow_transitive_p2p = false);

  as_map cone_cached_;

  std::set<ipv4_prefix_ptr> prefixes_cached_;

  bool add_p2c(const as_ptr& c);
};
} // namespace customer_cone