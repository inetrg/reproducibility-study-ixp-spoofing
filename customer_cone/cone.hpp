#pragma once

#include <algorithm>
#include <array>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "caf/optional.hpp"

#include "customer_cone/as.hpp"
#include "customer_cone/classification_type.hpp"
#include "customer_cone/ipv4_prefix.hpp"
#include "customer_cone/trie.hpp"
#include "customer_cone/utils/string.hpp"

#include "caf/all.hpp"

namespace customer_cone {

class cone {
public:
  static const std::string BOGON_ADDRESSES[];

  explicit cone(bool allow_transitive_p2p);

  trie prefixes_trie;

  trie bogons_trie;

  bool allow_transitive_p2p;

  as_map ases;

  std::map<uint32_t, std::shared_ptr<as_map>> cones;

  bool add_prefix(const std::string& p, uint32_t asn);

  bool rm_prefix(const std::string& p, uint32_t asn);

  bool add_as(uint32_t asn);

  std::shared_ptr<as> get_as(uint32_t asn);

  bool add_p2p(uint32_t a, uint32_t b);

  bool rm_p2p(uint32_t a, uint32_t b);

  bool add_c2p(uint32_t c, uint32_t p);

  bool rm_c2p(uint32_t c, uint32_t p);

  std::shared_ptr<as_map> get_cone(uint32_t asn);

  classification_type is_ip_in_cone(const std::string& ip, uint32_t asn);

  bool is_ip_bogon(const std::string& ip);

  bool is_as_in_cone(uint32_t asn, uint32_t xasn);

  std::string dispatch(const std::string& s);

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, cone& x) {
    return f(caf::meta::type_name("cone"), x.prefixes_trie, x.ases,
             x.allow_transitive_p2p);
  }

private:
  std::vector<as_ptr> get_origin(const std::string& ip);
};
} // namespace customer_cone