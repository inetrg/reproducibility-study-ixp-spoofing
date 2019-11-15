#include "customer_cone/as.hpp"
#include <algorithm>
#include <iterator>

namespace customer_cone {

using namespace std;

as::as(long asn) : asn(asn) {
  // nop
}

bool as::add_prefix(const ipv4_prefix_ptr& p) {
  return prefixes.emplace(p->to_string(), p).second;
}

bool as::add_p2p(const as_ptr& p) {
  return p->p2p_relations.emplace(asn, ptr()).second
         && p2p_relations.emplace(p->asn, p).second;
}

bool as::add_c2p(const as_ptr& p) {
  return p->p2c_relations.emplace(asn, ptr()).second;
}

bool as::add_p2c(const as_ptr& c) {
  return p2c_relations.emplace(c->asn, c).second;
}

shared_ptr<as_map> as::cone(bool allow_transitive_p2p) {
  auto c = make_shared<as_map>();
  return cone(c, asn, true, allow_transitive_p2p);
}

shared_ptr<as_map> as::cone(const shared_ptr<as_map>& cone, long mp_asn,
                            bool allow_p2p, bool allow_transitive_p2p) {
  cone->insert({asn, ptr()});
  if ((p2p_relations.find(mp_asn) == p2p_relations.end() || mp_asn == asn)
      && allow_p2p) {
    for (const auto& r : p2p_relations) {
      if (cone->emplace(r).second) {
        auto tmp_cone = r.second->cone(cone, r.first, allow_transitive_p2p,
                                       allow_transitive_p2p);
        cone->insert(tmp_cone->begin(), tmp_cone->end());
      }
    }
  }
  if (cone_cached_.empty()) {
    for (const auto& r : p2c_relations) {
      if (cone->emplace(r).second) {
        auto tmp_cone = r.second->cone(cone, mp_asn);
        cone_cached_.insert(tmp_cone->begin(), tmp_cone->end());
        cone->insert(tmp_cone->begin(), tmp_cone->end());
      }
    }
  } else {
    cone->insert(cone_cached_.begin(), cone_cached_.end());
  }

  return cone;
}

bool as::is_in_cone(const ipv4_prefix& prefix) {
  if (prefixes_cached_.empty()) {
    auto c = cone();
    for (const auto& as : *c) {
      for (const auto& p : as.second->prefixes)
        prefixes_cached_.emplace(p.second);
    }
  }

  return any_of(prefixes_cached_.cbegin(), prefixes_cached_.cend(),
                [&prefix](const auto& p) { return p->contains(prefix); });
}

bool as::is_in_cone(const string& ip) {
  auto prefix_o = ipv4_prefix::make(ip + "/32");
  return is_in_cone(prefix_o);
}

string as::to_string() {
  vector<long> p2p = {};
  vector<long> p2c = {};
  transform(p2c_relations.begin(), p2c_relations.end(), std::back_inserter(p2c),
            [](const auto c) -> long { return c.first; });
  transform(p2p_relations.begin(), p2p_relations.end(), std::back_inserter(p2p),
            [](const auto c) -> long { return c.first; });
  stringstream p2p_st;
  copy(p2p.begin(), p2p.end(), ostream_iterator<long>(p2p_st, ","));
  stringstream p2c_st;
  copy(p2c.begin(), p2c.end(), ostream_iterator<long>(p2c_st, ","));
  auto p2p_s = p2p_st.str();
  if (!p2p_s.empty())
    p2p_s.pop_back();
  auto p2c_s = p2c_st.str();
  if (!p2c_s.empty())
    p2c_s.pop_back();
  return "ASN:" + std::to_string(asn) + ", p2p: [" + p2p_s + "], p2c: [" + p2c_s
         + "]";
}

bool as::rm_prefix(const ipv4_prefix_ptr& p) {
  if (prefixes.count(p->to_string())) {
    prefixes.erase(p->to_string());
    return true;
  }
  return false;
}

bool as::rm_p2p(const as_ptr& p) {
  return p2p_relations.erase(p->asn) > 0;
}

bool as::rm_c2p(const as_ptr& c) {
  return p2c_relations.erase(c->asn) > 0;
}

bool as::is_in_cone(long as) {
  auto c = cone();
  return c->find(as) != c->end();
}
} // namespace customer_cone