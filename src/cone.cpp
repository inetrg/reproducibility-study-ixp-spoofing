#include <caf/pec.hpp>
#include <iterator>
#include <numeric>

#include "customer_cone/cone.hpp"
#include "customer_cone/utils/string.hpp"

using namespace std;

namespace customer_cone {
using namespace utils::str;

const string cone::BOGON_ADDRESSES[]
  = {"0.0.0.0/8",         "10.0.0.0/8",     "100.64.0.0/10",
     "127.0.0.0/8",       "169.254.0.0/16", "172.16.0.0/12",
     "192.0.0.0/24",      "192.0.2.0/24",   "192.88.99.0/24",
     "192.168.0.0/16",    "198.18.0.0/15",  "198.51.100.0/24",
     "203.0.113.0/24",    "224.0.0.0/3",    "240.0.0.0/4",
     "255.255.255.255/32"

};

cone::cone(bool allow_transitive_p2p)
  : allow_transitive_p2p(allow_transitive_p2p) {
  // nop
}

bool cone::add_prefix(const string& p, uint32_t asn) {
  bool r = false;
  auto a = get_as(asn);
  shared_ptr<ipv4_prefix> p_ptr;
  auto pref_v = prefixes_trie.search(ipv4_prefix::make(p));
  if (!pref_v.empty()) {
    for (const auto& x : pref_v) {
      if (x->to_string() == p) {
        x->origins.emplace(a->asn, a);
        r = true;
        p_ptr = x;
      }
    }
  }
  if (!r || pref_v.empty()) {
    if (p_ptr == nullptr)
      p_ptr = make_shared<ipv4_prefix>(ipv4_prefix::make(p, a));
    r = prefixes_trie.insert(p_ptr);
  }
  return a->add_prefix(p_ptr) || r;
}

bool cone::rm_prefix(const string& p, uint32_t asn) {
  auto a = get_as(asn);
  auto p_ptr = make_shared<ipv4_prefix>(ipv4_prefix::make(p, a));

  return a->rm_prefix(p_ptr);
}

shared_ptr<as> cone::get_as(uint32_t asn) {
  shared_ptr<as> a_ptr;
  auto l = ases.find(asn);
  if (l == ases.end()) {
    a_ptr = make_shared<as>(asn);
    ases.insert(pair<uint32_t, shared_ptr<as>>(asn, a_ptr));
  } else {
    a_ptr = l->second;
  }

  return a_ptr;
}

bool cone::add_as(uint32_t asn) {
  return ases.insert(pair<uint32_t, shared_ptr<as>>(asn, make_shared<as>(asn)))
    .second;
}

bool cone::add_p2p(uint32_t a, uint32_t b) {
  auto a_ptr = get_as(a);
  auto b_ptr = get_as(b);

  return a_ptr->add_p2p(b_ptr);
}

// todo fix caching
bool cone::add_c2p(uint32_t c, uint32_t p) {
  auto c_ptr = get_as(c);
  auto p_ptr = get_as(p);

  return c_ptr->add_c2p(p_ptr);
}

shared_ptr<as_map> cone::get_cone(uint32_t asn) {
  auto x = cones.find(asn);
  if (x == cones.end()) {
    auto cas = get_as(asn);
    auto c = cas->cone(allow_transitive_p2p);
    cones.emplace(asn, c);

    return c;
  } else {
    return x->second;
  }
}

bool cone::is_as_in_cone(uint32_t asn, uint32_t xasn) {
  auto cone = get_cone(asn);
  auto r = cone->find(xasn) != cone->end();
  return r;
}

vector<as_ptr> cone::get_origin(const string& ip) {
  auto xp = ipv4_prefix::make(ip + "/32");
  vector<shared_ptr<as>> ro;
  auto p_v = prefixes_trie.search(xp);
  for (const auto& x : p_v) {
    //ro.insert(ro.end(), x->origins.begin(), x->origins.end());
    for (const auto& xx: x->origins) {
      ro.push_back(xx.second);
    }
  }

  return ro;
}

bool cone::is_ip_bogon(const string& p) {
  if (bogons_trie.get_all_prefixes().empty()) {
    for (const auto& x : BOGON_ADDRESSES) {
      bogons_trie.insert(
        make_shared<ipv4_prefix>(ipv4_prefix::make(x + "/24")));
    }
  }

  return !bogons_trie.search(ipv4_prefix::make(p + "/24")).empty();
}

classification_type cone::is_ip_in_cone(const string& ip, uint32_t asn) {
  if (is_ip_bogon(ip)) {
    return classification_type::bogon;
  }

  auto o = get_origin(ip);
  if (!o.empty()) {
    for (const auto& x : o) {
      if (x) {
        if (x->asn == asn || is_as_in_cone(asn, x->asn))
          return classification_type::regular;
      }
    }
  } else {
    return classification_type::unrouted;
  }

  return classification_type::invalid;
}

string cone::dispatch(const string& s) {
  string result;
  auto tokens = split(s, ' ');
  if (tokens.size() == 2 && "add_as" == tokens[0]) {
    result = to_string(add_as(stoll(tokens[1])));
  } else if (tokens.size() == 3 && "is_ip_in_cone" == tokens[0]) {
    result = to_string(is_ip_in_cone(tokens[1], stoll(tokens[2])));
  } else if (tokens.size() == 3 && "add_c2p" == tokens[0]) {
    result = to_string(add_c2p(stoll(tokens[1]), stoll(tokens[2])));
  } else if (tokens.size() == 3 && "rm_c2p" == tokens[0]) {
    result = to_string(rm_c2p(stoll(tokens[1]), stoll(tokens[2])));
  } else if (tokens.size() == 3 && "add_p2p" == tokens[0]) {
    result = to_string(add_p2p(stoll(tokens[1]), stoll(tokens[2])));
  } else if (tokens.size() == 3 && "rm_p2p" == tokens[0]) {
    result = to_string(rm_p2p(stoll(tokens[1]), stoll(tokens[2])));
  } else if (tokens.size() == 3 && "add_prefix" == tokens[0]) {
    result = to_string(add_prefix(tokens[1], stoll(tokens[2])));
  } else if (tokens.size() == 3 && "rm_prefix" == tokens[0]) {
    result = to_string(rm_prefix(tokens[1], stoll(tokens[2])));
  } else if (tokens.size() == 2 && "get_cone" == tokens[0]) {
    auto cone = get_cone(stoll(tokens[1]));
    std::ostringstream oss;
    for_each(cone->begin(), cone->end(),
             [&](std::pair<const uint32_t, std::shared_ptr<as>> b) {
               oss << "," << std::to_string(b.first);
             });

    result = oss.str();
    result.erase(result.begin());

  } else if (tokens.size() == 2 && "get_prefixes" == tokens[0]) {
    auto x = get_as(stoll(tokens[1]));
    std::ostringstream oss;

    for_each(
      x->prefixes.begin(), x->prefixes.end(),
      [&](const pair<string, shared_ptr<ipv4_prefix>>& b) { oss << "," << b.first; });

    result = oss.str();
    if (!result.empty())
      result.erase(result.begin());

  } else if (tokens.size() == 1 && "get_prefixes" == tokens[0]) {
    std::ostringstream oss;
    auto ap = prefixes_trie.get_all_prefixes();
    for_each(ap.begin(), ap.end(), [&](const std::shared_ptr<ipv4_prefix>& b) {
      std::ostringstream oss2;
      for_each(b->origins.begin(), b->origins.end(),
               [&](const pair<uint32_t, std::shared_ptr<as>>& a) { oss2 << "," << a.second->asn; });
      auto o_str = oss2.str();
      o_str.erase(o_str.begin());
      oss << "," << o_str << ":" << b->to_string();
    });

    result = oss.str();
    if (!result.empty())
      result.erase(result.begin());
  }
  return result;
}

// todo fix caching
bool cone::rm_p2p(uint32_t a, uint32_t b) {
  auto a_ptr = get_as(a);
  auto b_ptr = get_as(b);
  return a_ptr->rm_p2p(b_ptr);
}

// todo fix caching
bool cone::rm_c2p(uint32_t c, uint32_t p) {
  auto c_ptr = get_as(c);
  auto p_ptr = get_as(p);
  return c_ptr->rm_c2p(p_ptr);
}
} // namespace customer_cone