#include "customer_cone/trie.hpp"
#include "customer_cone/byte_addr.hpp"
#include <algorithm>

using namespace std;

namespace customer_cone {

bool trie::insert(const shared_ptr<ipv4_prefix>& p) {
  bool r = false;
  if (!root) {
    root = std::make_shared<trie_node>();
  }
  auto c = root;
  for (size_t i = 0; i < byte_addr::num_bytes; i++) {

    auto k = p->addr.bytes[i] & p->subn_mask.bytes[i];
    auto cn = c->children.find(k);

    if (cn == c->children.end()) {
      auto nn = make_shared<trie_node>();
      nn->parent = c;
      c->children[k] = nn;
      c = nn;
    } else {
      c = cn->second;
    }
    if (p->subn_mask.bytes[i] < 255
        || (i < byte_addr::num_bytes - 1 && p->subn_mask.bytes[i + 1] < 255)) {
      r = c->prefixes.emplace(p->to_string(), p).second;
      break;
    }
  }
  return r;
}

std::vector<shared_ptr<ipv4_prefix>> trie::search(const ipv4_prefix& p) {
  auto r = std::vector<shared_ptr<ipv4_prefix>>();
  auto xn = root;
  while (xn && !xn->children.empty()) {
    for (size_t i = 0; i < byte_addr::num_bytes; i++) {
      auto k = p.addr.bytes[i] & p.subn_mask.bytes[i];
      auto cn = xn->children.find(k);
      if (cn != xn->children.end()) {
        for_each(cn->second->prefixes.begin(), cn->second->prefixes.end(),
                [&](const auto& xp) { if (xp.second->contains(p)) r.push_back(xp.second); });
        xn = cn->second;
      } else {
        xn.reset();
        break;
      }
    }
  }

  return r;
}

std::vector<shared_ptr<ipv4_prefix>> trie::get_all_prefixes() {
  std::vector<shared_ptr<ipv4_prefix>> prefixes = {};

  if (root)
    get_prefixes(root, prefixes);

  return prefixes;
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "InfiniteRecursion"
void trie::get_prefixes(const shared_ptr<trie_node>& cn,
                        vector<shared_ptr<ipv4_prefix>>& prefixes) {
  for_each(cn->prefixes.begin(), cn->prefixes.end(),
           [&](const auto& tn) { prefixes.push_back(tn.second); });

  for_each(cn->children.begin(), cn->children.end(),
           [&](const auto& tn) { get_prefixes(tn.second, prefixes); });
}
#pragma clang diagnostic pop
} // namespace customer_cone