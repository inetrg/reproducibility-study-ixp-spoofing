#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "ipv4_prefix.hpp"

namespace customer_cone {

struct trie_node {
  std::shared_ptr<trie_node> parent;
  std::map<uint8_t, std::shared_ptr<trie_node>> children;
  std::map<std::string, std::shared_ptr<ipv4_prefix>> prefixes;

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, trie_node& x) {
    return f(caf::meta::type_name("trie_node"), x.parent, x.children,
             x.prefixes);
  }
};

class trie {
private:
  std::shared_ptr<trie_node> root = nullptr;

public:
  bool insert(const std::shared_ptr<ipv4_prefix>& p);

  std::vector<std::shared_ptr<ipv4_prefix>> search(const ipv4_prefix& p);

  std::vector<std::shared_ptr<ipv4_prefix>> get_all_prefixes();

  static void get_prefixes(const std::shared_ptr<trie_node>& cn,
                           std::vector<std::shared_ptr<ipv4_prefix>>& prefixes);

  template <class Inspector>
  typename Inspector::result_type inspect(Inspector& f, trie& x) {
    return f(caf::meta::type_name("trie"), x.root);
  }
};
} // namespace customer_cone