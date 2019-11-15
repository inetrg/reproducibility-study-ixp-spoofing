#define CAF_SUITE trie

#include <memory>
#include <vector>

#include "caf/test/dsl.hpp"

#include "customer_cone/trie.hpp"

using namespace customer_cone;

namespace {

struct trie_fixture : test_coordinator_fixture<> {
  trie t;

  trie_fixture() {
    auto p1 = std::make_shared<ipv4_prefix>(ipv4_prefix::make("1.0.0.0/8"));
    auto p2 = std::make_shared<ipv4_prefix>(ipv4_prefix::make("1.1.0.0/16"));
    auto p3 = std::make_shared<ipv4_prefix>(ipv4_prefix::make("1.1.1.0/24"));
    auto p4 = std::make_shared<ipv4_prefix>(ipv4_prefix::make("89.244.0.0/14"));
    auto p5
      = std::make_shared<ipv4_prefix>(ipv4_prefix::make("89.244.80.0/14"));

    t.insert(p1);
    t.insert(p2);
    t.insert(p3);
    t.insert(p4);
    t.insert(p5);
  }
};
} // namespace

// Makes all members of `fixture` available to tests in the scope.
CAF_TEST_FIXTURE_SCOPE(trie_test, trie_fixture)

// Implements our first test.
CAF_TEST(trie) {
  auto p1 = ipv4_prefix::make("1.1.1.1/32");
  CAF_CHECK(!t.search(p1).empty());
  auto r = t.search(p1);
  CAF_CHECK_FAIL(r.size() == 3);
  CAF_CHECK_EQUAL(r.at(0)->to_string(), "1.0.0.0/8");
  CAF_CHECK_EQUAL(r.at(1)->to_string(), "1.1.0.0/16");
  CAF_CHECK_EQUAL(r.at(2)->to_string(), "1.1.1.0/24");
  auto p2 = ipv4_prefix::make(("9.9.9.9/32"));
  CAF_CHECK(t.search(p2).empty());
  auto r1 = t.search(ipv4_prefix::make("1.2.0.1/32"));
  CAF_CHECK(!r1.empty());
  CAF_CHECK_FAIL(r1.size() == 1);
  CAF_CHECK_EQUAL(r.at(0)->to_string(), "1.0.0.0/8");
  auto r2 = t.search(ipv4_prefix::make("89.244.80.1/32"));
  CAF_CHECK(!r2.empty());
  CAF_CHECK_FAIL(r2.size() == 2);
  CAF_CHECK_EQUAL(r2.at(0)->to_string(), "89.244.0.0/14");
  CAF_CHECK_EQUAL(r2.at(1)->to_string(), "89.244.80.0/14");
  auto r3 = t.search(ipv4_prefix::make("89.244.0.1/32"));
  CAF_CHECK(!r3.empty());
  CAF_CHECK_FAIL(r3.size() == 2);
  CAF_CHECK_EQUAL(r3.at(0)->to_string(), "89.244.0.0/14");
  CAF_CHECK_EQUAL(r3.at(1)->to_string(), "89.244.80.0/14");
}

CAF_TEST_FIXTURE_SCOPE_END()
