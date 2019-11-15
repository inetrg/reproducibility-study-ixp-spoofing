#define CAF_SUITE graph

#include "caf/test/dsl.hpp"

#include "customer_cone/classification_type.hpp"
#include "customer_cone/cone.hpp"

using namespace customer_cone;
using namespace utils::str;

namespace {

struct transitive_p2p_graph_fixture : test_coordinator_fixture<> {
  cone g;
  transitive_p2p_graph_fixture() : g(true) {
    for (auto i = 2; i < 1000; i++) {
      g.add_c2p(i - 1, i);
    }
    g.add_p2p(2, 2000);
    for (auto i = 2000; i < 3000; i++) {
      g.add_c2p(i, i + 1);
    }
    g.add_p2p(2000, 4000);

    for (auto i = 7000; i < 8000; i++) {
      g.add_c2p(5000, i);
    }

    g.add_p2p(2000, 8001);

    g.add_prefix("1.0.0.0/8", 1);
    g.add_prefix("1.4.1.0/24", 2);
    g.add_prefix("1.2.1.0/24", 1);
    g.add_prefix("1.3.1.0/24", 4000);
    g.add_prefix("2.2.2.0/24", 2);
    g.add_prefix("94.206.0.0/16", 2);
    g.add_prefix("85.214.0.0/15", 2);
    g.add_prefix("89.244.0.0/14", 1);
    g.add_prefix("89.244.80.0/14", 2000);
  }
};

struct graph_fixture : test_coordinator_fixture<> {
  cone g;
  graph_fixture() : g(false) {
    for (auto i = 2; i < 1000; i++) {
      g.add_c2p(i - 1, i);
    }
    g.add_p2p(2, 2000);
    for (auto i = 2000; i < 3000; i++) {
      g.add_c2p(i, i + 1);
    }
    g.add_p2p(2000, 4000);

    for (auto i = 7000; i < 8000; i++) {
      g.add_c2p(5000, i);
    }

    g.add_p2p(2000, 8001);

    g.add_prefix("1.0.0.0/8", 1);
    g.add_prefix("1.4.1.0/24", 2);
    g.add_prefix("1.2.1.0/24", 1);
    g.add_prefix("1.3.1.0/24", 4000);
    g.add_prefix("2.2.2.0/24", 2);
    g.add_prefix("94.206.0.0/16", 2);
    g.add_prefix("85.214.0.0/15", 2);
    g.add_prefix("89.244.0.0/14", 1);
    g.add_prefix("89.244.80.0/14", 2000);
  }
};
} // namespace

// Makes all members of `fixture` available to tests in the scope.
CAF_TEST_FIXTURE_SCOPE(graph_tests_transitive_p2p, transitive_p2p_graph_fixture)

// Implements our first test.
CAF_TEST(cone transitive_p2p) {
  CAF_CHECK_EQUAL(g.is_ip_in_cone("1.1.1.1", 1), classification_type::regular);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("1.1.1.1", 4000), classification_type::regular);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.214.0.1", 7001),
                  classification_type::invalid);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.213.0.1", 8001),
                  classification_type::unrouted);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.216.0.1", 8001),
                  classification_type::unrouted);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.214.0.1", 8001),
                  classification_type::regular);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("1.4.1.1", 2), classification_type::regular);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("2.2.3.1", 2), classification_type::unrouted);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("127.0.0.1", 2), classification_type::bogon);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("192.168.0.1", 2),
                  classification_type::bogon);
  std::set<std::string> prefixes2
    = {"1.4.1.0/24", "2.2.2.0/24", "94.206.0.0/16", "85.214.0.0/15"};
  auto result_get_prefixes_2 = g.dispatch("get_prefixes 2");
  auto result_get_prefixes_2_v = split(result_get_prefixes_2, ',');
  CAF_CHECK_EQUAL(result_get_prefixes_2_v.size(), prefixes2.size());
  for (const auto& x : result_get_prefixes_2_v) {
    auto check = prefixes2.find(x);
    CAF_CHECK_NOT_EQUAL(check, prefixes2.end());
  }
  std::set<std::string> prefixes
    = {"2:94.206.0.0/16", "1:89.244.0.0/14", "2000:89.244.80.0/14",
       "2:85.214.0.0/15", "2:2.2.2.0/24",    "2:1.4.1.0/24",
       "4000:1.3.1.0/24", "1:1.2.1.0/24",    "1:1.0.0.0/8"};
  auto result_get_prefixes = g.dispatch("get_prefixes");
  auto result_get_prefixes_v = split(result_get_prefixes, ',');
  CAF_CHECK_EQUAL(result_get_prefixes_v.size(), prefixes.size());
  for (const auto& x : result_get_prefixes_v) {
    auto check = prefixes.find(x);
    CAF_CHECK(check != prefixes.end());
  }
  std::set<std::string> cone8001 = {"1", "4000", "2000", "8001", "2"};
  auto result_cone8001 = g.dispatch("get_cone 8001");
  auto result_cone_8001_v = split(result_cone8001, ',');
  CAF_CHECK_EQUAL(result_cone_8001_v.size(), cone8001.size());
  for (const auto& x : result_cone_8001_v) {
    auto check = cone8001.find(x);
    CAF_CHECK(check != cone8001.end());
  }
  std::set<std::string> cone2 = {"1", "4000", "2000", "8001", "2"};
  auto result_cone2 = g.dispatch("get_cone 2");
  auto result_cone_2_v = split(result_cone2, ',');
  CAF_CHECK_EQUAL(result_cone_2_v.size(), cone2.size());
  for (const auto& x : result_cone_2_v) {
    auto check = cone2.find(x);
    CAF_CHECK(check != cone2.end());
  }
}

CAF_TEST_FIXTURE_SCOPE_END()

CAF_TEST_FIXTURE_SCOPE(graph_tests, graph_fixture)

// Implements our first test.
CAF_TEST(graph) {
  CAF_CHECK_EQUAL(g.is_ip_in_cone("1.1.1.1", 1), classification_type::regular);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("1.1.1.1", 4000),
                  classification_type::invalid);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.214.0.1", 7001),
                  classification_type::invalid);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.213.0.1", 8001),
                  classification_type::unrouted);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.216.0.1", 8001),
                  classification_type::unrouted);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("85.214.0.1", 8001),
                  classification_type::invalid);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("1.4.1.1", 2), classification_type::regular);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("2.2.3.1", 2), classification_type::unrouted);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("127.0.0.1", 2), classification_type::bogon);
  CAF_CHECK_EQUAL(g.is_ip_in_cone("192.168.0.1", 2),
                  classification_type::bogon);
  std::set<std::string> prefixes2
    = {"1.4.1.0/24", "2.2.2.0/24", "94.206.0.0/16", "85.214.0.0/15"};
  auto result_get_prefixes_2 = g.dispatch("get_prefixes 2");
  auto result_get_prefixes_2_v = split(result_get_prefixes_2, ',');
  CAF_CHECK_EQUAL(result_get_prefixes_2_v.size(), prefixes2.size());
  for (const auto& x : result_get_prefixes_2_v) {
    auto check = prefixes2.find(x);
    CAF_CHECK_NOT_EQUAL(check, prefixes2.end());
  }
  std::set<std::string> prefixes
    = {"2:94.206.0.0/16", "1:89.244.0.0/14", "2000:89.244.80.0/14",
       "2:85.214.0.0/15", "2:2.2.2.0/24",    "2:1.4.1.0/24",
       "4000:1.3.1.0/24", "1:1.2.1.0/24",    "1:1.0.0.0/8"};
  auto result_get_prefixes = g.dispatch("get_prefixes");
  auto result_get_prefixes_v = split(result_get_prefixes, ',');
  CAF_CHECK_EQUAL(result_get_prefixes_v.size(), prefixes.size());
  for (const auto& x : result_get_prefixes_v) {
    auto check = prefixes.find(x);
    CAF_CHECK(check != prefixes.end());
  }
  std::set<std::string> cone8001 = {"2000", "8001"};
  auto result_cone8001 = g.dispatch("get_cone 8001");
  auto result_cone_8001_v = split(result_cone8001, ',');
  CAF_CHECK_EQUAL(result_cone_8001_v.size(), cone8001.size());
  for (const auto& x : result_cone_8001_v) {
    auto check = cone8001.find(x);
    CAF_CHECK(check != cone8001.end());
  }
  std::set<std::string> cone2 = {"1", "2000", "2"};
  auto result_cone2 = g.dispatch("get_cone 2");
  auto result_cone_2_v = split(result_cone2, ',');
  CAF_CHECK_EQUAL(result_cone_2_v.size(), cone2.size());
  for (const auto& x : result_cone_2_v) {
    auto check = cone2.find(x);
    CAF_CHECK(check != cone2.end());
  }
}

CAF_TEST_FIXTURE_SCOPE_END()
