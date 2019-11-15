#include <utility>

#include <utility>

#include <utility>

#include <cmath>
#include <iterator>

#include "customer_cone/as.hpp"
#include "customer_cone/ipv4_prefix.hpp"
#include "customer_cone/utils/string.hpp"

using namespace std;

namespace customer_cone {
using namespace utils::str;
ipv4_prefix ipv4_prefix::make(const std::string& prefix,
                              const std::shared_ptr<as>& o_as) {
  auto prefix_o = ipv4_prefix::make(prefix);
  prefix_o.origins.emplace(o_as->asn, o_as);
  o_as->prefixes.emplace(prefix, make_shared<ipv4_prefix>(prefix_o));

  return prefix_o;
}

ipv4_prefix ipv4_prefix::make(const std::string& p) {
  auto r = split(p, '/');
  ipv4_prefix prefix_o{ipv4_address{r[0]},
                       ipv4_subnet_mask::make(std::stoi(r[1]))};

  return prefix_o;
}

ipv4_prefix::ipv4_prefix(const ipv4_address& a, const ipv4_subnet_mask& s,
                         std::map<uint32_t, std::shared_ptr<as>> origins)
  : addr(a), subn_mask(s), origins{std::move(origins)} {
  lower = (addr.to_number_rep() & subn_mask.to_number_rep());
  upper = (addr.to_number_rep() | (~subn_mask.to_number_rep()));
}

ipv4_prefix::ipv4_prefix(const ipv4_address& a, const ipv4_subnet_mask& s)
  : addr(a), subn_mask(s) {
  lower = (addr.to_number_rep() & subn_mask.to_number_rep());
  upper = (addr.to_number_rep() | (~subn_mask.to_number_rep()));
}

std::string ipv4_prefix::to_string() const {
  return utils::str::to_string(addr) + "/"
         + ::to_string(subn_mask.to_short_rep());
}

bool ipv4_prefix::contains(const std::string& a) const {
  return contains(ipv4_prefix::make(a + "/32"));
}

bool ipv4_prefix::contains(const std::shared_ptr<ipv4_prefix>& a) const {
  return contains(*a);
}

bool ipv4_prefix::contains(const ipv4_prefix& a) const {
  return upper >= a.upper && lower <= a.lower;
}
} // namespace customer_cone