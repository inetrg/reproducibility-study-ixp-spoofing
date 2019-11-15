#include <chrono>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include <IcmpLayer.h>
#include <caf/string_algorithms.hpp>
#include <iosfwd>

#include "customer_cone/ipv4_address.hpp"
#include "customer_cone/utils/string.hpp"

namespace customer_cone {
namespace utils {
namespace str {

using namespace std;

vector<string> split(const string& s, char delimiter) {
  vector<string> tokens;
  string token;
  istringstream tokenStream(s);
  while (getline(tokenStream, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

string rm_file_ending(const string& file) {
  auto file_v = split(file, '.');
  if (file_v.size() > 1)
    file_v.pop_back();

  return caf::join(file_v.begin(), file_v.end(), ".");
}

string extract_filename(const string& file) {
  auto path_v = split(file, '/');
  return path_v[path_v.size() - 1];
}

string to_string(const uint8_t mac[6]) {
  char str[19];
  snprintf(str, sizeof str, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
  return string(str);
}

string to_string(const byte_addr& addr) {
  string r;
  for (auto i : addr.bytes) {
    r += std::to_string((int)i) + ".";
  }
  r.pop_back();
  return r;
}

std::string to_string(const std::map<std::string, std::string>& m) {
  std::stringstream ss;
  for (const auto& k : m) {
    ss << '(' << k.first << ':' << k.second << ')';
  }
  return ss.str();
}

string to_string(const classification_type& type) {
  switch (type) {
    case classification_type::invalid:
      return "invalid";
    case classification_type ::unrouted:
      return "unrouted";
    case classification_type::bogon:
      return "bogon";
    case classification_type::regular:
      return "regular";
    default:
      return "unknown";
  }
}
string to_string(const pcpp::IcmpMessageType& type) {
  switch (type) {
    case pcpp::ICMP_ECHO_REPLY:
      return "ICMP_ECHO_REPLY";
    case pcpp::ICMP_DEST_UNREACHABLE:
      return "ICMP_DEST_UNREACHABLE";
    case pcpp::ICMP_SOURCE_QUENCH:
      return "ICMP_SOURCE_QUENCH";
    case pcpp::ICMP_REDIRECT:
      return "ICMP_REDIRECT";
    case pcpp::ICMP_ECHO_REQUEST:
      return "ICMP_ECHO_REQUEST";
    case pcpp::ICMP_ROUTER_ADV:
      return "ICMP_ROUTER_ADV";
    case pcpp::ICMP_ROUTER_SOL:
      return "ICMP_ROUTER_SOL";
    case pcpp::ICMP_TIME_EXCEEDED:
      return "ICMP_TIME_EXCEEDED";
    case pcpp::ICMP_PARAM_PROBLEM:
      return "ICMP_PARAM_PROBLEM";
    case pcpp::ICMP_TIMESTAMP_REQUEST:
      return "ICMP_TIMESTAMP_REQUEST";
    case pcpp::ICMP_TIMESTAMP_REPLY:
      return "ICMP_TIMESTAMP_REPLY";
    case pcpp::ICMP_INFO_REQUEST:
      return "ICMP_INFO_REQUEST";
    case pcpp::ICMP_INFO_REPLY:
      return "ICMP_INFO_REPLY";
    case pcpp::ICMP_ADDRESS_MASK_REQUEST:
      return "ICMP_ADDRESS_MASK_REQUEST";
    case pcpp::ICMP_ADDRESS_MASK_REPLY:
      return "ICMP_ADDRESS_MASK_REPLY";
    default:
      return "ICMP_UNSUPPORTED";
  }
}
std::string to_string(const pcpp::ProtocolType& type) {
  switch (type) {
    case pcpp::UnknownProtocol:
      return "unknown";
    case pcpp::Ethernet:
      return "ethernet";
    case pcpp::IPv4:
      return "ipv4";
    case pcpp::IPv6:
      return "ipv6";
    case pcpp::IP:
      return "ip";
    case pcpp::TCP:
      return "tcp";
    case pcpp::UDP:
      return "udp";
    case pcpp::HTTPRequest:
      return "http_request";
    case pcpp::HTTPResponse:
      return "http_response";
    case pcpp::HTTP:
      return "http";
    case pcpp::ARP:
      return "arp";
    case pcpp::VLAN:
      return "vlan";
    case pcpp::ICMP:
      return "icmp";
    case pcpp::PPPoESession:
      return "pppoe_session";
    case pcpp::PPPoEDiscovery:
      return "pppoe_discovery";
    case pcpp::PPPoE:
      return "pppoe";
    case pcpp::DNS:
      return "dns";
    case pcpp::MPLS:
      return "mpls";
    case pcpp::GREv0:
      return "grev0";
    case pcpp::GREv1:
      return "grev1";
    case pcpp::GRE:
      return "gre";
    case pcpp::PPP_PPTP:
      return "ppp_pptp";
    case pcpp::SSL:
      return "ssl";
    case pcpp::SLL:
      return "sll";
    case pcpp::DHCP:
      return "dhcp";
    case pcpp::NULL_LOOPBACK:
      return "null_loopback";
    case pcpp::IGMP:
      return "igmp";
    case pcpp::IGMPv1:
      return "igmpv1";
    case pcpp::IGMPv2:
      return "igmpv2";
    case pcpp::IGMPv3:
      return "igmpv3";
    case pcpp::GenericPayload:
      return "generic_payload";
    case pcpp::VXLAN:
      return "vsxlan";
    case pcpp::SIPRequest:
      return "sip_request";
    case pcpp::SIPResponse:
      return "sip_response";
    case pcpp::SIP:
      return "sip";
    case pcpp::SDP:
      return "sdp";
    case pcpp::PacketTrailer:
      return "packet_trailer";
    case pcpp::Radius:
      return "radius";
  }
}

string to_string(const item& it) {
  return to_string(it.str_checks) + ":" + to_string(it.ports);
}
} // namespace str
} // namespace utils
} // namespace customer_cone