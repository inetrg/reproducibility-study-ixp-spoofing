#include <iostream>
#include <utility>
#include <vector>

#include "IPv4Layer.h"
#include "Packet.h"
#include <DnsLayer.h>
#include <EthLayer.h>
#include <HttpLayer.h>
#include <IcmpLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <netinet/in.h>

#include "customer_cone/client/checker.hpp"
#include "customer_cone/client/client.hpp"
#include "customer_cone/ipv4_address.hpp"
#include "customer_cone/server/server.hpp"
#include "customer_cone/stats.hpp"
#include "customer_cone/utils/string.hpp"

using namespace std;
using namespace pcpp;
using namespace customer_cone::utils::str;

namespace customer_cone {
namespace client {

void checker::check_sample(
  const shared_ptr<sample>& s,
  const shared_ptr<unordered_map<string, uint32_t>>& asn_mac_mapping) {

  item it = item{};

  if (s->packet.isPacketOfType(IPv4)) {
    auto ipv4l = s->packet.getLayerOfType<IPv4Layer>();
    IPv4Address src_ip = ipv4l->getSrcIpAddress();
    IPv4Address dst_ip = ipv4l->getDstIpAddress();
    s->src_addr = ipv4_address{src_ip.toString()};
    s->dst_addr = ipv4_address{dst_ip.toString()};
    s->trans_proto = ipv4l->getProtocol();
    s->ttl = ipv4l->getIPv4Header()->timeToLive;

    if (s->src_addr == s->dst_addr) {
      it.str_checks.emplace("same-src-dst", 1);
    }
  }

  if (auto ethl = s->packet.getLayerOfType<EthLayer>()) {
    auto mx = to_string(ethl->getEthHeader()->srcMac);
    if (asn_mac_mapping->count(mx) > 0) {
      s->forwarding_asn = asn_mac_mapping->at(mx);
    } else
      s->forwarding_asn = 0;
  }

  if (auto tl = s->packet.getLayerOfType<TcpLayer>()) {
    s->trans_proto = TCP;
    s->src_port = ntohs(tl->getTcpHeader()->portSrc);
    s->dst_port = ntohs(tl->getTcpHeader()->portDst);
    vector<string> flags;
    if (tl->getTcpHeader()->ackFlag == 1)
      flags.emplace_back("ack");
    if (tl->getTcpHeader()->synFlag == 1)
      flags.emplace_back("syn");
    if (tl->getTcpHeader()->finFlag == 1)
      flags.emplace_back("fin");
    if (tl->getTcpHeader()->eceFlag == 1)
      flags.emplace_back("ece");
    if (tl->getTcpHeader()->urgFlag == 1)
      flags.emplace_back("urg");
    if (tl->getTcpHeader()->rstFlag == 1)
      flags.emplace_back("rst");
    if (tl->getTcpHeader()->pshFlag == 1)
      flags.emplace_back("psh");
    it.str_checks.emplace(caf::join(flags, "-"), 1);

    if (s->dst_port == 0 || s->src_port == 0)
      it.str_checks.emplace("tcp-port-0", 1);

  } else if (auto ul = s->packet.getLayerOfType<UdpLayer>()) {
    s->trans_proto = UDP;
    s->src_port = ntohs(ul->getUdpHeader()->portSrc);
    s->dst_port = ntohs(ul->getUdpHeader()->portDst);

    if (s->dst_port == 0 || s->src_port == 0)
      it.str_checks.emplace("udp-port-0", 1);
  } else if (auto icmp = s->packet.getLayerOfType<IcmpLayer>()) {
    s->trans_proto = ICMP;
    auto type
      = to_string(static_cast<IcmpMessageType>(icmp->getIcmpHeader()->type));
    to_lower(type);
    it.str_checks.emplace(type, 1);
  }

  if (auto http_req = s->packet.getLayerOfType<HttpRequestLayer>()) {
    s->proto = HTTPRequest;
    it.str_checks.emplace("request-payload-size", http_req->getDataLen());
  } else if (auto http_res = s->packet.getLayerOfType<HttpResponseLayer>()) {
    it.str_checks.emplace("response-payload-size", http_res->getDataLen());
    s->proto = HTTPResponse;
  }

  if (auto dns = s->packet.getLayerOfType<DnsLayer>()) {
    s->proto = DNS;
    auto query_count = dns->getQueryCount();
    if (query_count > 0)
      it.str_checks.emplace("dns-request", 1);
  }

  if (s->trans_proto == UnknownProtocol) {
    for (auto c_l = s->packet.getFirstLayer(); c_l != nullptr;
         c_l = c_l->getNextLayer()) {
      if (c_l->getProtocol() != UnknownProtocol
          && c_l->getOsiModelLayer() <= OsiModelTransportLayer)
        s->trans_proto = c_l->getProtocol();
    }
  }

  if (s->proto == UnknownProtocol) {
    for (auto c_l = s->packet.getFirstLayer(); c_l != nullptr;
         c_l = c_l->getNextLayer()) {
      if (c_l->getProtocol() != UnknownProtocol
          && c_l->getOsiModelLayer() > OsiModelTransportLayer)
        s->proto = c_l->getProtocol();
    }
  }

  if (s->trans_proto != ICMP) {
    if (s->dst_addr == s->src_addr)
      it.str_checks.emplace("same-src-dst", 1);

    if (s->dst_port != 0 && s->dst_port < dyn_port_lower_bound) {
      it.ports.emplace(s->dst_port, 1);

    } else if (s->dst_port != 0) {
      it.str_checks.emplace("dyn-ports", 1);
    }
  }

  s->checks = it;
}
} // namespace client
} // namespace customer_cone
