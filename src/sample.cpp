#include <sstream>

#include "IPv4Layer.h"
#include "Packet.h"
#include <ArpLayer.h>
#include <EthLayer.h>
#include <TcpLayer.h>

#include "customer_cone/sample.hpp"
#include "customer_cone/utils/string.hpp"

using namespace std;
using namespace pcpp;
using customer_cone::utils::str::to_string;

namespace customer_cone {

sample::sample(pcpp::Packet& packet, uint32_t sample_rate)
  : src_addr(ipv4_address{"0.0.0.0"}),
    dst_addr(ipv4_address{"0.0.0.0"}),
    packet(packet),
    sample_rate(sample_rate) {
  proto = pcpp::UnknownProtocol;
  trans_proto = pcpp::UnknownProtocol;
  label = unknown;
}

string sample::line_fields() {
  return "asn,label,src-ip,dst-ip,src-mac,dst-mac,trans-protocol,src-port,dst-"
         "port,"
         "trans_protocol_str,protocol_str,pkt-size,ttl,sample-rate,vlan-in,"
         "vlan-out,timestamp,{checks}";
}

string sample::line_rep() {
  ostringstream oss;

  auto ipv4l = packet.getLayerOfType<IPv4Layer>();
  auto ethl = packet.getLayerOfType<EthLayer>();

  oss << forwarding_asn << ',' << to_string(label) << ',' << to_string(src_addr)
      << ',' << to_string(dst_addr) << ','
      << (ethl ? to_string(ethl->getEthHeader()->srcMac) : "") << ','
      << (ethl ? to_string(ethl->getEthHeader()->dstMac) : "") << ','
      << (ipv4l ? to_string(ipv4l->getIPv4Header()->protocol) : "") << ','
      << src_port << ',' << dst_port << ',' << to_string(trans_proto) << ','
      << to_string(proto) << ',' << sampled_packet_size << ',' << to_string(ttl)
      << ',' << sample_rate << ',' << vlan_in << ',' << vlan_out << ','
      << packet.getRawPacket()->getPacketTimeStamp().tv_sec << ",{"
      << to_string(checks) << '}' << endl;
  auto r = oss.str();
  return r;
}
sample::~sample() {
  packet.getRawPacket()->clear();
  checks.ports.clear();
  checks.str_checks.clear();
}
} // namespace customer_cone