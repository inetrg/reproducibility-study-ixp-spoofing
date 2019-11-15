/* Copyright (c) 2002-2019 InMon Corp. Licensed under the terms of the InMon
 * sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#pragma once

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <search.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "encoder.hpp"
#include "sflow.h"      /* sFlow v5 */
#include "sflow_v2v4.h" /* sFlow v2/4 */

#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

#include "customer_cone/sample.hpp"
#include "sflow_data.hpp"

namespace customer_cone {
namespace sflow {
/* define my own IP header struct - to ease portability */
struct myiphdr {
  uint8_t version_and_headerLen;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

/* ip6 header if no option headers */
struct myip6hdr {
  uint8_t version_and_priority;
  uint8_t priority_and_label1;
  uint8_t label2;
  uint8_t label3;
  uint16_t payloadLength;
  uint8_t nextHeader;
  uint8_t ttl;
  struct in6_addr saddr;
  struct in6_addr daddr;
};

/* same for tcp */
struct mytcphdr {
  uint16_t th_sport; /* source port */
  uint16_t th_dport; /* destination port */
  uint32_t th_seq;   /* sequence number */
  uint32_t th_ack;   /* acknowledgement number */
  uint8_t th_off_and_unused;
  uint8_t th_flags;
  uint16_t th_win; /* window */
  uint16_t th_sum; /* checksum */
  uint16_t th_urp; /* urgent pointer */
};

/* and UDP */
struct myudphdr {
  uint16_t uh_sport; /* source port */
  uint16_t uh_dport; /* destination port */
  uint16_t uh_ulen;  /* udp length */
  uint16_t uh_sum;   /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
  uint8_t type; /* message type */
  uint8_t code; /* type sub-code */
  /* ignore the rest */
};

#ifdef SPOOFSOURCE
#define SPOOFSOURCE_SENDPACKET_SIZE 2000
struct mySendPacket {
  struct myiphdr ip;
  struct myudphdr udp;
  uint8_t data[SPOOFSOURCE_SENDPACKET_SIZE];
};
#endif

/* tcpdump file format */

struct pcap_file_header {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone; /* gmt to local correction */
  uint32_t sigfigs;  /* accuracy of timestamps */
  uint32_t snaplen;  /* max length saved portion of each pkt */
  uint32_t linktype; /* data link type (DLT_*) */
};

struct pcap_pkthdr {
  uint32_t ts_sec; /* time stamp - used to be struct timeval, but time_t can be
                      64 bits now */
  uint32_t ts_usec;
  uint32_t caplen; /* length of portion present */
  uint32_t len;    /* length this packet (off wire) */
  /* some systems expect to see more information here. For example,
   * on some versions of RedHat Linux, there are three extra fields:
   *   int index;
   *   unsigned short protocol;
   *   unsigned char pkt_type;
   */
};

typedef struct _SFForwardingTarget {
  struct _SFForwardingTarget* nxt;
  struct sockaddr_in addr;
  int sock;
} SFForwardingTarget;

typedef struct _SFForwardingTarget6 {
  struct _SFForwardingTarget6* nxt;
  struct sockaddr_in6 addr;
  int sock;
} SFForwardingTarget6;

typedef union _SFSockAddr {
  struct sockaddr_in sa4;
  struct sockaddr_in6 sa6;
} SFSockAddr;

typedef enum {
  SFLFMT_FULL = 0,
  SFLFMT_PCAP,
  SFLFMT_LINE,
  SFLFMT_LINE_CUSTOM,
  SFLFMT_NETFLOW,
  SFLFMT_FWD,
  SFLFMT_CLF,
  SFLFMT_SCRIPT,
  SFLFMT_JSON
} EnumSFLFormat;

#define SA_MAX_PCAP_PKT 65536
#define SA_MAX_SFLOW_PKT_SIZ 65536

#define SA_MAX_FIELDNAME_LEN 64

#define MAX_STRBUF_LEN 2048
typedef struct {
  int cap;
  int len;
  char str[MAX_STRBUF_LEN];
} SFStr;

typedef enum { SFSCOPE_NONE, SFSCOPE_DATAGRAM, SFSCOPE_SAMPLE } EnumSFScope;

struct SFFieldList {
  int n;
  char** fields;
  SFStr* values;
  /* dynamic info */
  char* fieldScope;
  int sampleFields;
};

struct SFConfig {
  /* sflow(R) options */
  uint16_t sFlowInputPort;
  /* netflow(TM) options */
  uint16_t netFlowOutputPort;
  SFLAddress netFlowOutputIP;
  SFSockAddr netFlowOutputSA;
  int netFlowOutputSocket;
  uint16_t netFlowPeerAS;
  int disableNetFlowScale;
  uint16_t netFlowVersion;
  /* tcpdump options */
  char* readPcapFileName;
  FILE* readPcapFile;
  struct pcap_file_header readPcapHdr;
  char* writePcapFile;
  EnumSFLFormat outputFormat;
  int jsonIndent;
  int jsonStart;
  int jsonListStart;
  int outputDepth;
  SFFieldList outputFieldList;
  EnumSFScope currentFieldScope;
  int pcapSwap;

#ifdef SPOOFSOURCE
  int spoofSource;
  uint16_t ipid;
  struct mySendPacket sendPkt;
  uint32_t packetLen;
#endif

  SFForwardingTarget* forwardingTargets;
  SFForwardingTarget6* forwardingTargets6;

  /* vlan filtering */
  int gotVlanFilter;
#define FILTER_MAX_VLAN 4096
  uint8_t vlanFilter[FILTER_MAX_VLAN + 1];

  /* content stripping */
  int removeContent;

  /* options to restrict IP socket / bind */
  int listen4;
  int listen6;
  int listenControlled;

  /* general options */
  int keepGoing;
  int allowDNS;
};

/* define a separate global we can use to construct the common-log-file format
 */
struct SFCommonLogFormat {
#define SFLFMT_CLF_MAX_LINE 2000
#define SFLFMT_CLF_MAX_CLIENT_LEN 64
  int valid;
  char client[SFLFMT_CLF_MAX_CLIENT_LEN];
  char http_log[SFLFMT_CLF_MAX_LINE];
};

typedef struct _SFSample {
  /* the raw pdu */
  uint8_t* rawSample;
  uint32_t rawSampleLen;
  uint8_t* endp;
  time_t pcapTimestamp;
  time_t readTimestamp;

  /* decode cursor */
  uint32_t* datap;

  /* datagram fields */
  SFLAddress sourceIP;
  SFLAddress agent_addr;
  uint32_t agentSubId;
  uint32_t datagramVersion;
  uint32_t sysUpTime;
  uint32_t sequenceNo;

  /* per-element fields */
  struct {
    uint32_t sampleType;
    uint32_t elementType;
    uint32_t ds_class;
    uint32_t ds_index;

    /* generic interface counter sample */
    SFLIf_counters ifCounters;

    /* data-source stream info */
    uint32_t samplesGenerated;
    uint32_t meanSkipCount;
    uint32_t samplePool;
    uint32_t dropEvents;

    /* the sampled header */
    uint32_t sampledPacketSize;
    uint32_t packet_data_tag;
    uint32_t headerProtocol;
    uint8_t* header;
    uint32_t headerLen;
    uint32_t stripped;

    /* header decode */
    int gotIPV4;
    int gotIPV4Struct;
    int offsetToIPV4;
    int gotIPV6;
    int gotIPV6Struct;
    int offsetToIPV6;
    int offsetToPayload;
    SFLAddress ipsrc;
    SFLAddress ipdst;
    uint32_t dcd_ipProtocol;
    uint32_t dcd_ipTos;
    uint32_t dcd_ipTTL;
    uint32_t dcd_sport;
    uint32_t dcd_dport;
    uint32_t dcd_tcpFlags;
    uint32_t ip_fragmentOffset;
    uint32_t udp_pduLen;

    /* ports */
    uint32_t inputPortFormat;
    uint32_t outputPortFormat;
    uint32_t inputPort;
    uint32_t outputPort;

    /* ethernet */
    uint32_t eth_type;
    uint32_t eth_len;
    uint8_t eth_src[8];
    uint8_t eth_dst[8];

    /* vlan */
    uint32_t in_vlan;
    uint32_t in_priority;
    uint32_t internalPriority;
    uint32_t out_vlan;
    uint32_t out_priority;
    int vlanFilterReject;

    /* extended data fields */
    uint32_t num_extended;
    uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096
#define SASAMPLE_EXTENDED_DATA_NAT_PORT 8192

    /* IP forwarding info */
    SFLAddress nextHop;
    uint32_t srcMask;
    uint32_t dstMask;

    /* BGP info */
    SFLAddress bgp_nextHop;
    uint32_t my_as;
    uint32_t src_as;
    uint32_t src_peer_as;
    uint32_t dst_as_path_len;
    uint32_t* dst_as_path;
    /* note: version 4 dst as path segments just get printed, not stored here,
     * however the dst_peer and dst_as are filled in, since those are used for
     * netflow encoding
     */
    uint32_t dst_peer_as;
    uint32_t dst_as;

    uint32_t communities_len;
    uint32_t* communities;
    uint32_t localpref;

    /* mpls */
    SFLAddress mpls_nextHop;

    /* nat */
    SFLAddress nat_src;
    SFLAddress nat_dst;

    /* counter blocks */
    uint32_t statsSamplingInterval;
    uint32_t counterBlockVersion;
  } s;

  /* exception handler context */
  jmp_buf env;

#define ERROUT stderr

#ifdef DEBUG
#define SFABORT(s, r) abort()
#undef ERROUT
#define ERROUT stdout
#else
#define SFABORT(s, r) longjmp((s)->env, (r))
#endif

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

} SFSample;

/* Cisco netflow version 5 record format */

typedef struct _NFFlow5 {
  uint32_t srcIP;
  uint32_t dstIP;
  uint32_t nextHop;
  uint16_t if_in;
  uint16_t if_out;
  uint32_t frames;
  uint32_t bytes;
  uint32_t firstTime;
  uint32_t lastTime;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t pad1;
  uint8_t tcpFlags;
  uint8_t ipProto;
  uint8_t ipTos;
  uint16_t srcAS;
  uint16_t dstAS;
  uint8_t srcMask; /* No. bits */
  uint8_t dstMask; /* No. bits */
  uint16_t pad2;
} NFFlow5;

typedef struct _NFFlowHdr5 {
  uint16_t version;
  uint16_t count;
  uint32_t sysUpTime;
  uint32_t unixSeconds;
  uint32_t unixNanoSeconds;
  uint32_t flowSequence;
  uint8_t engineType;
  uint8_t engineId;
  uint16_t sampling_interval;
} NFFlowHdr5;

typedef struct _NFFlowPkt5 {
  NFFlowHdr5 hdr;
  NFFlow5
    flow; /* normally an array, but here we always send just 1 at a time */
} NFFlowPkt5;

/* Cisco NetFlow version 9 format */

/* NetFlow v9/ipfix element ids */

#define ID_SRC_IP 8
#define ID_DST_IP 12
#define ID_NEXT_HOP 15
#define ID_IF_IN 10
#define ID_IF_OUT 14
#define ID_PACKETS 2
#define ID_BYTES 1
#define ID_FIRST_SWITCHED 22
#define ID_LAST_SWITCHED 21
#define ID_SRC_PORT 7
#define ID_DST_PORT 11
#define ID_TCP_FLAGS 6
#define ID_PROTOCOL 4
#define ID_TOS 5
#define ID_SRC_AS 16
#define ID_DST_AS 17
#define ID_SRC_MASK 9
#define ID_DST_MASK 13
#define ID_SAMPLING_INTERVAL 34

/* NetFlow v9/ipfix element sizes */

#define SZ_SRC_IP 4
#define SZ_DST_IP 4
#define SZ_NEXT_HOP 4
#define SZ_IF_IN 4
#define SZ_IF_OUT 4
#define SZ_PACKETS 4
#define SZ_BYTES 4
#define SZ_FIRST_SWITCHED 4
#define SZ_LAST_SWITCHED 4
#define SZ_SRC_PORT 2
#define SZ_DST_PORT 2
#define SZ_TCP_FLAGS 1
#define SZ_PROTOCOL 1
#define SZ_TOS 1
#define SZ_SRC_AS 4
#define SZ_DST_AS 4
#define SZ_SRC_MASK 1
#define SZ_DST_MASK 1
#define SZ_SAMPLING_INTERVAL 4

/* NetFlow v9/ipfix element type */

typedef struct _NFField9 {
  uint16_t id;
  uint16_t sz;
} __attribute__((packed)) NFField9;

/* NetFlow v9/ipfix (id, sz) pairs for each element */

/* The NetFlow v9 flow will be shaped similarly to v5,
 * but we move sampling interval from the v5 header into
 * the flow dataset and expand the interface field widths. */

typedef struct _NFFlow9 {
  uint32_t srcIP;
  uint32_t dstIP;
  uint32_t nextHop;
  uint32_t if_in;
  uint32_t if_out;
  uint32_t packets;
  uint32_t bytes;
  uint32_t firstTime;
  uint32_t lastTime;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t tcpFlags;
  uint8_t ipProto;
  uint8_t ipTos;
  uint32_t srcAS;
  uint32_t dstAS;
  uint8_t srcMask;
  uint8_t dstMask;
  uint32_t samplingInterval;
} __attribute__((packed)) NFFlow9;

/* NetFlow v9 template flowset */

typedef struct _NFTemplateFlowSet9 {
  uint16_t setId;
  uint16_t length;
  uint16_t templateId;
  uint16_t fieldCount;
  NFField9 field[19];
} __attribute__((packed)) NFTemplateFlowSet9;

/* NetFlow v9 data flowset */

typedef struct _NFDataFlowSet9 {
  uint16_t templateId;
  uint16_t length;
  NFFlow9 flow;
} __attribute__((packed)) NFDataFlowSet9;

/* NetFlow v9 flow packet header */

typedef struct _NFFlowHeader9 {
  uint16_t version;
  uint16_t count;
  uint32_t sysUpTime;
  uint32_t unixSeconds;
  uint32_t flowSequence;
  uint32_t sourceId;
} __attribute__((packed)) NFFlowHeader9;

/* NetFlow v9 flow packet */

typedef struct _NFFlowPkt9 {
  NFFlowHeader9 hdr;
  NFTemplateFlowSet9 tmpl;
  NFDataFlowSet9 data;
} __attribute__((packed)) NFFlowPkt9;

/* NetFLow packet can be either v5 or v9 */

typedef struct _NFFlowPkt {
  union {
    NFFlowPkt5 v5;
    NFFlowPkt9 v9;
  };
} __attribute__((packed)) NFFlowPkt;

struct encoder {
#define MAX_STRBUF_LEN 2048
  /* just do it in a portable way... */
  static uint32_t MyByteSwap32(uint32_t n);
  static uint16_t MyByteSwap16(uint16_t n);

#ifndef PRIu64
#ifdef _WIN32
#define PRIu64 "I64u"
#else
#define PRIu64 "llu"
#endif
#endif

#define YES 1
#define NO 0

  /* make the options structure global to the program */
  SFConfig sfConfig;

  static const NFField9 nfField9[];
  SFCommonLogFormat sfCLF;

  static const char* SFHTTP_method_names[];

  /* NetFlow functions to send datagrams */
  void sendNetFlowV5Datagram(SFSample* sample);
  void sendNetFlowV9Datagram(SFSample* sample);
  void (*sendNetFlowDatagram)(SFSample* sample);
  void readFlowSample_header(SFSample* sample);
  //  static sample readFlowSample_header(SFSample* sample);

  // static void readFlowSample(SFSample* sample, int expanded);
  void
  readFlowSample(SFSample* sample, int expanded,
                 std::vector<std::shared_ptr<customer_cone::sample>>& samples);
  /*_________________---------------------------__________________
    _________________     heap allocation       __________________
    -----------------___________________________------------------
  */
  static void* my_calloc(size_t bytes);

  void my_free(void* ptr);

  /*_________________---------------------------__________________
    _________________      string buffer        __________________
    -----------------___________________________------------------
    use string buffer scratchpad to avoid snprintf() idiosyncracies
  */

  static void SFStr_init(SFStr* sb);

  static char* SFStr_str(SFStr* sb);

  static int SFStr_len(SFStr* sb);

  static int SFStr_append(SFStr* sb, char* str);

  /* hex printing tends to be one of the performance bottlenecks,
     so take the trouble to optimize it just a little */

  static u_int8_t HexLookupL[513];

  static uint8_t HexLookupU[513];

  static int SFStr_append_hex(SFStr* sb, u_char* hex, int nbytes, int prefix,
                              int upper, char sep);

  static int SFStr_append_array32(SFStr* sb, uint32_t* array32, int n,
                                  int net_byte_order, char sep);

  static int SFStr_append_U32(SFStr* sb, char* fmt, uint32_t val32);

  static int SFStr_append_U64(SFStr* sb, char* fmt, uint64_t val64);

  static int SFStr_append_double(SFStr* sb, char* fmt, double vald);

  static int SFStr_append_mac(SFStr* sb, uint8_t* mac);

  static int SFStr_append_ip(SFStr* sb, uint8_t* ip);

  static int SFStr_append_ip6(SFStr* sb, uint8_t* ip6);

  static int SFStr_append_address(SFStr* sb, SFLAddress* address);

  static int SFStr_append_UUID(SFStr* sb, uint8_t* uuid);

  static int SFStr_append_tag(SFStr* sb, uint32_t tag);

  static int SFStr_append_timestamp(SFStr* sb, time_t ts);

  static int SFStr_append_dataSource(SFStr* sb, uint32_t ds_class,
                                     uint32_t ds_index);

  static int SFStr_copy(SFStr* sb, char* to, int capacity);

  /*_________________---------------------------__________________
    _________________     print functions       __________________
    -----------------___________________________------------------
  */

  static char* printAddress(SFLAddress* address, SFStr* sb);

  static char* printMAC(uint8_t* mac, SFStr* sb);

  static char* printTag(uint32_t tag, SFStr* sb);

  static char* printTimestamp(time_t ts, SFStr* sb);

  static char* printOUI(uint8_t* oui, SFStr* sb);

  static char* printDataSource(uint32_t ds_class, uint32_t ds_index, SFStr* sb);

  static char* printOutputPort_v2v4(uint32_t outputPort, SFStr* sb);

  static char* printInOutPort(uint32_t port, uint32_t format, SFStr* sb);

  /*_________________---------------------------__________________
    _________________      JSON utils           __________________
    -----------------___________________________------------------
  */

  void json_indent();

  void json_start(char* fname, char bracket);

  void json_end(char bracket);

  void json_start_ob(char* fname);

  void json_start_ar(char* fname);

  void json_end_ob();

  void json_end_ar();

  /*_________________---------------------------__________________
    _________________        sf_log             __________________
    -----------------___________________________------------------
  */

  void sf_log_context(SFSample* sample);

  void sf_log(SFSample* sample, char* fmt, ...);

  void sf_logf(SFSample* sample, char* fieldPrefix, char* fieldName, char* val);

  void sf_logf_U32_formatted(SFSample* sample, char* fieldPrefix,
                             char* fieldName, char* fmt, uint32_t val32);

  void sf_logf_U64_formatted(SFSample* sample, char* fieldPrefix,
                             char* fieldName, char* fmt, uint64_t val64);

  void sf_logf_double_formatted(SFSample* sample, char* fieldPrefix,
                                char* fieldName, char* fmt, double vald);

  /* shortcuts for convenience */

  void sf_logf_U32(SFSample* sample, char* fieldName, uint32_t val32);

  void sf_logf_U64(SFSample* sample, char* fieldName, uint64_t val64);

  /*_________________---------------------------__________________
    _________________       URLEncode           __________________
    -----------------___________________________------------------
  */

  static char* URLEncode(char* in, char* out, int outlen);

  /*_________________---------------------------__________________
    _________________    sampleFilterOK         __________________
    -----------------___________________________------------------
  */

  int sampleFilterOK(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    writeFlowLine          __________________
    -----------------___________________________------------------
  */

  void writeFlowLine(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    writeLineCustom        __________________
    -----------------___________________________------------------
  */

  void writeLineCustom(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    clearLineCustom        __________________
    -----------------___________________________------------------
  */

  void clearLineCustom(SFSample* sample, EnumSFScope scope);

  /*_________________---------------------------__________________
    _________________    writeCountersLine      __________________
    -----------------___________________________------------------
  */

  static void writeCountersLine(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    receiveError           __________________
    -----------------___________________________------------------
  */

  static void receiveError(SFSample* sample, char* errm, int hexdump);

  /*_________________---------------------------__________________
    _________________    lengthCheck            __________________
    -----------------___________________________------------------
  */

  static void lengthCheck(SFSample* sample, char* description, uint8_t* start,
                          int len);

  /*_________________---------------------------__________________
    _________________     decodeLinkLayer       __________________
    -----------------___________________________------------------
    store the offset to the start of the ipv4 header in the sequence_number
    field or -1 if not found. Decode the 802.1d if it's there.
  */

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

  void decodeLinkLayer(SFSample* sample);

  /*_________________---------------------------__________________
    _________________       decode80211MAC      __________________
    -----------------___________________________------------------
    store the offset to the start of the ipv4 header in the sequence_number
    field or -1 if not found.
  */

#define WIFI_MIN_HDR_SIZ 24

  void decode80211MAC(SFSample* sample);

  /*_________________---------------------------__________________
    _________________     decodeIPLayer4        __________________
    -----------------___________________________------------------
  */

  void decodeIPLayer4(SFSample* sample, uint8_t* ptr);

  /*_________________---------------------------__________________
    _________________     decodeIPV4            __________________
    -----------------___________________________------------------
  */

  void decodeIPV4(SFSample* sample);

  /*_________________---------------------------__________________
    _________________     decodeIPV6            __________________
    -----------------___________________________------------------
  */

  void decodeIPV6(SFSample* sample);

  /*_________________---------------------------__________________
    _________________   readPcapHeader          __________________
    -----------------___________________________------------------
  */

#define TCPDUMP_MAGIC 0xa1b2c3d4 /* from libpcap-0.5: savefile.c */
#define DLT_EN10MB 1             /* from libpcap-0.5: net/bpf.h */
#define PCAP_VERSION_MAJOR 2     /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4     /* from libpcap-0.5: pcap.h */

  void readPcapHeader();

  /*_________________---------------------------__________________
    _________________   writePcapHeader         __________________
    -----------------___________________________------------------
  */

#define DLT_EN10MB 1         /* from libpcap-0.5: net/bpf.h */
#define DLT_LINUX_SLL 113    /* Linux "cooked" encapsulation */
#define PCAP_VERSION_MAJOR 2 /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4 /* from libpcap-0.5: pcap.h */

  static void writePcapHeader();

  /*_________________---------------------------__________________
    _________________   writePcapPacket         __________________
    -----------------___________________________------------------
  */

  void writePcapPacket(SFSample* sample);

#ifdef SPOOFSOURCE

  /*_________________---------------------------__________________
    _________________      in_checksum          __________________
    -----------------___________________________------------------
  */
  static uint16_t in_checksum(uint16_t* addr, int len) {
    int nleft = len;
    uint16_t* w = addr;
    uint16_t answer;
    int sum = 0;

    while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1)
      sum += *(uint8_t*)w;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
  }

  /*_________________---------------------------__________________
    _________________   openNetFlowSocket_spoof __________________
    -----------------___________________________------------------
  */

  static void openNetFlowSocket_spoof() {
    int on;

    if ((sfConfig.netFlowOutputSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP))
        == -1) {
      fprintf(ERROUT, "netflow output raw socket open failed\n");
      exit(-11);
    }
    on = 1;
    if (setsockopt(sfConfig.netFlowOutputSocket, IPPROTO_IP, IP_HDRINCL,
                   (char*)&on, sizeof(on))
        < 0) {
      fprintf(ERROUT, "setsockopt( IP_HDRINCL ) failed\n");
      exit(-13);
    }
    on = 1;
    if (setsockopt(sfConfig.netFlowOutputSocket, SOL_SOCKET, SO_REUSEADDR,
                   (char*)&on, sizeof(on))
        < 0) {
      fprintf(ERROUT, "setsockopt( SO_REUSEADDR ) failed\n");
      exit(-14);
    }

    memset(&sfConfig.sendPkt, 0, sizeof(sfConfig.sendPkt));
    sfConfig.sendPkt.ip.version_and_headerLen = 0x45;
    sfConfig.sendPkt.ip.protocol = IPPROTO_UDP;
    sfConfig.sendPkt.ip.ttl = 64; /* IPDEFTTL */
    sfConfig.ipid
      = 12000; /* start counting from 12000 (just an arbitrary number) */
    /* sfConfig.ip->frag_off = htons(0x4000); */ /* don't fragment */
    /* can't set the source address yet, but the dest address is known */
    sfConfig.sendPkt.ip.daddr = sfConfig.netFlowOutputIP.address.ip_v4.addr;
    /* can't do the ip_len and checksum until we know the size of the packet */
    sfConfig.sendPkt.udp.uh_dport = htons(sfConfig.netFlowOutputPort);
    /* might as well set the source port to be the same */
    sfConfig.sendPkt.udp.uh_sport = htons(sfConfig.netFlowOutputPort);
    /* can't do the udp_len or udp_checksum until we know the size of the packet
     */
  }

  /*_________________---------------------------__________________
    _________________ sendNetFlowDatagram_spoof __________________
    -----------------___________________________------------------
  */

  static void sendNetFlowDatagram_spoof(SFSample* sample, NFFlowPkt* pkt) {
    /* Grab the netflow version from packet */
    uint16_t version = ntohs(*((uint16_t*)pkt));
    uint16_t packetLen = 0;

    /* Copy data into send packet */
    switch (version) {
      case 5: {
        packetLen = sizeof(NFFlowPkt5) + sizeof(struct myiphdr)
                    + sizeof(struct myudphdr);
        memcpy(sfConfig.sendPkt.data, (char*)pkt, sizeof(NFFlowPkt5));
      } break;
      case 9: {
        packetLen = sizeof(NFFlowPkt9) + sizeof(struct myiphdr)
                    + sizeof(struct myudphdr);
        memcpy(sfConfig.sendPkt.data, (char*)pkt, sizeof(NFFlowPkt9));
      } break;
      default:
        /* unsupported version */
        return;
    }

    /* increment the ip-id */
    sfConfig.sendPkt.ip.id = htons(++sfConfig.ipid);
    /* set the length fields in the ip and udp headers */
    sfConfig.sendPkt.ip.tot_len = htons(packetLen);
    sfConfig.sendPkt.udp.uh_ulen = htons(packetLen - sizeof(struct myiphdr));
    /* set the source address to the source address of the input event */
    sfConfig.sendPkt.ip.saddr = sample->agent_addr.address.ip_v4.addr;
    /* IP header checksum */
    sfConfig.sendPkt.ip.check
      = in_checksum((uint16_t*)&sfConfig.sendPkt.ip, sizeof(struct myiphdr));
    if (sfConfig.sendPkt.ip.check == 0)
      sfConfig.sendPkt.ip.check = 0xffff;
    /* UDP Checksum
       copy out those parts of the IP header that are supposed to be in the UDP
       checksum, and blat them in front of the udp header (after saving what was
       there before). Then compute the udp checksum.  Then patch the saved data
       back again. */
    {
      char* ptr;
      struct udpmagichdr {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
      } h, saved;

      h.src = sfConfig.sendPkt.ip.saddr;
      h.dst = sfConfig.sendPkt.ip.daddr;
      h.zero = 0;
      h.proto = IPPROTO_UDP;
      h.len = sfConfig.sendPkt.udp.uh_ulen;
      /* set the pointer to 12 bytes before the start of the udp header */
      ptr = (char*)&sfConfig.sendPkt.udp;
      ptr -= sizeof(struct udpmagichdr);
      /* save what's there */
      memcpy(&saved, ptr, sizeof(struct udpmagichdr));
      /* blat in the replacement bytes */
      memcpy(ptr, &h, sizeof(struct udpmagichdr));
      /* compute the checksum */
      sfConfig.sendPkt.udp.uh_sum = 0;
      sfConfig.sendPkt.udp.uh_sum
        = in_checksum((uint16_t*)ptr, ntohs(sfConfig.sendPkt.udp.uh_ulen)
                                        + sizeof(struct udpmagichdr));
      if (sfConfig.sendPkt.udp.uh_sum == 0)
        sfConfig.sendPkt.udp.uh_sum = 0xffff;
      /* copy the save bytes back again */
      memcpy(ptr, &saved, sizeof(struct udpmagichdr));

      { /* now send the packet */
        int bytesSent;
        struct sockaddr dest;
        struct sockaddr_in* to = (struct sockaddr_in*)&dest;
        memset(&dest, 0, sizeof(dest));
        to->sin_family = AF_INET;
        to->sin_addr.s_addr = sfConfig.sendPkt.ip.daddr;
        if ((bytesSent = sendto(sfConfig.netFlowOutputSocket, &sfConfig.sendPkt,
                                packetLen, 0, &dest, sizeof(dest)))
            != packetLen) {
          fprintf(ERROUT, "sendto returned %d (expected %d): %s\n", bytesSent,
                  packetLen, strerror(errno));
        }
      }
    }
  }

#endif /* SPOOFSOURCE */

  /*_________________---------------------------__________________
    _________________   openNetFlowSocket       __________________
    -----------------___________________________------------------
  */

  void openNetFlowSocket();

  /*_________________---------------------------__________________
    _________________   sendNetFlowV5Datagram   __________________
    -----------------___________________________------------------
  */

  static int NFFlowSequenceNo;

  /*_________________---------------------------__________________
    _________________   read data fns           __________________
    -----------------___________________________------------------
  */

  static uint32_t getData32_nobswap(SFSample* sample);

  static uint32_t getData32(SFSample* sample);

  static float getFloat(SFSample* sample);

  static uint64_t getData64(SFSample* sample);

  static double getDouble(SFSample* sample);

  static void skipBytes(SFSample* sample, uint32_t skip);

  uint32_t sf_log_next32(SFSample* sample, char* fieldName);

  uint64_t sf_log_next64(SFSample* sample, char* fieldName);

  void sf_log_percentage(SFSample* sample, char* fieldName);

  float sf_log_nextFloat(SFSample* sample, char* fieldName);

  void sf_log_nextMAC(SFSample* sample, char* fieldName);

  static uint32_t getString(SFSample* sample, char* buf, uint32_t bufLen);

  static uint32_t getAddress(SFSample* sample, SFLAddress* address);

  void skipTLVRecord(SFSample* sample, uint32_t tag, uint32_t len,
                     char* description);

  /*_________________---------------------------__________________
    _________________    readExtendedSwitch     __________________
    -----------------___________________________------------------
  */

  void readExtendedSwitch(SFSample* sample);

  // static sample readExtendedSwitch(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedRouter     __________________
    -----------------___________________________------------------
  */

  void readExtendedRouter(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedGateway_v2   __________________
    -----------------___________________________------------------
  */

  void readExtendedGateway_v2(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedGateway      __________________
    -----------------___________________________------------------
  */

  void readExtendedGateway(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedUser       __________________
    -----------------___________________________------------------
  */

  void readExtendedUser(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedUrl        __________________
    -----------------___________________________------------------
  */

  void readExtendedUrl(SFSample* sample);

  /*_________________---------------------------__________________
    _________________       mplsLabelStack      __________________
    -----------------___________________________------------------
  */

  void mplsLabelStack(SFSample* sample, char* fieldName);

  /*_________________---------------------------__________________
    _________________    readExtendedMpls       __________________
    -----------------___________________________------------------
  */

  void readExtendedMpls(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedNat        __________________
    -----------------___________________________------------------
  */

  void readExtendedNat(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedNatPort    __________________
    -----------------___________________________------------------
  */

  void readExtendedNatPort(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedMplsTunnel __________________
    -----------------___________________________------------------
  */

  void readExtendedMplsTunnel(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedMplsVC     __________________
    -----------------___________________________------------------
  */

  void readExtendedMplsVC(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readExtendedMplsFTN    __________________
    -----------------___________________________------------------
  */

  void readExtendedMplsFTN(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedMplsLDP_FEC  __________________
    -----------------___________________________------------------
  */

  void readExtendedMplsLDP_FEC(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedVlanTunnel   __________________
    -----------------___________________________------------------
  */

  void readExtendedVlanTunnel(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedWifiPayload  __________________
    -----------------___________________________------------------
  */

  void readExtendedWifiPayload(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedWifiRx       __________________
    -----------------___________________________------------------
  */

  void readExtendedWifiRx(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedWifiTx       __________________
    -----------------___________________________------------------
  */

  void readExtendedWifiTx(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readExtendedAggregation  __________________
    -----------------___________________________------------------
  */

#if 0 /* commenting this out until its caller is uncommented too */
static void readExtendedAggregation(SFSample *sample)
{
  uint32_t i, num_pdus = getData32(sample);
  sf_logf_U32(sample, "aggregation_num_pdus", num_pdus);
  for(i = 0; i < num_pdus; i++) {
    sf_logf_U32(sample, "aggregation_pdu", i);
    readFlowSample(sample, NO); /* not sure if this the right one here */
  }
}
#endif

  /*_________________---------------------------__________________
    _________________  readFlowSample_ethernet  __________________
    -----------------___________________________------------------
  */

  void readFlowSample_ethernet(SFSample* sample, char* prefix);

  /*_________________---------------------------__________________
    _________________    readFlowSample_IPv4    __________________
    -----------------___________________________------------------
  */

  void readFlowSample_IPv4(SFSample* sample, char* prefix);
  // static sample readFlowSample_IPv4(SFSample* sample, char* prefix);
  /*_________________---------------------------__________________
    _________________    readFlowSample_IPv6    __________________
    -----------------___________________________------------------
  */

  void readFlowSample_IPv6(SFSample* sample, char* prefix);

  /*_________________----------------------------__________________
    _________________  readFlowSample_memcache   __________________
    -----------------____________________________------------------
  */

  void readFlowSample_memcache(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readFlowSample_http       __________________
    -----------------____________________________------------------
  */

  void readFlowSample_http(SFSample* sample, uint32_t tag);

  /*_________________----------------------------__________________
    _________________  readFlowSample_APP        __________________
    -----------------____________________________------------------
  */

  void readFlowSample_APP(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readFlowSample_APP_CTXT   __________________
    -----------------____________________________------------------
  */

  void readFlowSample_APP_CTXT(SFSample* sample);

  /*_________________---------------------------------__________________
    _________________  readFlowSample_APP_ACTOR_INIT  __________________
    -----------------_________________________________------------------
  */

  void readFlowSample_APP_ACTOR_INIT(SFSample* sample);

  /*_________________---------------------------------__________________
    _________________  readFlowSample_APP_ACTOR_TGT   __________________
    -----------------_________________________________------------------
  */

  void readFlowSample_APP_ACTOR_TGT(SFSample* sample);

  /*_________________----------------------------__________________
    _________________   readExtendedSocket4      __________________
    -----------------____________________________------------------
  */

  void readExtendedSocket4(SFSample* sample);

  /*_________________----------------------------__________________
    _________________ readExtendedProxySocket4   __________________
    -----------------____________________________------------------
  */

  void readExtendedProxySocket4(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readExtendedSocket6       __________________
    -----------------____________________________------------------
  */

  void readExtendedSocket6(SFSample* sample);

  /*_________________----------------------------__________________
    _________________ readExtendedProxySocket6   __________________
    -----------------____________________________------------------
  */

  void readExtendedProxySocket6(SFSample* sample);

  /*_________________----------------------------__________________
    _________________    readExtendedDecap       __________________
    -----------------____________________________------------------
  */

  void readExtendedDecap(SFSample* sample, char* prefix);

  /*_________________----------------------------__________________
    _________________    readExtendedVNI         __________________
    -----------------____________________________------------------
  */

  void readExtendedVNI(SFSample* sample, char* prefix);
  /*_________________----------------------------__________________
    _________________    readExtendedTCPInfo     __________________
    -----------------____________________________------------------
  */

  void readExtendedTCPInfo(SFSample* sample);

  /*_________________----------------------------__________________
    _________________    readExtendedEntities    __________________
    -----------------____________________________------------------
  */

  void readExtendedEntities(SFSample* sample);

  /*_________________---------------------------__________________
    _________________    readFlowSample_v2v4    __________________
    -----------------___________________________------------------
  */

  void readFlowSample_v2v4(
    SFSample* sample,
    std::vector<std::shared_ptr<customer_cone::sample>>& samples);

  /*_________________---------------------------__________________
    _________________  readCounters_generic     __________________
    -----------------___________________________------------------
  */

  void readCounters_generic(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_ethernet    __________________
    -----------------___________________________------------------
  */

  void readCounters_ethernet(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_tokenring   __________________
    -----------------___________________________------------------
  */

  void readCounters_tokenring(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_vg          __________________
    -----------------___________________________------------------
  */

  void readCounters_vg(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_vlan        __________________
    -----------------___________________________------------------
  */

  void readCounters_vlan(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_80211       __________________
    -----------------___________________________------------------
  */

  void readCounters_80211(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_processor   __________________
    -----------------___________________________------------------
  */

  void readCounters_processor(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_radio       __________________
    -----------------___________________________------------------
  */

  void readCounters_radio(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_OFPort      __________________
    -----------------___________________________------------------
  */

  void readCounters_OFPort(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_portName    __________________
    -----------------___________________________------------------
  */

  void readCounters_portName(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_OVSDP       __________________
    -----------------___________________________------------------
  */

  void readCounters_OVSDP(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_hid    __________________
    -----------------___________________________------------------
  */

  void readCounters_host_hid(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_adaptors    __________________
    -----------------___________________________------------------
  */

  void readCounters_adaptors(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_host_parent  __________________
    -----------------____________________________------------------
  */

  void readCounters_host_parent(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_cpu    __________________
    -----------------___________________________------------------
  */

  void readCounters_host_cpu(SFSample* sample, uint32_t length);

  /*_________________---------------------------__________________
    _________________  readCounters_host_mem    __________________
    -----------------___________________________------------------
  */

  void readCounters_host_mem(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_dsk    __________________
    -----------------___________________________------------------
  */

  void readCounters_host_dsk(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_nio    __________________
    -----------------___________________________------------------
  */

  void readCounters_host_nio(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_ip     __________________
    -----------------___________________________------------------
  */

  void readCounters_host_ip(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_icmp   __________________
    -----------------___________________________------------------
  */

  void readCounters_host_icmp(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_tcp     __________________
    -----------------___________________________------------------
  */

  void readCounters_host_tcp(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCounters_host_udp    __________________
    -----------------___________________________------------------
  */

  void readCounters_host_udp(SFSample* sample);

  /*_________________-----------------------------__________________
    _________________  readCounters_host_vnode    __________________
    -----------------_____________________________------------------
  */

  void readCounters_host_vnode(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_host_vcpu    __________________
    -----------------____________________________------------------
  */

  void readCounters_host_vcpu(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_host_vmem    __________________
    -----------------____________________________------------------
  */

  void readCounters_host_vmem(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_host_vdsk    __________________
    -----------------____________________________------------------
  */

  void readCounters_host_vdsk(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_host_vnio    __________________
    -----------------____________________________------------------
  */

  void readCounters_host_vnio(SFSample* sample);

  /*_________________------------------------------__________________
    _________________  readCounters_host_gpu_nvml  __________________
    -----------------______________________________------------------
  */

  void readCounters_host_gpu_nvml(SFSample* sample);

  /*_________________------------------------------__________________
    _________________  readCounters_bcm_tables     __________________
    -----------------______________________________------------------
  */

  void readCounters_bcm_tables(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_memcache     __________________
    -----------------____________________________------------------
   for structure 2200 (deprecated)
  */

  void readCounters_memcache(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_memcache2    __________________
    -----------------____________________________------------------
    for structure 2204
  */

  void readCounters_memcache2(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_http         __________________
    -----------------____________________________------------------
  */

  void readCounters_http(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_JVM          __________________
    -----------------____________________________------------------
  */

  void readCounters_JVM(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_JMX          __________________
    -----------------____________________________------------------
  */

  void readCounters_JMX(SFSample* sample, uint32_t length);

  /*_________________----------------------------__________________
    _________________  readCounters_APP          __________________
    -----------------____________________________------------------
  */

  void readCounters_APP(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_APP_RESOURCE __________________
    -----------------____________________________------------------
  */

  void readCounters_APP_RESOURCE(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_APP_WORKERS  __________________
    -----------------____________________________------------------
  */

  void readCounters_APP_WORKERS(SFSample* sample);
  /*_________________----------------------------__________________
    _________________       readCounters_VDI     __________________
    -----------------____________________________------------------
  */

  void readCounters_VDI(SFSample* sample);

  /*_________________------------------------------__________________
    _________________     readCounters_LACP        __________________
    -----------------______________________________------------------
  */

  void readCounters_LACP(SFSample* sample);

  /*_________________----------------------------__________________
    _________________  readCounters_SFP          __________________
    -----------------____________________________------------------
  */

  void sf_logf_SFP(SFSample* sample, char* field, uint32_t lane,
                   uint32_t val32);

  void readCounters_SFP(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  readCountersSample_v2v4  __________________
    -----------------___________________________------------------
  */

  void readCountersSample_v2v4(SFSample* sample);

  /*_________________---------------------------__________________
    _________________   readCountersSample      __________________
    -----------------___________________________------------------
  */

  void readCountersSample(SFSample* sample, int expanded);
  /*_________________---------------------------__________________
    _________________       readRTMetric        __________________
    -----------------___________________________------------------
  */

  void readRTMetric(SFSample* sample);

  /*_________________---------------------------__________________
    _________________       readRTFlow          __________________
    -----------------___________________________------------------
  */

  void readRTFlow(SFSample* sample);

  /*_________________---------------------------__________________
    _________________      readSFlowDatagram    __________________
    -----------------___________________________------------------
  */

  // void readSFlowDatagram(SFSample* sample);
  std::vector<std::shared_ptr<sample>> readSFlowDatagram(SFSample* sample);

  /*_________________---------------------------__________________
    _________________  receiveSFlowDatagram     __________________
    -----------------___________________________------------------
  */

  // void receiveSFlowDatagram(SFSample* sample);
  std::vector<std::shared_ptr<sample>> receiveSFlowDatagram(SFSample* sample);

  /*__________________-----------------------------__________________
     _________________    openInputUDPSocket       __________________
     -----------------_____________________________------------------
  */

  int openInputUDPSocket(uint16_t port);

  /*__________________-----------------------------__________________
     _________________    openInputUDP6Socket      __________________
     -----------------_____________________________------------------
  */

  int openInputUDP6Socket(uint16_t port);

  /*_________________---------------------------__________________
    _________________   ipv4MappedAddress       __________________
    -----------------___________________________------------------
  */

  int ipv4MappedAddress(SFLIPv6* ipv6addr, SFLIPv4* ip4addr);

  /*_________________---------------------------__________________
    _________________       readPacket          __________________
    -----------------___________________________------------------
  */

  void readPacket(int soc);

  /*_________________---------------------------__________________
    _________________     readPcapPacket        __________________
    -----------------___________________________------------------
  */

  /*_________________---------------------------__________________
    _________________     decodeLinkLayer       __________________
    -----------------___________________________------------------
    store the offset to the start of the ipv4 header in the sequence_number
    field or -1 if not found. Decode the 802.1d if it's there.
  */

  int pcapOffsetToSFlow(uint8_t* start, int len);

  // int readPcapPacket(FILE* file);

  caf::optional<std::vector<std::shared_ptr<sample>>>
  readPcapPacket(FILE* file);

  /*_________________---------------------------__________________
    _________________     parseVlanFilter       __________________
    -----------------___________________________------------------
  */

  void peekForNumber(char* p);

  void testVlan(uint32_t num);

  void parseVlanFilter(uint8_t* array, uint8_t flag, char* start);

  /*_________________---------------------------__________________
    _________________    parseFieldList         __________________
    -----------------___________________________------------------
  */

  int parseFields(char* start, char** array);

  //  void parseFieldList(SFFieldList *fieldList, char *start);

  /*________________---------------------------__________________
    ________________       lookupAddress       __________________
    ----------------___________________________------------------
  */

  int parseOrResolveAddress(char* name, struct sockaddr* sa, SFLAddress* addr,
                            int family, int numeric);
  /*_________________---------------------------__________________
    _________________   addForwardingTarget     __________________
    -----------------___________________________------------------
    return boolean for success or failure
  */

  int addForwardingTarget(char* hostandport);
  void parseFieldList(SFFieldList* fieldList, char* start);
  int setNetFlowCollector(char* host);
  std::shared_ptr<customer_cone::sample>
  make_sample(const SFSample* sf_sample) const;
};
} // namespace sflow
} // namespace customer_cone
