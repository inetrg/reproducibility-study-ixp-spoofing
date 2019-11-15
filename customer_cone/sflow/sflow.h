/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon
 * sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

/*
/////////////////////////////////////////////////////////////////////////////////
/////////////////////// sFlow Sampling Packet Data Types
////////////////////////
/////////////////////////////////////////////////////////////////////////////////
*/

#pragma once

typedef struct {
  u_int32_t addr;
} SFLIPv4;

typedef struct {
  u_int8_t addr[16];
} SFLIPv6;

typedef union _SFLAddress_value {
  SFLIPv4 ip_v4;
  SFLIPv6 ip_v6;
} SFLAddress_value;

enum SFLAddress_type {
  SFLADDRESSTYPE_UNDEFINED = 0,
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef struct _SFLAddress {
  u_int32_t type; /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023 = 1,
  SFLHEADER_ISO88024_TOKENBUS = 2,
  SFLHEADER_ISO88025_TOKENRING = 3,
  SFLHEADER_FDDI = 4,
  SFLHEADER_FRAME_RELAY = 5,
  SFLHEADER_X25 = 6,
  SFLHEADER_PPP = 7,
  SFLHEADER_SMDS = 8,
  SFLHEADER_AAL5 = 9,
  SFLHEADER_AAL5_IP = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4 = 11,
  SFLHEADER_IPv6 = 12,
  SFLHEADER_MPLS = 13,
  SFLHEADER_POS = 14,
  SFLHEADER_IEEE80211MAC = 15,
  SFLHEADER_IEEE80211_AMPDU = 16,
  SFLHEADER_IEEE80211_AMSDU_SUBFRAME = 17
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  u_int32_t header_protocol; /* (enum SFLHeader_protocol) */
  u_int32_t frame_length;    /* Original length of packet before sampling */
  u_int32_t stripped;        /* header/trailer bytes stripped by sender */
  u_int32_t header_length;   /* length of sampled header bytes to follow */
  u_int8_t* header_bytes;    /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  u_int32_t eth_len;   /* The length of the MAC packet excluding
                       lower layer encapsulations */
  u_int8_t src_mac[8]; /* 6 bytes + 2 pad */
  u_int8_t dst_mac[8];
  u_int32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  u_int32_t length;    /* The length of the IP packet
                        excluding lower layer encapsulations */
  u_int32_t protocol;  /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv4 src_ip;      /* Source IP Address */
  SFLIPv4 dst_ip;      /* Destination IP Address */
  u_int32_t src_port;  /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;  /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags; /* TCP flags */
  u_int32_t tos;       /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */

typedef struct _SFLSampled_ipv6 {
  u_int32_t length;    /* The length of the IP packet
                        excluding lower layer encapsulations */
  u_int32_t protocol;  /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv6 src_ip;      /* Source IP Address */
  SFLIPv6 dst_ip;      /* Destination IP Address */
  u_int32_t src_port;  /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;  /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags; /* TCP flags */
  u_int32_t priority;  /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  u_int32_t src_vlan;     /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority; /* The 802.1p priority */
  u_int32_t dst_vlan;     /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority; /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop; /* IP address of next hop router */
  u_int32_t src_mask; /* Source address prefix mask bits */
  u_int32_t dst_mask; /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,     /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2 /* Ordered sequence of ASs */
};

typedef struct _SFLExtended_as_path_segment {
  u_int32_t type;   /* enum SFLExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t* set;
    u_int32_t* seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;             /* Address of the border router that should
                                   be used for the destination network */
  u_int32_t as;                   /* AS number for this gateway */
  u_int32_t src_as;               /* AS number of source (origin) */
  u_int32_t src_peer_as;          /* AS number of source peer */
  u_int32_t dst_as_path_segments; /* number of segments in path */
  SFLExtended_as_path_segment* dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t* communities;                   /* set of communities */
  u_int32_t localpref; /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  u_int32_t len;
  char* str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  u_int32_t
    src_charset; /* MIBEnum value of character set used to encode a string - See
                  RFC 2978 Where possible UTF-8 encoding (MIBEnum=106) should be
                  used. A value of zero indicates an unknown encoding. */
  SFLString src_user;
  u_int32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  u_int32_t direction; /* enum SFLExtended_url_direction */
  SFLString url;       /* URL associated with the packet flow.
                        Must be URL encoded */
  SFLString host;      /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  u_int32_t depth;
  u_int32_t*
    stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop; /* Address of the next hop */
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

/* Extended NAT data
   Packet header records report addresses as seen at the sFlowDataSource.
   The extended_nat structure reports on translated source and/or destination
   addesses for this packet. If an address was not translated it should
   be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src; /* Source address */
  SFLAddress dst; /* Destination address */
} SFLExtended_nat;

typedef struct _SFLExtended_nat_port {
  u_int32_t src_port;
  u_int32_t dst_port;
} SFLExtended_nat_port;

/* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
  SFLString tunnel_lsp_name; /* Tunnel name */
  u_int32_t tunnel_id;       /* Tunnel ID */
  u_int32_t tunnel_cos;      /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
  SFLString vc_instance_name; /* VC instance name */
  u_int32_t vll_vc_id;        /* VLL/VC instance ID */
  u_int32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
    - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
  SFLString mplsFTNDescr;
  u_int32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
    - Definition from MPLS-LDP-STD-MIB mplsFecTable
    Note: mplsFecAddrType, mplsFecAddr information available
          from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
  u_int32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information
   Record outer VLAN encapsulations that have
   been stripped. extended_vlantunnel information
   should only be reported if all the following conditions are satisfied:
     1. The packet has nested vlan tags, AND
     2. The reporting device is VLAN aware, AND
     3. One or more VLAN tags have been stripped, either
        because they represent proprietary encapsulations, or
        because switch hardware automatically strips the outer VLAN
        encapsulation.
   Reporting extended_vlantunnel information is not a substitute for
   reporting extended_switch information. extended_switch data must
   always be reported to describe the ingress/egress VLAN information
   for the packet. The extended_vlantunnel information only applies to
   nested VLAN tags, and then only when one or more tags has been
   stripped. */

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel {
  SFLVlanStack stack; /* List of stripped 802.1Q TPID/TCI layers. Each
                       TPID,TCI pair is represented as a single 32 bit
                       integer. Layers listed from outermost to
                       innermost. */
} SFLExtended_vlan_tunnel;

/*
   ////////////////// IEEE 802.11 Extension structs ////////////////////

   The 4-byte cipher_suite identifier follows the format of the cipher suite
   selector value from the 802.11i (TKIP/CCMP amendment to 802.11i)
   The most significant three bytes contain the OUI and the least significant
   byte contains the Suite Type.

   The currently assigned values are:

   OUI        |Suite type  |Meaning
   ----------------------------------------------------
   00-0F-AC   | 0          | Use group cipher suite
   00-0F-AC   | 1          | WEP-40
   00-0F-AC   | 2          | TKIP
   00-0F-AC   | 3          | Reserved
   00-0F-AC   | 4          | CCMP
   00-0F-AC   | 5          | WEP-104
   00-0F-AC   | 6-255      | Reserved
   Vendor OUI | Other      | Vendor specific
   Other      | Any        | Reserved
   ----------------------------------------------------
*/

typedef u_int32_t SFLCipherSuite;

/* Extended wifi Payload
   Used to provide unencrypted version of 802.11 MAC data. If the
   MAC data is not encrypted then the agent must not include an
   extended_wifi_payload structure.
   If 802.11 MAC data is encrypted then the sampled_header structure
   should only contain the MAC header (since encrypted data cannot
   be decoded by the sFlow receiver). If the sFlow agent has access to
   the unencrypted payload, it should add an extended_wifi_payload
   structure containing the unencrypted data bytes from the sampled
   packet header, starting at the beginning of the 802.2 LLC and not
   including any trailing encryption footers.  */
/* opaque = flow_data; enterprise = 0; format = 1013 */

typedef struct _SFLExtended_wifi_payload {
  SFLCipherSuite cipherSuite;
  SFLSampled_header header;
} SFLExtended_wifi_payload;

typedef enum {
  IEEE80211_A = 1,
  IEEE80211_B = 2,
  IEEE80211_G = 3,
  IEEE80211_N = 4,
} SFL_IEEE80211_version;

/* opaque = flow_data; enterprise = 0; format = 1014 */

#define SFL_MAX_SSID_LEN 256

typedef struct _SFLExtended_wifi_rx {
  u_int32_t ssid_len;
  char* ssid;
  char bssid[6];                 /* BSSID */
  SFL_IEEE80211_version version; /* version */
  u_int32_t channel;             /* channel number */
  u_int64_t speed;
  u_int32_t rsni; /* received signal to noise ratio, see dot11FrameRprtRSNI */
  u_int32_t rcpi; /* received channel power, see dot11FrameRprtLastRCPI */
  u_int32_t packet_duration_us; /* amount of time that the successfully received
                                   pkt occupied RF medium.*/
} SFLExtended_wifi_rx;

/* opaque = flow_data; enterprise = 0; format = 1015 */

typedef struct _SFLExtended_wifi_tx {
  u_int32_t ssid_len;
  char* ssid;                    /* SSID string */
  char bssid[6];                 /* BSSID */
  SFL_IEEE80211_version version; /* version */
  u_int32_t transmissions;       /* number of transmissions for sampled
                                  packet.
                                  0 = unkown
                                  1 = packet was successfully transmitted
                                  on first attempt
                                  n > 1 = n - 1 retransmissions */
  u_int32_t packet_duration_us;  /* amount of time that the successfully
                                  transmitted packet occupied the
                                  RF medium */
  u_int32_t retrans_duration_us; /* amount of time that failed transmission
                                  attempts occupied the RF medium */
  u_int32_t channel;             /* channel number */
  u_int64_t speed;
  u_int32_t power_mw; /* transmit power in mW. */
} SFLExtended_wifi_tx;

/* Extended 802.11 Aggregation Data */
/* A flow_sample of an aggregated frame would consist of a packet
   header for the whole frame + any other extended structures that
   apply (e.g. 80211_tx/rx etc.) + an extended_wifi_aggregation
   structure which would contain an array of pdu structures (one
   for each PDU in the aggregate). A pdu is simply an array of
   flow records, in the simplest case a packet header for each PDU,
   but extended structures could be included as well. */

/* opaque = flow_data; enterprise = 0; format = 1016 */

struct _SFLFlow_Pdu; /* forward decl */

typedef struct _SFLExtended_aggregation {
  u_int32_t num_pdus;
  struct _SFFlow_Pdu* pdus;
} SFLExtended_aggregation;
/* TCP connection state */
/* Based on struct tcp_info in /usr/include/linux/tcp.h */
/* opaque = flow_data; enterprise=0; format=2209 */

typedef enum {
  PKTDIR_unknown = 0,
  PKTDIR_received = 1,
  PKTDIR_sent = 2
} EnumPktDirection;

typedef struct _SFLExtended_TCP_info {
  u_int32_t dirn;       /* EnumPktDirection: Sampled packet direction */
  u_int32_t snd_mss;    /* Cached effective mss, not including SACKS */
  u_int32_t rcv_mss;    /* Max. recv. segment size */
  u_int32_t unacked;    /* Packets which are "in flight" */
  u_int32_t lost;       /* Lost packets */
  u_int32_t retrans;    /* Retransmitted packets */
  u_int32_t pmtu;       /* Last pmtu seen by socket */
  u_int32_t rtt;        /* smoothed RTT (microseconds) */
  u_int32_t rttvar;     /* RTT variance (microseconds) */
  u_int32_t snd_cwnd;   /* Sending congestion window */
  u_int32_t reordering; /* Reordering */
  u_int32_t min_rtt;    /* Minimum RTT (microseconds) */
} SFLExtended_TCP_info;

#define XDRSIZ_SFLEXTENDED_TCP_INFO 48

/* Physical or virtual host description
   opaque = flow_data; enterprise = 0; format = 2210
   Set Data source to all zeroes if unknown  */
typedef struct _SFLExtended_entities {
  u_int32_t src_dsClass; /* Data Source associated with packet source */
  u_int32_t src_dsIndex;
  u_int32_t dst_dsClass; /* Data Source associated with packet destination */
  u_int32_t dst_dsIndex;
} SFLExtended_entities;

#define XDRSIZ_SFLEXTENDED_ENTITIES 16

/* Extended socket information,
   Must be filled in for all application transactions associated with a network
   socket Omit if transaction associated with non-network IPC  */

/* IPv4 Socket */
/* opaque = flow_data; enterprise = 0; format = 2100 */
typedef struct _SFLExtended_socket_ipv4 {
  u_int32_t protocol;    /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv4 local_ip;      /* local IP address */
  SFLIPv4 remote_ip;     /* remote IP address */
  u_int32_t local_port;  /* TCP/UDP local port number or equivalent */
  u_int32_t remote_port; /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv4;

#define XDRSIZ_SFLEXTENDED_SOCKET4 20

/* IPv6 Socket */
/* opaque = flow_data; enterprise = 0; format = 2101 */
typedef struct _SFLExtended_socket_ipv6 {
  u_int32_t protocol;    /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv6 local_ip;      /* local IP address */
  SFLIPv6 remote_ip;     /* remote IP address */
  u_int32_t local_port;  /* TCP/UDP local port number or equivalent */
  u_int32_t remote_port; /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv6;

#define XDRSIZ_SFLEXTENDED_SOCKET6 44

typedef enum {
  MEMCACHE_PROT_OTHER = 0,
  MEMCACHE_PROT_ASCII = 1,
  MEMCACHE_PROT_BINARY = 2
} SFLMemcache_prot;

typedef enum {
  MEMCACHE_CMD_OTHER = 0,
  MEMCACHE_CMD_SET = 1,
  MEMCACHE_CMD_ADD = 2,
  MEMCACHE_CMD_REPLACE = 3,
  MEMCACHE_CMD_APPEND = 4,
  MEMCACHE_CMD_PREPEND = 5,
  MEMCACHE_CMD_CAS = 6,
  MEMCACHE_CMD_GET = 7,
  MEMCACHE_CMD_GETS = 8,
  MEMCACHE_CMD_INCR = 9,
  MEMCACHE_CMD_DECR = 10,
  MEMCACHE_CMD_DELETE = 11,
  MEMCACHE_CMD_STATS = 12,
  MEMCACHE_CMD_FLUSH = 13,
  MEMCACHE_CMD_VERSION = 14,
  MEMCACHE_CMD_QUIT = 15,
  MEMCACHE_CMD_TOUCH = 16
} SFLMemcache_cmd;

enum SFLMemcache_operation_status {
  MEMCACHE_OP_UNKNOWN = 0,
  MEMCACHE_OP_OK = 1,
  MEMCACHE_OP_ERROR = 2,
  MEMCACHE_OP_CLIENT_ERROR = 3,
  MEMCACHE_OP_SERVER_ERROR = 4,
  MEMCACHE_OP_STORED = 5,
  MEMCACHE_OP_NOT_STORED = 6,
  MEMCACHE_OP_EXISTS = 7,
  MEMCACHE_OP_NOT_FOUND = 8,
  MEMCACHE_OP_DELETED = 9
};

#define SFL_MAX_MEMCACHE_KEY 255

typedef struct _SFLSampled_memcache {
  u_int32_t protocol; /* SFLMemcache_prot */
  u_int32_t command;  /* SFLMemcache_cmd */
  SFLString key;      /* up to 255 chars */
  u_int32_t nkeys;
  u_int32_t value_bytes;
  u_int32_t duration_uS;
  u_int32_t status; /* SFLMemcache_operation_status */
} SFLSampled_memcache;

typedef enum {
  SFHTTP_OTHER = 0,
  SFHTTP_OPTIONS = 1,
  SFHTTP_GET = 2,
  SFHTTP_HEAD = 3,
  SFHTTP_POST = 4,
  SFHTTP_PUT = 5,
  SFHTTP_DELETE = 6,
  SFHTTP_TRACE = 7,
  SFHTTP_CONNECT = 8
} SFLHTTP_method;

#define SFL_MAX_HTTP_URI 255
#define SFL_MAX_HTTP_HOST 64
#define SFL_MAX_HTTP_REFERRER 255
#define SFL_MAX_HTTP_USERAGENT 128
#define SFL_MAX_HTTP_XFF 64
#define SFL_MAX_HTTP_AUTHUSER 32
#define SFL_MAX_HTTP_MIMETYPE 64

typedef struct _SFLSampled_http {
  SFLHTTP_method method;
  u_int32_t protocol; /* 1.1=1001 */
  SFLString uri;  /* URI exactly as it came from the client (up to 255 bytes) */
  SFLString host; /* Host value from request header (<= 64 bytes) */
  SFLString referrer;  /* Referer value from request header (<=255 bytes) */
  SFLString useragent; /* User-Agent value from request header (<= 128 bytes)*/
  SFLString xff; /* X-Forwarded-For value from request header (<= 64 bytes)*/
  SFLString authuser;   /* RFC 1413 identity of user (<=32 bytes)*/
  SFLString mimetype;   /* Mime-Type (<=64 bytes) */
  u_int64_t req_bytes;  /* Content-Length of request */
  u_int64_t resp_bytes; /* Content-Length of response */
  u_int32_t uS;         /* duration of the operation (microseconds) */
  u_int32_t status;     /* HTTP status code */
} SFLSampled_http;

typedef enum {
  SFLAPP_SUCCESS = 0,
  SFLAPP_OTHER = 1,
  SFLAPP_TIMEOUT = 2,
  SFLAPP_INTERNAL_ERROR = 3,
  SFLAPP_BAD_REQUEST = 4,
  SFLAPP_FORBIDDEN = 5,
  SFLAPP_TOO_LARGE = 6,
  SFLAPP_NOT_IMPLEMENTED = 7,
  SFLAPP_NOT_FOUND = 8,
  SFLAPP_UNAVAILABLE = 9,
  SFLAPP_UNAUTHORIZED = 10,
  SFLAPP_NUM_STATUS_CODES
} EnumSFLAPPStatus;

static const char* SFL_APP_STATUS_names[]
  = {"SUCCESS",     "OTHER",       "TIMEOUT",    "INTERNAL_ERROR",
     "BAD_REQUEST", "FORBIDDEN",   "TOO_LARGE",  "NOT_IMPLEMENTED",
     "NOT_FOUND",   "UNAVAILABLE", "UNATHORIZED"};

/* Operation context */
typedef struct {
  SFLString application;
  SFLString operation;  /* type of operation (e.g. authorization, payment) */
  SFLString attributes; /* specific attributes associated operation */
} SFLSampled_APP_CTXT;

#define SFLAPP_MAX_APPLICATION_LEN 32
#define SFLAPP_MAX_OPERATION_LEN 32
#define SFLAPP_MAX_ATTRIBUTES_LEN 255

/* Sampled Enterprise Operation */
/* opaque = flow_data; enterprise = 0; format = 2202 */
typedef struct {
  SFLSampled_APP_CTXT context; /* attributes describing the operation */
  SFLString status_descr;  /* additional text describing status (e.g. "unknown
                              client") */
  u_int64_t req_bytes;     /* size of request body (exclude headers) */
  u_int64_t resp_bytes;    /* size of response body (exclude headers) */
  u_int32_t duration_uS;   /* duration of the operation (microseconds) */
  EnumSFLAPPStatus status; /* status code */
} SFLSampled_APP;

#define SFLAPP_MAX_STATUS_LEN 32

typedef struct {
  SFLString actor;
} SFLSampled_APP_ACTOR;

#define SFLAPP_MAX_ACTOR_LEN 64

typedef struct _SFLExtended_vni {
  u_int32_t vni; /* virtual network identifier */
} SFLExtended_vni;

typedef struct _SFLExtended_decap {
  u_int32_t innerHeaderOffset;
} SFLExtended_decap;

enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER = 1,            /* Packet headers are sampled */
  SFLFLOW_ETHERNET = 2,          /* MAC layer information */
  SFLFLOW_IPV4 = 3,              /* IP version 4 data */
  SFLFLOW_IPV6 = 4,              /* IP version 6 data */
  SFLFLOW_EX_SWITCH = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY = 1003,     /* Extended gateway router information */
  SFLFLOW_EX_USER = 1004,        /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL = 1005,         /* Extended URL information */
  SFLFLOW_EX_MPLS = 1006,        /* Extended MPLS information */
  SFLFLOW_EX_NAT = 1007,         /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL = 1008, /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC = 1009,
  SFLFLOW_EX_MPLS_FTN = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL = 1012, /* VLAN stack */
  SFLFLOW_EX_80211_PAYLOAD = 1013,
  SFLFLOW_EX_80211_RX = 1014,
  SFLFLOW_EX_80211_TX = 1015,
  SFLFLOW_EX_AGGREGATION = 1016,
  SFLFLOW_EX_NAT_PORT = 1020,      /* Extended NAT port information */
  SFLFLOW_EX_L2_TUNNEL_OUT = 1021, /* http://sflow.org/sflow_tunnels.txt */
  SFLFLOW_EX_L2_TUNNEL_IN = 1022,
  SFLFLOW_EX_IPV4_TUNNEL_OUT = 1023,
  SFLFLOW_EX_IPV4_TUNNEL_IN = 1024,
  SFLFLOW_EX_IPV6_TUNNEL_OUT = 1025,
  SFLFLOW_EX_IPV6_TUNNEL_IN = 1026,
  SFLFLOW_EX_DECAP_OUT = 1027,
  SFLFLOW_EX_DECAP_IN = 1028,
  SFLFLOW_EX_VNI_OUT = 1029,
  SFLFLOW_EX_VNI_IN = 1030,
  SFLFLOW_EX_SOCKET4 = 2100,
  SFLFLOW_EX_SOCKET6 = 2101,
  SFLFLOW_EX_PROXYSOCKET4 = 2102,
  SFLFLOW_EX_PROXYSOCKET6 = 2103,
  SFLFLOW_MEMCACHE = 2200,
  SFLFLOW_HTTP = 2201,
  SFLFLOW_APP = 2202,            /* transaction sample */
  SFLFLOW_APP_CTXT = 2203,       /* enclosing server context */
  SFLFLOW_APP_ACTOR_INIT = 2204, /* initiator */
  SFLFLOW_APP_ACTOR_TGT = 2205,  /* target */
  SFLFLOW_HTTP2 = 2206,
  SFLFLOW_EX_TCP_INFO = 2209,
  SFLFLOW_EX_ENTITIES = 2210,
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
  SFLSampled_ipv6 ipv6;
  SFLSampled_memcache memcache;
  SFLSampled_http http;
  SFLSampled_APP app;
  SFLSampled_APP_CTXT appCtxt;
  SFLSampled_APP_ACTOR appActor;
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_nat_port nat_port;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
  SFLExtended_wifi_payload wifi_payload;
  SFLExtended_wifi_rx wifi_rx;
  SFLExtended_wifi_tx wifi_tx;
  SFLExtended_aggregation aggregation;
  SFLExtended_socket_ipv4 socket4;
  SFLExtended_socket_ipv6 socket6;
  SFLExtended_vni tunnel_vni;
  SFLExtended_decap tunnel_decap;
  SFLExtended_TCP_info tcp_info;
  SFLExtended_entities entities;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element* nxt;
  u_int32_t tag; /* SFLFlow_type_tag */
  u_int32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4, /* enterprise = 0 : format = 4 */
  SFLRTMETRIC = ((4300 << 12) + 1002),
  SFLRTFLOW = ((4300 << 12) + 1003)
};

typedef struct _SFLFlow_Pdu {
  struct _SFLFlow_Pdu* nxt;
  u_int32_t num_elements;
  SFLFlow_sample_element* elements;
} SFLFlow_Pdu;

/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* u_int32_t tag;    */ /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number; /* Incremented with each flow sample
                              generated */
  u_int32_t source_id;       /* fsSourceId */
  u_int32_t sampling_rate;   /* fsPacketSamplingRate */
  u_int32_t sample_pool;     /* Total number of packets that could have been
                              sampled (i.e. packets skipped by sampling
                              process + total number of samples) */
  u_int32_t drops;           /* Number of times a packet was dropped due to
                              lack of resources */
  u_int32_t input;           /* SNMP ifIndex of input interface.
                              0 if interface is not known. */
  u_int32_t output;          /* SNMP ifIndex of output interface,
                              0 if interface is not known.
                              Set most significant bit to indicate
                              multiple destination interfaces
                              (i.e. in case of broadcast or multicast)
                              and set lower order bits to indicate
                              number of destination interfaces.
                              Examples:
                              0x00000002  indicates ifIndex = 2
                              0x00000000  ifIndex unknown.
                              0x80000007  indicates a packet sent
                              to 7 interfaces.
                              0x80000000  indicates a packet sent to
                              an unknown number of
                              interfaces greater than 1.*/
  u_int32_t num_elements;
  SFLFlow_sample_element* elements;
} SFLFlow_sample;

/* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* u_int32_t tag;    */ /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number; /* Incremented with each flow sample
                              generated */
  u_int32_t ds_class;        /* EXPANDED */
  u_int32_t ds_index;        /* EXPANDED */
  u_int32_t sampling_rate;   /* fsPacketSamplingRate */
  u_int32_t sample_pool;     /* Total number of packets that could have been
                              sampled (i.e. packets skipped by sampling
                              process + total number of samples) */
  u_int32_t drops;           /* Number of times a packet was dropped due to
                              lack of resources */
  u_int32_t inputFormat;     /* EXPANDED */
  u_int32_t input;           /* SNMP ifIndex of input interface.
                              0 if interface is not known. */
  u_int32_t outputFormat;    /* EXPANDED */
  u_int32_t output;          /* SNMP ifIndex of output interface,
                              0 if interface is not known. */
  u_int32_t num_elements;
  SFLFlow_sample_element* elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection; /* Derived from MAU MIB (RFC 2668)
                          0 = unknown, 1 = full-duplex,
                          2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;    /* bit field with the following bits assigned:
                          bit 0 = ifAdminStatus (0 = down, 1 = up)
                          bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} SFLVlan_counters;

typedef struct _SFLWifi_counters {
  u_int32_t dot11TransmittedFragmentCount;
  u_int32_t dot11MulticastTransmittedFrameCount;
  u_int32_t dot11FailedCount;
  u_int32_t dot11RetryCount;
  u_int32_t dot11MultipleRetryCount;
  u_int32_t dot11FrameDuplicateCount;
  u_int32_t dot11RTSSuccessCount;
  u_int32_t dot11RTSFailureCount;
  u_int32_t dot11ACKFailureCount;
  u_int32_t dot11ReceivedFragmentCount;
  u_int32_t dot11MulticastReceivedFrameCount;
  u_int32_t dot11FCSErrorCount;
  u_int32_t dot11TransmittedFrameCount;
  u_int32_t dot11WEPUndecryptableCount;
  u_int32_t dot11QoSDiscardedFragmentCount;
  u_int32_t dot11AssociatedStationCount;
  u_int32_t dot11QoSCFPollsReceivedCount;
  u_int32_t dot11QoSCFPollsUnusedCount;
  u_int32_t dot11QoSCFPollsUnusableCount;
  u_int32_t dot11QoSCFPollsLostCount;
} SFLWifi_counters;

/* Processor Information */
/* opaque = counter_data; enterprise = 0; format = 1001 */

typedef struct _SFLProcessor_counters {
  u_int32_t five_sec_cpu; /* 5 second average CPU utilization */
  u_int32_t one_min_cpu;  /* 1 minute average CPU utilization */
  u_int32_t five_min_cpu; /* 5 minute average CPU utilization */
  u_int64_t total_memory; /* total memory (in bytes) */
  u_int64_t free_memory;  /* free memory (in bytes) */
} SFLProcessor_counters;

typedef struct _SFLRadio_counters {
  u_int32_t elapsed_time;         /* elapsed time in ms */
  u_int32_t on_channel_time;      /* time in ms spent on channel */
  u_int32_t on_channel_busy_time; /* time in ms spent on channel and busy */
} SFLRadio_counters;

/* host sflow */

enum SFLMachine_type {
  SFLMT_unknown = 0,
  SFLMT_other = 1,
  SFLMT_x86 = 2,
  SFLMT_x86_64 = 3,
  SFLMT_ia64 = 4,
  SFLMT_sparc = 5,
  SFLMT_alpha = 6,
  SFLMT_powerpc = 7,
  SFLMT_m68k = 8,
  SFLMT_mips = 9,
  SFLMT_arm = 10,
  SFLMT_hppa = 11,
  SFLMT_s390 = 12
};

enum SFLOS_name {
  SFLOS_unknown = 0,
  SFLOS_other = 1,
  SFLOS_linux = 2,
  SFLOS_windows = 3,
  SFLOS_darwin = 4,
  SFLOS_hpux = 5,
  SFLOS_aix = 6,
  SFLOS_dragonfly = 7,
  SFLOS_freebsd = 8,
  SFLOS_netbsd = 9,
  SFLOS_openbsd = 10,
  SFLOS_osf = 11,
  SFLOS_solaris = 12
};

typedef struct _SFLMacAddress {
  u_int8_t mac[8];
} SFLMacAddress;

typedef struct _SFLAdaptor {
  u_int32_t ifIndex;
  u_int32_t num_macs;
  SFLMacAddress macs[1];
} SFLAdaptor;

typedef struct _SFLAdaptorList {
  u_int32_t capacity;
  u_int32_t num_adaptors;
  SFLAdaptor** adaptors;
} SFLAdaptorList;

typedef struct _SFLHost_parent {
  u_int32_t dsClass; /* sFlowDataSource class */
  u_int32_t dsIndex; /* sFlowDataSource index */
} SFLHost_parent;

#define SFL_MAX_HOSTNAME_LEN 64
#define SFL_MAX_OSRELEASE_LEN 32

typedef struct _SFLHostId {
  SFLString hostname;
  u_int8_t uuid[16];
  u_int32_t machine_type; /* enum SFLMachine_type */
  u_int32_t os_name;      /* enum SFLOS_name */
  SFLString os_release;   /* max len 32 bytes */
} SFLHostId;

typedef struct _SFLHost_nio_counters {
  u_int64_t bytes_in;
  u_int32_t pkts_in;
  u_int32_t errs_in;
  u_int32_t drops_in;
  u_int64_t bytes_out;
  u_int32_t pkts_out;
  u_int32_t errs_out;
  u_int32_t drops_out;
} SFLHost_nio_counters;

typedef struct _SFLHost_cpu_counters {
  float load_one;       /* 1 minute load avg. */
  float load_five;      /* 5 minute load avg. */
  float load_fifteen;   /* 15 minute load avg. */
  u_int32_t proc_run;   /* running threads */
  u_int32_t proc_total; /* total threads */
  u_int32_t cpu_num;    /* # CPU cores */
  u_int32_t cpu_speed;  /* speed in MHz of CPU */
  u_int32_t uptime;     /* seconds since last reboot */
  u_int32_t cpu_user;   /* time executing in user mode processes (ms) */
  u_int32_t cpu_nice;   /* time executing niced processs (ms) */
  u_int32_t cpu_system; /* time executing kernel mode processes (ms) */
  u_int32_t cpu_idle;   /* idle time (ms) */
  u_int32_t cpu_wio;    /* time waiting for I/O to complete (ms) */
  u_int32_t cpu_intr;   /* time servicing interrupts (ms) */
  u_int32_t cpu_sintr;  /* time servicing softirqs (ms) */
  u_int32_t interrupts; /* interrupt count */
  u_int32_t contexts;   /* context switch count */
  u_int32_t cpu_steal; /* time spent in other OS instances (virtual env) (ms) */
  u_int32_t cpu_guest; /* time spent running vcpu for guest OS */
  u_int32_t cpu_guest_nice; /* time spent running vcpu for "niced" guest OS */
} SFLHost_cpu_counters;

typedef struct _SFLHost_mem_counters {
  u_int64_t mem_total;   /* total bytes */
  u_int64_t mem_free;    /* free bytes */
  u_int64_t mem_shared;  /* shared bytes */
  u_int64_t mem_buffers; /* buffers bytes */
  u_int64_t mem_cached;  /* cached bytes */
  u_int64_t swap_total;  /* swap total bytes */
  u_int64_t swap_free;   /* swap free bytes */
  u_int32_t page_in;     /* page in count */
  u_int32_t page_out;    /* page out count */
  u_int32_t swap_in;     /* swap in count */
  u_int32_t swap_out;    /* swap out count */
} SFLHost_mem_counters;

typedef struct _SFLHost_dsk_counters {
  u_int64_t disk_total;
  u_int64_t disk_free;
  u_int32_t part_max_used; /* as percent * 100, so 100==1% */
  u_int32_t reads;         /* reads issued */
  u_int64_t bytes_read;    /* bytes read */
  u_int32_t read_time;     /* read time (ms) */
  u_int32_t writes;        /* writes completed */
  u_int64_t bytes_written; /* bytes written */
  u_int32_t write_time;    /* write time (ms) */
} SFLHost_dsk_counters;

/* Virtual Node Statistics */
/* opaque = counter_data; enterprise = 0; format = 2100 */

typedef struct _SFLHost_vrt_node_counters {
  u_int32_t mhz;         /* expected CPU frequency */
  u_int32_t cpus;        /* the number of active CPUs */
  u_int64_t memory;      /* memory size in bytes */
  u_int64_t memory_free; /* unassigned memory in bytes */
  u_int32_t num_domains; /* number of active domains */
} SFLHost_vrt_node_counters;

/* Virtual Domain Statistics */
/* opaque = counter_data; enterprise = 0; format = 2101 */

/* virDomainState imported from libvirt.h */
enum SFLVirDomainState {
  SFL_VIR_DOMAIN_NOSTATE = 0,  /* no state */
  SFL_VIR_DOMAIN_RUNNING = 1,  /* the domain is running */
  SFL_VIR_DOMAIN_BLOCKED = 2,  /* the domain is blocked on resource */
  SFL_VIR_DOMAIN_PAUSED = 3,   /* the domain is paused by user */
  SFL_VIR_DOMAIN_SHUTDOWN = 4, /* the domain is being shut down */
  SFL_VIR_DOMAIN_SHUTOFF = 5,  /* the domain is shut off */
  SFL_VIR_DOMAIN_CRASHED = 6   /* the domain is crashed */
};

typedef struct _SFLHost_vrt_cpu_counters {
  u_int32_t state;    /* virtDomainState */
  u_int32_t cpuTime;  /* the CPU time used in mS */
  u_int32_t cpuCount; /* number of virtual CPUs for the domain */
} SFLHost_vrt_cpu_counters;

/* Virtual Domain Memory statistics */
/* opaque = counter_data; enterprise = 0; format = 2102 */

typedef struct _SFLHost_vrt_mem_counters {
  u_int64_t memory;    /* memory in bytes used by domain */
  u_int64_t maxMemory; /* memory in bytes allowed */
} SFLHost_vrt_mem_counters;

/* Virtual Domain Disk statistics */
/* opaque = counter_data; enterprise = 0; format = 2103 */

typedef struct _SFLHost_vrt_dsk_counters {
  u_int64_t capacity;   /* logical size in bytes */
  u_int64_t allocation; /* current allocation in bytes */
  u_int64_t available;  /* remaining free bytes */
  u_int32_t rd_req;     /* number of read requests */
  u_int64_t rd_bytes;   /* number of read bytes */
  u_int32_t wr_req;     /* number of write requests */
  u_int64_t wr_bytes;   /* number of  written bytes */
  u_int32_t errs;       /* read/write errors */
} SFLHost_vrt_dsk_counters;

/* Virtual Domain Network statistics */
/* opaque = counter_data; enterprise = 0; format = 2104 */

typedef struct _SFLHost_vrt_nio_counters {
  u_int64_t bytes_in;
  u_int32_t pkts_in;
  u_int32_t errs_in;
  u_int32_t drops_in;
  u_int64_t bytes_out;
  u_int32_t pkts_out;
  u_int32_t errs_out;
  u_int32_t drops_out;
} SFLHost_vrt_nio_counters;

/* NVML statistics */
/* opaque = counter_data; enterprise = 5703, format=1 */
typedef struct _SFLHost_gpu_nvml {
  u_int32_t device_count; /* see nvmlGetDeviceCount */
  u_int32_t processes;    /* see nvmlDeviceGetComputeRunningProcesses */
  u_int32_t gpu_time;     /* total milliseconds in which one or more kernels was
                             executing on GPU */
  u_int32_t mem_time;   /* total milliseconds during which global device memory
                           was being read/written */
  u_int64_t mem_total;  /* bytes. see nvmlDeviceGetMemoryInfo */
  u_int64_t mem_free;   /* bytes. see nvmlDeviceGetMemoryInfo */
  u_int32_t ecc_errors; /* see nvmlDeviceGetTotalEccErrors */
  u_int32_t energy;     /* mJ. see nvmlDeviceGetPowerUsage */
  u_int32_t
    temperature; /* C. maximum across devices - see nvmlDeviceGetTemperature */
  u_int32_t
    fan_speed; /* %. maximum across devices - see nvmlDeviceGetFanSpeed */
} SFLHost_gpu_nvml;

/* Broadcom switch ASIC table utilizations */
/* opaque = counter_data; enterprise = 4413 (Broadcom); format = 3 */
typedef struct {
  u_int32_t bcm_host_entries;
  u_int32_t bcm_host_entries_max;
  u_int32_t bcm_ipv4_entries;
  u_int32_t bcm_ipv4_entries_max;
  u_int32_t bcm_ipv6_entries;
  u_int32_t bcm_ipv6_entries_max;
  u_int32_t bcm_ipv4_ipv6_entries;
  u_int32_t bcm_ipv4_ipv6_entries_max;
  u_int32_t bcm_long_ipv6_entries;
  u_int32_t bcm_long_ipv6_entries_max;
  u_int32_t bcm_total_routes;
  u_int32_t bcm_total_routes_max;
  u_int32_t bcm_ecmp_nexthops;
  u_int32_t bcm_ecmp_nexthops_max;
  u_int32_t bcm_mac_entries;
  u_int32_t bcm_mac_entries_max;
  u_int32_t bcm_ipv4_neighbors;
  u_int32_t bcm_ipv6_neighbors;
  u_int32_t bcm_ipv4_routes;
  u_int32_t bcm_ipv6_routes;
  u_int32_t bcm_acl_ingress_entries;
  u_int32_t bcm_acl_ingress_entries_max;
  u_int32_t bcm_acl_ingress_counters;
  u_int32_t bcm_acl_ingress_counters_max;
  u_int32_t bcm_acl_ingress_meters;
  u_int32_t bcm_acl_ingress_meters_max;
  u_int32_t bcm_acl_ingress_slices;
  u_int32_t bcm_acl_ingress_slices_max;
  u_int32_t bcm_acl_egress_entries;
  u_int32_t bcm_acl_egress_entries_max;
  u_int32_t bcm_acl_egress_counters;
  u_int32_t bcm_acl_egress_counters_max;
  u_int32_t bcm_acl_egress_meters;
  u_int32_t bcm_acl_egress_meters_max;
  u_int32_t bcm_acl_egress_slices;
  u_int32_t bcm_acl_egress_slices_max;
} SFLBCM_tables;

///////////// TCP/UDP/ICMP from MIB-II ///////////////////////

/* IP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2007 */

typedef struct _SFLHost_IP_counters {
  u_int32_t ipForwarding;
  u_int32_t ipDefaultTTL;
  u_int32_t ipInReceives;
  u_int32_t ipInHdrErrors;
  u_int32_t ipInAddrErrors;
  u_int32_t ipForwDatagrams;
  u_int32_t ipInUnknownProtos;
  u_int32_t ipInDiscards;
  u_int32_t ipInDelivers;
  u_int32_t ipOutRequests;
  u_int32_t ipOutDiscards;
  u_int32_t ipOutNoRoutes;
  u_int32_t ipReasmTimeout;
  u_int32_t ipReasmReqds;
  u_int32_t ipReasmOKs;
  u_int32_t ipReasmFails;
  u_int32_t ipFragOKs;
  u_int32_t ipFragFails;
  u_int32_t ipFragCreates;
} SFLHost_IP_counters;

/* ICMP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2008 */

typedef struct _SFLHost_ICMP_counters {
  u_int32_t icmpInMsgs;
  u_int32_t icmpInErrors;
  u_int32_t icmpInDestUnreachs;
  u_int32_t icmpInTimeExcds;
  u_int32_t icmpInParamProbs;
  u_int32_t icmpInSrcQuenchs;
  u_int32_t icmpInRedirects;
  u_int32_t icmpInEchos;
  u_int32_t icmpInEchoReps;
  u_int32_t icmpInTimestamps;
  u_int32_t icmpInAddrMasks;
  u_int32_t icmpInAddrMaskReps;
  u_int32_t icmpOutMsgs;
  u_int32_t icmpOutErrors;
  u_int32_t icmpOutDestUnreachs;
  u_int32_t icmpOutTimeExcds;
  u_int32_t icmpOutParamProbs;
  u_int32_t icmpOutSrcQuenchs;
  u_int32_t icmpOutRedirects;
  u_int32_t icmpOutEchos;
  u_int32_t icmpOutEchoReps;
  u_int32_t icmpOutTimestamps;
  u_int32_t icmpOutTimestampReps;
  u_int32_t icmpOutAddrMasks;
  u_int32_t icmpOutAddrMaskReps;
} SFLHost_ICMP_counters;

/* TCP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2009 */

typedef struct _SFLHost_TCP_counters {
  u_int32_t tcpRtoAlgorithm;
  u_int32_t tcpRtoMin;
  u_int32_t tcpRtoMax;
  u_int32_t tcpMaxConn;
  u_int32_t tcpActiveOpens;
  u_int32_t tcpPassiveOpens;
  u_int32_t tcpAttemptFails;
  u_int32_t tcpEstabResets;
  u_int32_t tcpCurrEstab;
  u_int32_t tcpInSegs;
  u_int32_t tcpOutSegs;
  u_int32_t tcpRetransSegs;
  u_int32_t tcpInErrs;
  u_int32_t tcpOutRsts;
  u_int32_t tcpInCsumErrors;
} SFLHost_TCP_counters;

/* UDP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2010 */

typedef struct _SFLHost_UDP_counters {
  u_int32_t udpInDatagrams;
  u_int32_t udpNoPorts;
  u_int32_t udpInErrors;
  u_int32_t udpOutDatagrams;
  u_int32_t udpRcvbufErrors;
  u_int32_t udpSndbufErrors;
  u_int32_t udpInCsumErrors;
} SFLHost_UDP_counters;

/* memcache */
/* opaque = counter_data; enterprise = 0; format = 2204 */

typedef struct _SFLMemcache_counters {
  u_int32_t uptime;          /* not in 2204 */
  u_int32_t rusage_user;     /* not in 2204 */
  u_int32_t rusage_system;   /* not in 2204 */
  u_int32_t cmd_get;         /* not in 2204 */
  u_int32_t accepting_conns; /* not in 2204 */
  u_int32_t cmd_set;
  u_int32_t cmd_touch; /* added for 2204 */
  u_int32_t cmd_flush;
  u_int32_t get_hits;
  u_int32_t get_misses;
  u_int32_t delete_hits;
  u_int32_t delete_misses;
  u_int32_t incr_hits;
  u_int32_t incr_misses;
  u_int32_t decr_hits;
  u_int32_t decr_misses;
  u_int32_t cas_hits;
  u_int32_t cas_misses;
  u_int32_t cas_badval;
  u_int32_t auth_cmds;
  u_int32_t auth_errors;
  u_int32_t threads;
  u_int32_t conn_yields;
  u_int32_t listen_disabled_num;
  u_int32_t curr_connections;
  u_int32_t rejected_connections; /* added for 2204 */
  u_int32_t total_connections;
  u_int32_t connection_structures;
  u_int32_t evictions;
  u_int32_t reclaimed; /* added for 2204 */
  u_int32_t curr_items;
  u_int32_t total_items;
  u_int64_t bytes_read;
  u_int64_t bytes_written;
  u_int64_t bytes;
  u_int64_t limit_maxbytes; /* converted to 64-bit for structure 2204 */
} SFLMemcache_counters;

/* http */
/* opaque = counter_data; enterprise = 0; format = 2201 */

typedef struct _SFLHTTP_counters {
  u_int32_t method_option_count;
  u_int32_t method_get_count;
  u_int32_t method_head_count;
  u_int32_t method_post_count;
  u_int32_t method_put_count;
  u_int32_t method_delete_count;
  u_int32_t method_trace_count;
  u_int32_t methd_connect_count;
  u_int32_t method_other_count;
  u_int32_t status_1XX_count;
  u_int32_t status_2XX_count;
  u_int32_t status_3XX_count;
  u_int32_t status_4XX_count;
  u_int32_t status_5XX_count;
  u_int32_t status_other_count;
} SFLHTTP_counters;

/* Enterprise counters */
/* opaque = counter_data; enterprise = 0; format = 2202 */
typedef struct _SFLAPP_counters {
  SFLString application;
  u_int32_t status_OK;
  u_int32_t errors_OTHER;
  u_int32_t errors_TIMEOUT;
  u_int32_t errors_INTERNAL_ERROR;
  u_int32_t errors_BAD_REQUEST;
  u_int32_t errors_FORBIDDEN;
  u_int32_t errors_TOO_LARGE;
  u_int32_t errors_NOT_IMPLEMENTED;
  u_int32_t errors_NOT_FOUND;
  u_int32_t errors_UNAVAILABLE;
  u_int32_t errors_UNAUTHORIZED;
} SFLAPP_counters;

/* Enterprise resource counters */
/* opaque = counter_data; enterprise = 0; format = 2203 */
typedef struct {
  u_int32_t user_time;   /* in milliseconds */
  u_int32_t system_time; /* in milliseconds */
  u_int64_t mem_used;
  u_int64_t mem_max;
  u_int32_t fd_open;
  u_int32_t fd_max;
  u_int32_t conn_open;
  u_int32_t conn_max;
} SFLAPP_resources;

/* Enterprise application workers */
/* opaque = counter_data; enterprise = 0; format = 2206 */

typedef struct {
  u_int32_t workers_active;
  u_int32_t workers_idle;
  u_int32_t workers_max;
  u_int32_t req_delayed;
  u_int32_t req_dropped;
} SFLAPP_workers;

typedef struct _SFLJVM_ID {
  SFLString vm_name;
  SFLString vm_vendor;
  SFLString vm_version;
} SFLJVM_ID;

#define SFLJVM_MAX_VMNAME_LEN 64
#define SFLJVM_MAX_VENDOR_LEN 32
#define SFLJVM_MAX_VERSION_LEN 32

typedef struct _SFLJMX_counters {
  u_int64_t hmem_initial;
  u_int64_t hmem_used;
  u_int64_t hmem_committed;
  u_int64_t hmem_max;
  u_int64_t nhmem_initial;
  u_int64_t nhmem_used;
  u_int64_t nhmem_committed;
  u_int64_t nhmem_max;
  u_int32_t gc_count;
  u_int32_t gc_ms;
  u_int32_t cls_loaded;
  u_int32_t cls_total;
  u_int32_t cls_unloaded;
  u_int32_t comp_ms;
  u_int32_t thread_live;
  u_int32_t thread_daemon;
  u_int32_t thread_started;
  u_int32_t fds_open;
  u_int32_t fds_max;
} SFLJMX_counters;

#define XDRSIZ_JMX_COUNTERS 108

typedef struct _SFLVdi_counters {
  u_int32_t sessions_current;  /* number of current sessions */
  u_int32_t sessions_total;    /* total sessions started */
  u_int32_t sessions_duration; /* cumulative session time (in seconds)
                               across all sessions, such that average
                               session duration = sessions_duration
                               / sessions_total */
  u_int32_t rx_bytes;          /* total bytes received */
  u_int32_t tx_bytes;          /* total bytes sent */
  u_int32_t rx_packets;        /* total packet received */
  u_int32_t tx_packets;        /* total packets sent */
  u_int32_t rx_packets_lost;   /* total received packets lost */
  u_int32_t tx_packets_lost;   /* total sent packets lost */
  u_int32_t rtt_min_ms;        /* minimum round trip latency with client
                               across all current sessions
                               measured in milliseconds */
  u_int32_t rtt_max_ms;        /* maximum round trip latency with client
                               across all current sessions
                               measured in millisecond */
  u_int32_t rtt_avg_ms;        /* average round trip latency with client
                               across all current sessions
                               measured in milliseconds */
  u_int32_t audio_rx_bytes;    /* total bytes of audio data received */
  u_int32_t audio_tx_bytes;    /* total bytes of audio data sent */
  u_int32_t audio_tx_limit;    /* administrative limit on audio transmission
                               bandwidth (in bits per second) */
  u_int32_t img_rx_bytes;      /* total bytes of imaging data recieved */
  u_int32_t img_tx_bytes;      /* total bytes of imaging data sent */
  u_int32_t img_frames;        /* total image frames encoded */
  u_int32_t img_qual_min;      /* minimum image encoding quality across
                               current sessions, on a scale of 0 to 100 */
  u_int32_t img_qual_max;      /* best image encoding quality across
                               current sessions, on a scale of 0 to 100 */
  u_int32_t img_qual_avg;      /* average image encoding quality across
                               current sessions, on a scale of 0 to 100 */
  u_int32_t usb_rx_bytes;      /* total bytes of usb data received */
  u_int32_t usb_tx_bytes;      /* total bytes of usb data sent */
} SFLVdi_counters;

/* LAG Port Statistics - see IEEE8023-LAG-MIB */
/* opaque = counter_data; enterprise = 0; format = 7 */
typedef union _SFLLACP_portState {
  u_int32_t all;
  struct {
    u_int8_t actorAdmin;
    u_int8_t actorOper;
    u_int8_t partnerAdmin;
    u_int8_t partnerOper;
  } v;
} SFLLACP_portState;

typedef struct _SFLLACP_counters {
  u_int8_t actorSystemID[8];   /* 6 bytes + 2 pad */
  u_int8_t partnerSystemID[8]; /* 6 bytes + 2 pad */
  u_int32_t attachedAggID;
  SFLLACP_portState portState;
  u_int32_t LACPDUsRx;
  u_int32_t markerPDUsRx;
  u_int32_t markerResponsePDUsRx;
  u_int32_t unknownRx;
  u_int32_t illegalRx;
  u_int32_t LACPDUsTx;
  u_int32_t markerPDUsTx;
  u_int32_t markerResponsePDUsTx;
} SFLLACP_counters;

#define XDRSIZ_LACP_COUNTERS 56

/* openflow port */
/* opaque = counter_data; enterprise = 0; format = 1004 */
typedef struct {
  u_int64_t datapath_id;
  u_int32_t port_no;
} SFLOFPort;

#define XDRSIZ_OFPORT 12

/* port name */
/* opaque = counter_data; enterprise = 0; format = 1005 */
typedef struct {
  SFLString portName;
} SFLPortName;

#define SFL_MAX_PORTNAME_LEN 255

/* OVS datapath stats */
typedef struct _SFLOVSDP_counters {
  u_int32_t n_hit;
  u_int32_t n_missed;
  u_int32_t n_lost;
  u_int32_t n_mask_hit;
  u_int32_t n_flows;
  u_int32_t n_masks;
} SFLOVSDP_counters;

#define XDRSIZE_OVSDP 24

/* Optical SFP/QSFP metrics */
/* opaque = counter_data; enterprise = 0; format = 10 */

typedef struct {
  u_int32_t lane_index;      /* index of lane in module - starting from 1 */
  u_int32_t tx_bias_current; /* microamps */
  u_int32_t tx_power;        /* microwatts */
  u_int32_t tx_power_min;    /* microwatts */
  u_int32_t tx_power_max;    /* microwatts */
  u_int32_t tx_wavelength;   /* nanometers */
  u_int32_t rx_power;        /* microwatts */
  u_int32_t rx_power_min;    /* microwatts */
  u_int32_t rx_power_max;    /* microwatts */
  u_int32_t rx_wavelength;   /* nanometers */
} SFLLane;

#define XDRSIZ_LANE_COUNTERS 40

typedef struct {
  u_int32_t module_id;
  u_int32_t module_total_lanes;    /* total lanes in module */
  u_int32_t module_supply_voltage; /* millivolts */
  int32_t module_temperature;      /* signed - in oC / 1000 */
  u_int32_t num_lanes;             /* number of active lane structs to come */
  SFLLane* lanes;
} SFLSFP_counters;

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC = 1,
  SFLCOUNTERS_ETHERNET = 2,
  SFLCOUNTERS_TOKENRING = 3,
  SFLCOUNTERS_VG = 4,
  SFLCOUNTERS_VLAN = 5,
  SFLCOUNTERS_80211 = 6,
  SFLCOUNTERS_LACP = 7,
  SFLCOUNTERS_SFP = 10,
  SFLCOUNTERS_PROCESSOR = 1001,
  SFLCOUNTERS_RADIO = 1002,
  SFLCOUNTERS_OFPORT = 1004,
  SFLCOUNTERS_PORTNAME = 1005,
  SFLCOUNTERS_HOST_HID = 2000, /* host id */
  SFLCOUNTERS_ADAPTORS = 2001, /* host adaptors */
  SFLCOUNTERS_HOST_PAR = 2002, /* host parent */
  SFLCOUNTERS_HOST_CPU = 2003, /* host cpu  */
  SFLCOUNTERS_HOST_MEM = 2004, /* host memory  */
  SFLCOUNTERS_HOST_DSK = 2005, /* host storage I/O  */
  SFLCOUNTERS_HOST_NIO = 2006, /* host network I/O */
  SFLCOUNTERS_HOST_IP = 2007,
  SFLCOUNTERS_HOST_ICMP = 2008,
  SFLCOUNTERS_HOST_TCP = 2009,
  SFLCOUNTERS_HOST_UDP = 2010,
  SFLCOUNTERS_HOST_VRT_NODE = 2100, /* host virt node */
  SFLCOUNTERS_HOST_VRT_CPU = 2101,  /* host virt cpu */
  SFLCOUNTERS_HOST_VRT_MEM = 2102,  /* host virt mem */
  SFLCOUNTERS_HOST_VRT_DSK = 2103,  /* host virt storage */
  SFLCOUNTERS_HOST_VRT_NIO = 2104,  /* host virt network I/O */
  SFLCOUNTERS_JVM = 2105,           /* java runtime */
  SFLCOUNTERS_JMX = 2106,           /* java JMX stats */
  SFLCOUNTERS_MEMCACHE = 2200,      /* memcached (deprecated) */
  SFLCOUNTERS_HTTP = 2201,          /* http */
  SFLCOUNTERS_APP = 2202,
  SFLCOUNTERS_APP_RESOURCE = 2203,
  SFLCOUNTERS_MEMCACHE2 = 2204, /* memcached */
  SFLCOUNTERS_VDI = 2205,
  SFLCOUNTERS_APP_WORKERS = 2206,
  SFLCOUNTERS_OVSDP = 2207,
  SFLCOUNTERS_HOST_GPU_NVML = (5703 << 12) + 1, /* = 23359489 */
  SFLCOUNTERS_BCM_TABLES = (4413 << 12) + 3,
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
  SFLWifi_counters wifi;
  SFLProcessor_counters processor;
  SFLRadio_counters radio;
  SFLHostId hostId;
  SFLAdaptorList* adaptors;
  SFLHost_parent host_par;
  SFLHost_cpu_counters host_cpu;
  SFLHost_mem_counters host_mem;
  SFLHost_dsk_counters host_dsk;
  SFLHost_nio_counters host_nio;
  SFLHost_IP_counters host_ip;
  SFLHost_ICMP_counters host_icmp;
  SFLHost_TCP_counters host_tcp;
  SFLHost_UDP_counters host_udp;
  SFLHost_vrt_node_counters host_vrt_node;
  SFLHost_vrt_cpu_counters host_vrt_cpu;
  SFLHost_vrt_mem_counters host_vrt_mem;
  SFLHost_vrt_dsk_counters host_vrt_dsk;
  SFLHost_vrt_nio_counters host_vrt_nio;
  SFLHost_gpu_nvml host_gpu_nvml;
  SFLBCM_tables bcm_tables;
  SFLMemcache_counters memcache;
  SFLHTTP_counters http;
  SFLJVM_ID jvm;
  SFLJMX_counters jmx;
  SFLAPP_counters app;
  SFLAPP_resources appResources;
  SFLAPP_workers appWorkers;
  SFLVdi_counters vdi;
  SFLLACP_counters lacp;
  SFLPortName portName;
  SFLSFP_counters sfp;
  SFLOVSDP_counters ovsdp;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element* nxt; /* linked list */
  u_int32_t tag;                           /* SFLCounters_type_tag */
  u_int32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* u_int32_t tag;    */ /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number; /* Incremented with each counters sample
                              generated by this source_id */
  u_int32_t source_id;       /* fsSourceId */
  u_int32_t num_elements;
  SFLCounters_sample_element* elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* u_int32_t tag;    */ /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number; /* Incremented with each counters sample
                              generated by this source_id */
  u_int32_t ds_class;        /* EXPANDED */
  u_int32_t ds_index;        /* EXPANDED */
  u_int32_t num_elements;
  SFLCounters_sample_element* elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el)                                               \
  do {                                                                         \
    (_el)->nxt = (_sm)->elements;                                              \
    (_sm)->elements = (_el);                                                   \
  } while (0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  u_int32_t datagram_version; /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;   /* IP address of sampling agent */
  u_int32_t sub_agent_id;     /* Used to distinguishing between datagram
                               streams from separate agent sub entities
                               within an device. */
  u_int32_t sequence_number;  /* Incremented with each sample datagram
                               generated */
  u_int32_t uptime;           /* Current time (in milliseconds since device
                               last booted). Should be set as close to
                               datagram transmission time as possible.*/
  u_int32_t
    num_records; /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400
